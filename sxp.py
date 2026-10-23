import cmd
import hashlib
import json
import os
import random
import re
import shutil
import socket
import ssl
import string
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import List, Optional, Tuple

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
RESET = "\033[0m"

MAX_WORKERS = 200
SOCKET_TIMEOUT = 2.5
READ_LIMIT = 16384

VERSION = "1.3"
# Where `update` pulls a fresh sxp.py from. Both are overridable via env
# so a fork or a local mirror can be used for testing.
UPDATE_BASE = os.environ.get(
    "SXP_UPDATE_BASE",
    "https://raw.githubusercontent.com/egwyl666/SXP-Scanner")
UPDATE_BRANCH = os.environ.get("SXP_BRANCH", "work/fixit1.0")
UPDATE_URL = f"{UPDATE_BASE}/{UPDATE_BRANCH}/sxp.py"

# A realistic browser User-Agent so servers/WAFs behave as they would for one.
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

LOGO = RED + r"""
███████╗██╗  ██╗██████╗
██╔════╝╚██╗██╔╝██╔══██╗
███████╗ ╚███╔╝ ██████╔╝
╚════██║ ██╔██╗ ██╔═══╝
███████║██╔╝ ██╗██║
╚══════╝╚═╝  ╚═╝╚═╝     """ + RESET


# --------------------------------------------------------------------------- #
# Low-level networking (checksums, raw headers, source IP)                    #
# --------------------------------------------------------------------------- #

def checksum(source_string):
    """Standard 16-bit one's-complement Internet checksum (RFC 1071)."""
    total = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        total = (total + this_val) & 0xffffffff
        count += 2
    if count_to < len(source_string):
        total = (total + source_string[-1]) & 0xffffffff
    total = (total >> 16) + (total & 0xffff)
    total += (total >> 16)
    answer = ~total & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def get_source_ip(target_ip):
    """Local address the kernel would use to reach target_ip (no packet sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _is_ip(value):
    try:
        socket.inet_aton(value)
        return value.count(".") == 3
    except (OSError, AttributeError):
        return False


def service_name(port):
    """Well-known service name for a port, from the system services DB."""
    for proto in ("tcp", "udp"):
        try:
            return socket.getservbyport(port, proto)
        except OSError:
            continue
    return "unknown"


# --------------------------------------------------------------------------- #
# Target parsing (Block 1)                                                     #
# --------------------------------------------------------------------------- #

@dataclass
class TargetSpec:
    host_input: str
    hostname: str = ""
    ip: str = ""
    scheme: str = ""
    ports: List[int] = field(default_factory=list)
    path: str = "/"
    error: str = ""


def parse_port_list(text):
    """'80,443,8080' or '20-25 80' -> sorted unique valid ports."""
    ports = set()
    for token in re.split(r"[,\s]+", text.strip()):
        if not token:
            continue
        if "-" in token:
            a, _, b = token.partition("-")
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(token))
    for p in ports:
        if not 0 < p < 65536:
            raise ValueError(f"port out of range: {p}")
    return sorted(ports)


def parse_target(raw_target, port_args=None, default_ports=None):
    """Parse site.com / 10.0.0.1 / site.com:8443 / https://site.com:8443/p?x=1.

    Resolves the IP but keeps the original hostname for TLS SNI and the Host
    header. Port precedence: explicit port_args > :port in target >
    scheme default (https->443, http->80) > default_ports > [].
    """
    raw = raw_target.strip()
    if "://" in raw:
        parts = urllib.parse.urlsplit(raw)
    else:
        parts = urllib.parse.urlsplit("//" + raw)

    scheme = parts.scheme.lower()
    hostname = parts.hostname or ""
    if not hostname:
        return TargetSpec(host_input=raw, error="could not parse a hostname")

    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    # Determine ports.
    ports = []
    if port_args:
        joined = port_args if isinstance(port_args, str) else " ".join(port_args)
        try:
            ports = parse_port_list(joined)
        except ValueError as e:
            return TargetSpec(host_input=raw, hostname=hostname,
                              error=f"invalid port(s): {e}")
    elif parts.port:
        ports = [parts.port]
    elif scheme == "https":
        ports = [443]
    elif scheme == "http":
        ports = [80]
    elif default_ports:
        ports = list(default_ports)

    spec = TargetSpec(host_input=raw, hostname=hostname, scheme=scheme,
                      ports=ports, path=path)

    # Resolve IP (keep hostname for SNI/Host).
    if _is_ip(hostname):
        spec.ip = hostname
    else:
        try:
            spec.ip = socket.gethostbyname(hostname)
        except socket.gaierror as e:
            spec.error = f"cannot resolve {hostname}: {e}"
    return spec


# --------------------------------------------------------------------------- #
# TLS / socket transport                                                       #
# --------------------------------------------------------------------------- #

def _tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except (NotImplementedError, AttributeError):
        pass
    return ctx


def _open_socket(ip, port, use_tls, timeout=SOCKET_TIMEOUT, server_hostname=None):
    """Open a TCP (and optionally TLS) socket. SNI uses server_hostname when
    it is a real name, never a bare IP."""
    raw = socket.create_connection((ip, port), timeout=timeout)
    raw.settimeout(timeout)
    if not use_tls:
        return raw
    ctx = _tls_context()
    sni = server_hostname if (server_hostname and not _is_ip(server_hostname)) else None
    try:
        return ctx.wrap_socket(raw, server_hostname=sni)
    except (ssl.SSLError, ValueError, OSError):
        try:
            raw.close()
        except OSError:
            pass
        # Retry once without SNI (some servers reject SNI, or host is an IP).
        raw2 = socket.create_connection((ip, port), timeout=timeout)
        raw2.settimeout(timeout)
        try:
            return ctx.wrap_socket(raw2)
        except (ssl.SSLError, OSError):
            raw2.close()
            raise


def _recv_all(sock, limit=READ_LIMIT):
    chunks = []
    total = 0
    while total < limit:
        try:
            part = sock.recv(min(4096, limit - total))
        except socket.timeout:
            break
        except OSError:
            break
        if not part:
            break
        chunks.append(part)
        total += len(part)
    return b"".join(chunks)


def _looks_like_tls(data):
    # TLS record header: 0x16 handshake / 0x15 alert, then a 0x03 version byte.
    return len(data) >= 2 and data[0] in (0x15, 0x16) and data[1] == 0x03


# --------------------------------------------------------------------------- #
# HTTP engine (Block 2)                                                        #
# --------------------------------------------------------------------------- #

@dataclass
class HttpResp:
    status: str = ""
    code: int = 0
    server: str = ""
    headers_raw: List[Tuple[str, str]] = field(default_factory=list)
    headers_lower: dict = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    location: str = ""
    body: str = ""
    length: int = 0
    title: str = ""
    rtt_ms: float = 0.0
    transport: str = "TCP"
    alpn: str = ""
    tls_version: str = ""
    cipher: str = ""
    cert: Optional["CertInfo"] = None
    raw_banner: str = ""
    error: str = ""


def _host_header(hostname, port, use_tls):
    standard = (use_tls and port == 443) or (not use_tls and port == 80)
    return hostname if standard else f"{hostname}:{port}"


def _build_request(hostname, port, use_tls, path, method, http10,
                   extra_headers, send_host):
    version = "HTTP/1.0" if http10 else "HTTP/1.1"
    lines = [f"{method} {path} {version}"]
    if send_host:
        lines.append(f"Host: {_host_header(hostname, port, use_tls)}")
    lines.append(f"User-Agent: {BROWSER_UA}")
    lines.append("Accept: text/html,application/xhtml+xml,application/xml;"
                 "q=0.9,*/*;q=0.8")
    lines.append("Accept-Encoding: identity")
    for k, v in (extra_headers or {}).items():
        lines.append(f"{k}: {v}")
    lines += ["Connection: close", "", ""]
    return "\r\n".join(lines).encode("latin-1", "replace")


def _dechunk(body):
    """Decode a Transfer-Encoding: chunked body into plain bytes."""
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        j = body.find(b"\r\n", i)
        if j == -1:
            break
        try:
            size = int(body[i:j].split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        start = j + 2
        out += body[start:start + size]
        i = start + size + 2          # skip the chunk's trailing CRLF
    return bytes(out)


def _fill_http(resp, data):
    if not data[:5].upper().startswith(b"HTTP/"):
        if data:
            first = data.decode("latin-1", "replace").splitlines()
            resp.raw_banner = (first[0][:120] if first else "")
        if not resp.error:
            resp.error = "non-HTTP response"
        return
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    resp.status = lines[0].decode("latin-1", "replace").strip()
    resp.code = _status_code(resp.status)
    for ln in lines[1:]:
        if b":" not in ln:
            continue
        k, _, v = ln.partition(b":")
        key = k.decode("latin-1", "replace").strip()
        val = v.decode("latin-1", "replace").strip()
        resp.headers_raw.append((key, val))
        low = key.lower()
        resp.headers_lower[low] = val
        if low == "set-cookie":
            resp.cookies.append(val)
        elif low == "location":
            resp.location = val
    resp.server = resp.headers_lower.get("server", "")
    if "chunked" in resp.headers_lower.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    resp.length = len(body)
    body_text = body[:4096].decode("latin-1", "replace")
    resp.body = body_text
    m = re.search(r"<title[^>]*>(.*?)</title>", body_text,
                  re.IGNORECASE | re.DOTALL)
    resp.title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def http_request(ip, port, use_tls, hostname, path="/", method="GET",
                 http10=False, extra_headers=None, send_host=True,
                 timeout=SOCKET_TIMEOUT):
    """One HTTP(S) request. Always returns an HttpResp (error set on failure)."""
    resp = HttpResp(transport="TCP")
    t0 = time.time()
    try:
        sock = _open_socket(ip, port, use_tls, timeout, server_hostname=hostname)
    except OSError as e:
        resp.error = str(e)
        resp.rtt_ms = (time.time() - t0) * 1000
        return resp
    try:
        if use_tls:
            resp.transport = sock.version() or "TLS"
            resp.tls_version = resp.transport
            c = sock.cipher()
            resp.cipher = c[0] if c else ""
            try:
                resp.alpn = sock.selected_alpn_protocol() or ""
            except Exception:                              # noqa: BLE001
                resp.alpn = ""
            resp.cert = extract_cert_info(sock)
        req = _build_request(hostname, port, use_tls, path, method,
                             http10, extra_headers, send_host)
        sock.sendall(req)
        data = _recv_all(sock)
    except OSError as e:
        resp.error = str(e)
        resp.rtt_ms = (time.time() - t0) * 1000
        return resp
    finally:
        sock.close()
    resp.rtt_ms = (time.time() - t0) * 1000
    _fill_http(resp, data)
    return resp


def _status_code(status_line):
    parts = status_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return 0


def _parse_location(loc, cur, orig_hostname, orig_ip):
    """Resolve a Location header relative to the current request.

    Returns a dict {ip, port, use_tls, hostname, path} to follow, or None to
    stop (cross-host redirect or unparseable)."""
    parts = urllib.parse.urlsplit(loc)
    if parts.scheme or parts.netloc:
        host = parts.hostname or ""
        if host and host.lower() not in (orig_hostname.lower(), orig_ip):
            return None                                    # cross-host: stop
        use_tls = parts.scheme.lower() == "https"
        port = parts.port or (443 if use_tls else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return {"ip": orig_ip, "port": port, "use_tls": use_tls,
                "hostname": host or orig_hostname, "path": path}
    # Relative path on the same endpoint.
    path = loc if loc.startswith("/") else "/" + loc
    return {"ip": orig_ip, "port": cur["port"], "use_tls": cur["use_tls"],
            "hostname": cur["hostname"], "path": path}


def fetch_follow(ip, port, use_tls, hostname, path, timeout, max_hops=2):
    """GET a URL, following up to max_hops same-host redirects.

    Returns (final_resp, redirect_chain) where the chain is a list of
    (code, location) tuples for each hop taken."""
    chain = []
    cur = {"ip": ip, "port": port, "use_tls": use_tls,
           "hostname": hostname, "path": path}
    resp = http_request(ip, port, use_tls, hostname, path, timeout=timeout)
    hops = 0
    while (resp.code in (301, 302, 303, 307, 308) and resp.location
           and hops < max_hops):
        chain.append((resp.code, resp.location))
        nxt = _parse_location(resp.location, cur, hostname, ip)
        if nxt is None:
            break
        resp = http_request(nxt["ip"], nxt["port"], nxt["use_tls"],
                            nxt["hostname"], nxt["path"], timeout=timeout)
        cur = nxt
        hops += 1
    return resp, chain


# --------------------------------------------------------------------------- #
# Service fingerprinting / unmasking (Block 2 + 5)                            #
# --------------------------------------------------------------------------- #

TLS_PORTS = {443, 8443, 9443, 4443, 2053, 2083, 2087, 2096}
PLAINTEXT_HTTP_PORTS = {80, 81, 591, 8000, 8008, 8080, 8081, 8888, 2052, 2082,
                        2086, 2095, 8880}
SPOOF_PRONE = {"cloudflare", "apache", "iis", "microsoft-iis", "gws",
               "openresty"}
PUBLIC_CA_HINTS = ("cloudflare", "google trust", "digicert", "lets encrypt",
                   "let's encrypt", "amazon", "sectigo", "globalsign",
                   "baltimore", "isrg")

_BODY_SIGS = [
    ("nginx", "<center>nginx</center>"),
    ("openresty", "openresty"),
    ("apache", "<address>apache"),
    ("apache", "apache/"),
    ("iis", "microsoft-iis"),
    ("litespeed", "litespeed"),
    ("caddy", "caddy"),
    ("tomcat", "apache tomcat"),
    ("starlette", "internal server error"),  # weak, only as last resort
]


@dataclass
class CertInfo:
    subject_cn: str = ""
    subject_o: str = ""
    issuer_cn: str = ""
    issuer_o: str = ""
    san: List[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    self_signed: bool = False
    source: str = ""

    def one_line(self):
        issuer = self.issuer_o or self.issuer_cn or "?"
        tag = " (self-signed)" if self.self_signed else ""
        return f"CN={self.subject_cn or '?'} | Issuer={issuer}{tag}"


@dataclass
class Evidence:
    weight: int
    description: str
    inferred_service: str = ""


@dataclass
class Fingerprint:
    port: int
    transport: str = "TCP"
    tls_version: str = ""
    cipher: str = ""
    alpn: str = ""
    cert: Optional[CertInfo] = None
    http_status: str = ""
    title: str = ""
    server_header: str = ""
    headers_raw: List[Tuple[str, str]] = field(default_factory=list)
    headers_lower: dict = field(default_factory=dict)
    body_snippet: str = ""
    raw_banner: str = ""
    redirect_chain: List[Tuple[int, str]] = field(default_factory=list)
    notfound_status: str = ""
    allow: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    inferred_service: str = ""
    spoofed: bool = False
    error: str = ""


# --- certificate extraction (stdlib hack + fallbacks) ----------------------- #

def _name_field(name_seq, key):
    for rdn in name_seq or ():
        for attr in rdn:
            if attr[0] == key:
                return attr[1]
    return ""


def _cert_via_stdlib(pem):
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decode is None:
        return None
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        d = decode(path)
    except (ssl.SSLError, OSError, ValueError, TypeError):
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    ci = CertInfo(source="stdlib")
    ci.subject_cn = _name_field(d.get("subject"), "commonName")
    ci.subject_o = _name_field(d.get("subject"), "organizationName")
    ci.issuer_cn = _name_field(d.get("issuer"), "commonName")
    ci.issuer_o = _name_field(d.get("issuer"), "organizationName")
    ci.not_before = d.get("notBefore", "")
    ci.not_after = d.get("notAfter", "")
    for entry in d.get("subjectAltName", ()):
        if len(entry) == 2:
            ci.san.append(f"{entry[0]}:{entry[1]}")
    return ci


def _openssl_field(text, prefix, key):
    for line in text.splitlines():
        if line.lower().startswith(prefix + "="):
            m = re.search(rf"\b{key}\s*=\s*([^,/]+)", line)
            if m:
                return m.group(1).strip()
    return ""


def _cert_via_openssl(pem):
    if not shutil.which("openssl"):
        return None
    try:
        out = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer",
             "-dates", "-ext", "subjectAltName"],
            input=pem, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    text = out.stdout + out.stderr
    ci = CertInfo(source="openssl")
    ci.subject_cn = _openssl_field(text, "subject", "CN")
    ci.subject_o = _openssl_field(text, "subject", "O")
    ci.issuer_cn = _openssl_field(text, "issuer", "CN")
    ci.issuer_o = _openssl_field(text, "issuer", "O")
    nb = re.search(r"notBefore=(.+)", text)
    na = re.search(r"notAfter=(.+)", text)
    ci.not_before = nb.group(1).strip() if nb else ""
    ci.not_after = na.group(1).strip() if na else ""
    for m in re.finditer(r"(DNS|IP Address):([^,\s]+)", text):
        ci.san.append(f"{m.group(1)}:{m.group(2)}")
    return ci


def _cert_via_der_scan(der):
    ci = CertInfo(source="der-scan")
    cns = []
    marker = b"\x06\x03\x55\x04\x03"
    i = 0
    while True:
        j = der.find(marker, i)
        if j == -1:
            break
        k = j + len(marker)
        if k + 2 <= len(der):
            strlen = der[k + 1]
            val = der[k + 2:k + 2 + strlen]
            if val:
                cns.append(val.decode("utf-8", "replace"))
        i = j + 1
    if cns:
        ci.subject_cn = cns[0]
        if len(cns) > 1:
            ci.issuer_cn = cns[-1]
    return ci


def extract_cert_info(sslsock):
    try:
        der = sslsock.getpeercert(binary_form=True)
    except (ssl.SSLError, OSError):
        der = None
    if not der:
        return None
    pem = ssl.DER_cert_to_PEM_cert(der)
    info = _cert_via_stdlib(pem) or _cert_via_openssl(pem) \
        or _cert_via_der_scan(der)
    if info is not None:
        info.self_signed = bool(
            info.subject_cn
            and info.subject_cn == info.issuer_cn
            and (info.subject_o or "") == (info.issuer_o or ""))
    return info


def _cert_validity_days(cert):
    if not cert.not_before or not cert.not_after:
        return None
    try:
        nb = ssl.cert_time_to_seconds(cert.not_before)
        na = ssl.cert_time_to_seconds(cert.not_after)
    except (ValueError, OSError):
        return None
    return int((na - nb) / 86400)


def _cert_is_private(cert):
    if cert.self_signed:
        return True
    issuer = f"{cert.issuer_o} {cert.issuer_cn}".lower().strip()
    if not issuer:
        return True
    return not any(h in issuer for h in PUBLIC_CA_HINTS)


# --- helpers ---------------------------------------------------------------- #

def _http_get_probe(host):
    return (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {BROWSER_UA}\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode()


def _engine_from_body(body):
    if not body:
        return "", ""
    low = body.lower()
    for engine, sig in _BODY_SIGS:
        if sig in low:
            return engine, sig
    return "", ""


def _family(server_header):
    if not server_header or not server_header.strip():
        return ""
    return server_header.split("/")[0].split()[0].strip().lower()


def _rand_path():
    return "/sxp_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


# --- transport decision + probe pipeline ------------------------------------ #

def _plaintext_probe(host, port, timeout):
    """Returns (http_bytes, greeting_or_None, tls_hint, nginx_https)."""
    try:
        sock = _open_socket(host, port, False, timeout)
    except OSError:
        return b"", None, False, False
    try:
        sock.settimeout(0.8)
        try:
            greet = sock.recv(512)
        except (socket.timeout, OSError):
            greet = b""
        sock.settimeout(timeout)
        if greet:
            is_http = greet[:5].upper().startswith(b"HTTP/")
            is_tls = _looks_like_tls(greet)
            if not is_http and not is_tls:
                first = next((l for l in
                              greet.decode("latin-1", "replace").splitlines()
                              if l.strip()), "")
                if first:
                    return b"", first.strip()[:120], False, False
            if is_http:
                rest = _recv_all(sock, READ_LIMIT - len(greet))
                return greet + rest, None, False, False
            if is_tls:
                return greet, None, True, False
        try:
            sock.sendall(_http_get_probe(host))
            data = _recv_all(sock)
        except OSError:
            data = b""
    finally:
        sock.close()

    nginx_sig = b"plain HTTP request was sent to HTTPS port" in data
    tls_hint = (_looks_like_tls(data) or nginx_sig
                or (not data and port not in PLAINTEXT_HTTP_PORTS))
    return data, None, tls_hint, nginx_sig


def _decide_transport(ip, port, timeout):
    """Returns (use_tls, raw_banner_or_None, nginx_https_marker)."""
    if port in TLS_PORTS:
        return True, None, False
    _, greeting, tls_hint, nginx_sig = _plaintext_probe(ip, port, timeout)
    if greeting is not None:
        return False, greeting, False
    return bool(tls_hint), None, nginx_sig


def fingerprint_port(ip, hostname, port, path="/", timeout=SOCKET_TIMEOUT):
    """Smart multi-probe fingerprint + unmasking for one open TCP port."""
    fp = Fingerprint(port=port)
    use_tls, raw_banner, nginx_marker = _decide_transport(ip, port, timeout)
    if raw_banner is not None:
        fp.raw_banner = raw_banner
        return fp

    # Probe 1: standard GET, following redirects to the real endpoint.
    resp, chain = fetch_follow(ip, port, use_tls, hostname, path, timeout)
    fp.redirect_chain = chain
    fp.transport = resp.transport
    fp.tls_version = resp.tls_version
    fp.cipher = resp.cipher
    fp.alpn = resp.alpn
    fp.cert = resp.cert
    fp.http_status = resp.status
    fp.headers_raw = resp.headers_raw
    fp.headers_lower = resp.headers_lower
    fp.body_snippet = resp.body
    fp.title = resp.title
    fp.server_header = resp.server
    if not resp.code:
        if resp.raw_banner and not fp.raw_banner:
            fp.raw_banner = resp.raw_banner
        if resp.error:
            fp.error = resp.error

    if nginx_marker:
        fp.evidence.append(Evidence(
            5, "plaintext request to a TLS port returned the nginx signature "
               "'The plain HTTP request was sent to HTTPS port'", "nginx"))

    bodies = [("main", fp.body_snippet)]

    if fp.http_status:
        # Probe 2: OPTIONS to read Allow / Public.
        opt = http_request(ip, port, use_tls, hostname, path or "/",
                           method="OPTIONS", timeout=timeout)
        fp.allow = opt.headers_lower.get("allow", "") or \
            opt.headers_lower.get("public", "")
        # Probe 3: random path -> native 404, often reveals the real engine.
        nf = http_request(ip, port, use_tls, hostname, _rand_path(),
                          timeout=timeout)
        fp.notfound_status = nf.status
        bodies.append(("404", nf.body))
        if nf.server and _family(nf.server) and _family(nf.server) != _family(fp.server_header):
            fp.evidence.append(Evidence(
                3, f"404 Server header '{nf.server}' differs from main "
                   f"'{fp.server_header or '(none)'}'", _family(nf.server)))
        # Probe 4: malformed HTTP/1.0 without Host -> native error page.
        err = http_request(ip, port, use_tls, hostname, "/", http10=True,
                           send_host=False, timeout=timeout)
        bodies.append(("error", err.body))

    _unmask(fp, bodies)
    return fp


def _unmask(fp, bodies):
    server_family = _family(fp.server_header)

    seen = set()
    for label, text in bodies:
        engine, sig = _engine_from_body(text)
        if engine and engine not in seen:
            seen.add(engine)
            weight = 5 if label in ("error", "404") else 4
            fp.evidence.append(Evidence(
                weight, f"{label} body reveals {engine} ('{sig}')", engine))

    if "cloudflare" in server_family:
        if "cf-ray" not in fp.headers_lower:
            fp.evidence.append(Evidence(
                3, "Server claims Cloudflare but no 'cf-ray' header present"))
        if fp.cert and _cert_is_private(fp.cert):
            issuer = fp.cert.issuer_o or fp.cert.issuer_cn or "?"
            extra = ", self-signed" if fp.cert.self_signed else ""
            fp.evidence.append(Evidence(
                4, f"TLS certificate is not from a public CDN CA "
                   f"(issuer={issuer}{extra})"))
        if fp.transport == "TCP":
            fp.evidence.append(Evidence(
                3, "Server claims Cloudflare but answers over plaintext HTTP "
                   "(a real Cloudflare edge terminates TLS)"))

    if fp.cert:
        days = _cert_validity_days(fp.cert)
        if days and days > 398:
            fp.evidence.append(Evidence(
                2, f"TLS certificate valid for {days} days (> 398); public "
                   f"CAs no longer issue certificates this long "
                   f"(internal / self-signed CA)"))

    best = max((e for e in fp.evidence if e.inferred_service),
               key=lambda e: e.weight, default=None)
    if best:
        fp.inferred_service = best.inferred_service
    elif server_family:
        fp.inferred_service = server_family

    if (server_family and fp.inferred_service
            and fp.inferred_service != server_family
            and fp.inferred_service != "unknown"):
        fp.spoofed = True

    if "cloudflare" in server_family and not fp.spoofed:
        if any(e.weight >= 3 for e in fp.evidence):
            fp.spoofed = True
            if not best:
                fp.inferred_service = "non-Cloudflare origin"


def fingerprint_lines(fp, verbose):
    out = []
    if fp.raw_banner and not fp.http_status:
        out.append(f"        {fp.raw_banner}")
        return out
    if not fp.http_status:
        if fp.inferred_service or fp.evidence:
            note = f"   (TLS retry failed: {fp.error})" if fp.error else ""
            out.append(f"        Identified: {fp.inferred_service or '?'}{note}")
            if verbose:
                for e in sorted(fp.evidence, key=lambda x: -x.weight):
                    tag = f" -> {e.inferred_service}" if e.inferred_service else ""
                    out.append(f"          - [w={e.weight}] {e.description}{tag}")
        else:
            out.append(f"        (no banner{': ' + fp.error if fp.error else ''})")
        return out

    head = f"        [{fp.transport}"
    if fp.alpn:
        head += f"/{fp.alpn}"
    head += f"] {fp.http_status}"
    if fp.title:
        head += f'  title="{fp.title}"'
    out.append(head)

    claimed_family = _family(fp.server_header)
    if fp.server_header or fp.spoofed or fp.inferred_service:
        claimed = fp.server_header or "(none)"
        line = f"        Server: {claimed}"
        if fp.spoofed:
            line += (f"   {RED}[!] SPOOFED: claims "
                     f"'{claimed_family or claimed}' -> likely "
                     f"'{fp.inferred_service}'{RESET}")
        elif fp.inferred_service and fp.inferred_service != claimed_family:
            line += f"   (identified: {fp.inferred_service})"
        out.append(line)

    if fp.redirect_chain:
        hop = " -> ".join(f"{c}:{loc}" for c, loc in fp.redirect_chain)
        out.append(f"        redirect: {hop}")
    if fp.cert:
        out.append(f"        cert: {fp.cert.one_line()}")

    if verbose:
        for e in sorted(fp.evidence, key=lambda x: -x.weight):
            tag = f" -> {e.inferred_service}" if e.inferred_service else ""
            out.append(f"          - [w={e.weight}] {e.description}{tag}")
        if fp.allow:
            out.append(f"          Allow: {fp.allow}")
        if fp.notfound_status:
            out.append(f"          404 probe: {fp.notfound_status}")
        if fp.tls_version:
            out.append(f"          TLS: {fp.tls_version} / {fp.cipher}"
                       + (f" / ALPN={fp.alpn}" if fp.alpn else ""))
        if fp.cert:
            if fp.cert.san:
                out.append(f"          SAN: {', '.join(fp.cert.san[:8])}")
            out.append(
                f"          Validity: {fp.cert.not_before or '?'} .. "
                f"{fp.cert.not_after or '?'} (decoded via {fp.cert.source})")
        if fp.headers_raw:
            out.append("          Headers:")
            for k, v in fp.headers_raw:
                out.append(f"            {k}: {v}")
    return out


# --------------------------------------------------------------------------- #
# Host intelligence (Block 5)                                                  #
# --------------------------------------------------------------------------- #

# cPanel / WHM / Webmail come in (http, https) pairs.
CPANEL_PAIRS = [((2082, 2083), "cPanel"), ((2086, 2087), "WHM"),
                ((2095, 2096), "Webmail")]
# Cloudflare's alternative proxy ports (minus 80/443).
CF_ALT_PORTS = {2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880}
# Single-port management panels / apps.
PANEL_SINGLE = {
    8006: "Proxmox VE", 9443: "Portainer", 9000: "Portainer/PHP-FPM",
    3000: "Grafana", 1500: "ISPmanager", 8291: "MikroTik Winbox",
    8083: "Plesk (alt)", 10000: "Webmin/Virtualmin",
}


def host_intel(open_ports, fps):
    """Infrastructure insights from the open-port layout + fingerprints."""
    out = []
    op = set(open_ports)

    panels = [name for pair, name in CPANEL_PAIRS if op & set(pair)]
    if panels:
        out.append(f"Control-panel ports present: {', '.join(panels)} "
                   f"(cPanel/WHM hosting stack)")
    for port, name in sorted(PANEL_SINGLE.items()):
        if port in op:
            out.append(f"Port {port} -> possible {name}")

    cf_hit = op & CF_ALT_PORTS
    spoofed_cf = any(
        (f.spoofed and "cloudflare" in _family(f.server_header))
        or "non-Cloudflare" in (f.inferred_service or "")
        for f in fps.values())
    if len(cf_hit) >= 4 and spoofed_cf:
        out.append(f"{RED}[!] Host Role Insight: port layout mimics a "
                   f"Cloudflare edge, but demasking proves the real stack is "
                   f"self-hosted cPanel/nginx (no real Cloudflare){RESET}")
    elif len(cf_hit) >= 4:
        out.append("Port set matches Cloudflare's alternative ports "
                   "(also the cPanel port range) -> likely a cPanel host")
    return out


# --------------------------------------------------------------------------- #
# SYN / XMAS / connect scanning (Block 4)                                      #
# --------------------------------------------------------------------------- #

def connect_scan_port(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, port))
            return "open"
        except socket.timeout:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError as e:
            return f"error: {e}"


def build_ip_header(source_ip, dest_ip):
    ip_ihl_ver = (4 << 4) + 5
    ip_tot_len = 40
    ip_id = 0x6ea9
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)
    header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, 0, ip_tot_len,
                         ip_id, 0, ip_ttl, ip_proto, 0, ip_saddr, ip_daddr)
    ip_check = checksum(header)
    return struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, 0, ip_tot_len,
                       ip_id, 0, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)


def build_tcp_header(source_ip, dest_ip, source_port, dest_port, flags):
    tcp_seq = 0
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_window = 1024
    tcp_urg_ptr = 0
    tcp_offset_res = (tcp_doff << 4)
    tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, tcp_seq,
                             tcp_ack_seq, tcp_offset_res, flags,
                             tcp_window, 0, tcp_urg_ptr)
    pseudo = struct.pack('!4s4sBBH', socket.inet_aton(source_ip),
                         socket.inet_aton(dest_ip), 0,
                         socket.IPPROTO_TCP, len(tcp_header))
    tcp_check = checksum(pseudo + tcp_header)
    return struct.pack('!HHLLBBHHH', source_port, dest_port, tcp_seq,
                       tcp_ack_seq, tcp_offset_res, flags,
                       tcp_window, tcp_check, tcp_urg_ptr)


def syn_interpret(tcp_flags):
    if tcp_flags & 0x12 == 0x12:
        return "open"
    if tcp_flags & 0x04:
        return "closed"
    return None


def xmas_interpret(tcp_flags):
    if tcp_flags & 0x04:
        return "closed"
    return None


def raw_scan(ip, host_label, ports, flags, interpret, default_state, timeout=2.0):
    """Two-pass SYN/XMAS scan with port shuffling and a retransmit pass.

    Returns {port: state}. No reply after both passes becomes `default_state`
    (filtered for SYN, open|filtered for XMAS).
    """
    source_ip = get_source_ip(ip)
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
    except PermissionError:
        print("Raw sockets need root. Try: sudo python3 sxp.py")
        return None, source_ip

    # Shuffle so we don't hammer a firewall's rate-limit in port order.
    order = list(ports)
    random.shuffle(order)
    sport_of = {(40000 + i) % 65536 or 1: p for i, p in enumerate(order)}
    port_sport = {p: s for s, p in sport_of.items()}
    results = {}

    def send(targets):
        for p in targets:
            pkt = (build_ip_header(source_ip, ip) +
                   build_tcp_header(source_ip, ip, port_sport[p], p, flags))
            try:
                send_sock.sendto(pkt, (ip, 0))
            except OSError as e:
                results[p] = f"error: {e}"

    def listen(deadline, pending):
        while pending and time.time() < deadline:
            recv_sock.settimeout(max(0.05, deadline - time.time()))
            try:
                data, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                break
            except OSError:
                continue
            if addr[0] != ip or len(data) < 40:
                continue
            ihl = (data[0] & 0x0f) * 4
            if len(data) < ihl + 20:
                continue
            src_port, dst_port = struct.unpack('!HH', data[ihl:ihl + 4])
            if dst_port not in sport_of or src_port != sport_of[dst_port]:
                continue
            state = interpret(data[ihl + 13])
            if state is not None:
                results[sport_of[dst_port]] = state
                pending.discard(sport_of[dst_port])

    pending = set(p for p in ports if p not in results)
    send(pending)
    listen(time.time() + timeout, pending)
    # Retransmit pass for everything still silent (packet loss insurance).
    if pending:
        time.sleep(0.3)
        send(set(pending))
        listen(time.time() + timeout, pending)

    send_sock.close()
    recv_sock.close()
    for p in ports:
        results.setdefault(p, default_state)
    return results, source_ip


# --------------------------------------------------------------------------- #
# ICMP ping                                                                    #
# --------------------------------------------------------------------------- #

def create_icmp_packet(packet_id):
    header = struct.pack('!BBHHH', 8, 0, 0, packet_id, 1)
    data = b'ilovermrf'
    my_checksum = checksum(header + data)
    header = struct.pack('!BBHHH', 8, 0, my_checksum, packet_id, 1)
    return header + data


def icmp_ping(host):
    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"Cannot resolve {host}: {e}")
        return
    packet_id = int(time.time() * 1000) & 0xffff
    packet = create_icmp_packet(packet_id)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_ICMP)
    except PermissionError:
        print("ICMP ping needs root. Try: sudo python3 sxp.py")
        return
    try:
        start = time.time()
        sock.sendto(packet, (target_ip, 0))
        deadline = start + 2
        while time.time() < deadline:
            sock.settimeout(max(0.05, deadline - time.time()))
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                break
            ihl = (data[0] & 0x0f) * 4
            if len(data) < ihl + 8:
                continue
            icmp_type, icmp_code, _, reply_id, _ = struct.unpack(
                '!BBHHH', data[ihl:ihl + 8])
            if icmp_type == 0 and reply_id == packet_id:
                rtt = (time.time() - start) * 1000
                ttl = data[8]
                print(f"Reply from {addr[0]}: {len(data)} bytes, "
                      f"ttl={ttl}, RTT {rtt:.2f} ms")
                return
        print(f"No reply from {host} (timed out)")
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# Scan orchestration + reporting                                               #
# --------------------------------------------------------------------------- #

def _fingerprint_open(ip, hostname, open_ports):
    fps = {}
    if not open_ports:
        return fps
    workers = min(MAX_WORKERS, max(4, len(open_ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fingerprint_port, ip, hostname, p): p
                   for p in open_ports}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                fps[port] = fut.result()
            except Exception as e:                         # noqa: BLE001
                fp = Fingerprint(port=port)
                fp.error = f"fingerprint error: {e}"
                fps[port] = fp
    return fps


def _emit_scan(spec, results, fps, elapsed, scan_type, verbose):
    """Print a scan report and return a JSON-able structure of it."""
    open_ports = sorted(p for p in results if results[p] == "open")
    struct_ports = []

    for port in sorted(results):
        state = results[port]
        is_open = state == "open"
        is_err = state.startswith("error")
        entry = {"port": port, "state": state}
        if is_open:
            entry["service"] = service_name(port)
        else:
            entry["port_hint"] = service_name(port)
        if is_open and port in fps:
            entry["fingerprint"] = asdict(fps[port])
        struct_ports.append(entry)

        if not (verbose or is_open or is_err):
            continue
        if is_open:
            print(f"Port {port:>5}: {GREEN}open{RESET}         {service_name(port)}")
            for line in fingerprint_lines(fps.get(port, Fingerprint(port=port)),
                                          verbose):
                print(line)
        else:
            hint = service_name(port)
            hint_txt = f"  (port-hint: {hint})" if hint != "unknown" else ""
            print(f"Port {port:>5}: {state}{hint_txt}")

    # Summary footer.
    total = len(results)
    n_open = len(open_ports)
    n_closed = sum(1 for s in results.values() if s == "closed")
    n_filtered = sum(1 for s in results.values()
                     if s in ("filtered", "open|filtered"))
    n_err = sum(1 for s in results.values() if s.startswith("error"))
    tail = ""
    if n_filtered and n_filtered > n_open and n_closed <= max(3, total // 100):
        tail = " (default-drop firewall detected)"
    err_txt = f", {n_err} errored" if n_err else ""
    summary = (f"Scanned {total} ports in {elapsed:.2f}s: "
               f"{n_open} open, {n_closed} closed, {n_filtered} filtered"
               f"{err_txt}{tail}")
    print(summary)

    insights = host_intel(open_ports, fps)
    for line in insights:
        print(f"  {line}")

    return {
        "type": scan_type,
        "target": {"input": spec.host_input, "hostname": spec.hostname,
                   "ip": spec.ip},
        "elapsed_s": round(elapsed, 3),
        "summary": summary,
        "insights": insights,
        "ports": struct_ports,
    }


def run_scan(spec, scan_type, verbose, banner):
    """Drive a syn/xmas/connect scan and print + return structured results."""
    ip, label = spec.ip, spec.hostname
    print(f"{scan_type.upper()} scan of {label} ({ip}) - "
          f"{len(spec.ports)} port(s)")
    start = time.time()

    if scan_type == "connect":
        results = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(connect_scan_port, ip, p): p
                       for p in spec.ports}
            for fut in as_completed(futures):
                results[futures[fut]] = fut.result()
    else:
        flags, interp, default_state = (
            (0x02, syn_interpret, "filtered") if scan_type == "syn"
            else (0x29, xmas_interpret, "open|filtered"))
        results, src = raw_scan(ip, label, spec.ports, flags, interp,
                                default_state)
        if results is None:
            return None
        print(f"(source IP {src})")

    open_ports = sorted(p for p in results if results[p] == "open")
    fps = _fingerprint_open(ip, label, open_ports) if banner else {}
    elapsed = time.time() - start
    return _emit_scan(spec, results, fps, elapsed, scan_type, verbose)


def run_fingerprint(spec, verbose):
    """Deep L7 fingerprint of specific ports (no full port scan)."""
    ip, label = spec.ip, spec.hostname
    print(f"Fingerprint of {label} ({ip}) on ports "
          f"{', '.join(map(str, spec.ports))}")
    start = time.time()
    fps = _fingerprint_open(ip, label, spec.ports)
    struct_ports = []
    for port in spec.ports:
        fp = fps.get(port, Fingerprint(port=port))
        reachable = bool(fp.http_status or fp.raw_banner or fp.evidence)
        print(f"Port {port:>5}: " +
              (f"{GREEN}responded{RESET}" if reachable else "no response"))
        for line in fingerprint_lines(fp, True):
            print(line)
        struct_ports.append({"port": port, "fingerprint": asdict(fp)})
    elapsed = time.time() - start
    insights = host_intel([p for p in spec.ports
                           if fps.get(p) and fps[p].http_status], fps)
    for line in insights:
        print(f"  {line}")
    print(f"Fingerprinted {len(spec.ports)} port(s) in {elapsed:.2f}s")
    return {
        "type": "fingerprint",
        "target": {"input": spec.host_input, "hostname": spec.hostname,
                   "ip": spec.ip},
        "elapsed_s": round(elapsed, 3),
        "insights": insights,
        "ports": struct_ports,
    }


# --------------------------------------------------------------------------- #
# WAF / CDN detection (Block 3)                                                #
# --------------------------------------------------------------------------- #

WAF_BLOCK_CODES = {403, 406, 418, 419, 429, 494, 495, 496, 501}

WAF_PROBES = [
    ("sqli", "/?id=1%27%20OR%20%271%27%3D%271"),
    ("xss", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ("lfi", "/?file=../../../../../../../etc/passwd"),
    ("rce", "/?cmd=;cat%20/etc/passwd"),
]
WAF_BAD_UA = "() { :;}; /bin/bash -c 'id'"

WAF_HEADER_SIGS = [
    ("Cloudflare", "cf-ray", None),
    ("Cloudflare", "cf-cache-status", None),
    ("Cloudflare", "cf-mitigated", None),
    ("Cloudflare", "server", "cloudflare"),
    ("Imperva Incapsula", "x-iinfo", None),
    ("Imperva Incapsula", "x-cdn", "incapsula"),
    ("Akamai", "server", "akamaighost"),
    ("Akamai", "x-akamai-transformed", None),
    ("Sucuri CloudProxy", "x-sucuri-id", None),
    ("Sucuri CloudProxy", "x-sucuri-cache", None),
    ("Sucuri CloudProxy", "server", "sucuri"),
    ("AWS WAF", "x-amzn-waf-action", None),
    ("AWS CloudFront", "server", "cloudfront"),
    ("F5 BIG-IP ASM", "server", "big-ip"),
    ("Fastly", "x-served-by", "cache-"),
    ("Barracuda", "server", "barracuda"),
    ("FortiWeb", "server", "fortiweb"),
    ("ModSecurity", "server", "mod_security"),
    ("DDoS-Guard", "server", "ddos-guard"),
    ("Qrator", "server", "qrator"),
]
WAF_COOKIE_SIGS = [
    ("Cloudflare", "__cf_bm"),
    ("Cloudflare", "cf_clearance"),
    ("Imperva Incapsula", "incap_ses"),
    ("Imperva Incapsula", "visid_incap"),
    ("F5 BIG-IP", "TS01"),
    ("Citrix NetScaler", "citrix_ns_id"),
    ("Citrix NetScaler", "ns_af"),
    ("Barracuda", "barra_counter_session"),
    ("FortiWeb", "FORTIWAFSID"),
    ("Airlock", "AL_SESS"),
]
WAF_BODY_SIGS = [
    ("Cloudflare (challenge)", "just a moment"),
    ("Cloudflare (challenge)", "_cf_chl_opt"),
    ("Cloudflare", "attention required!"),
    ("Cloudflare", "cloudflare ray id"),
    ("ModSecurity", "mod_security"),
    ("Sucuri CloudProxy", "sucuri website firewall"),
    ("Imperva Incapsula", "incapsula incident id"),
    ("Imperva Incapsula", "powered by incapsula"),
    ("Wordfence", "generated by wordfence"),
    ("Citrix NetScaler", "violation of security policy"),
    ("DDoS-Guard", "ddos-guard"),
    ("StormWall", "stormwall"),
    ("Qrator", "qrator"),
    ("Bitrix Cloud Protection", "bitrix"),
    ("NAXSI", "naxsi"),
]
WAF_BLOCK_BODY = (
    "has been blocked", "request blocked", "access denied",
    "web application firewall", "not acceptable", "forbidden",
    "blocked by", "security policy", "/blocked", "/captcha",
)
WAF_CHALLENGE_SIGS = ("just a moment", "_cf_chl_opt", "checking your browser",
                      "ddos-guard", "stormwall", "qrator",
                      "attention required", "ray id")


@dataclass
class WafResult:
    port: int
    transport: str = "TCP"
    baseline_status: str = ""
    baseline_rtt_ms: float = 0.0
    baseline_length: int = 0
    redirect_note: str = ""
    challenge: str = ""
    blocked: List[Tuple[str, int, str]] = field(default_factory=list)
    waf_names: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    spoof_note: str = ""
    error: str = ""


def _cookie_names(resp):
    names = set()
    for c in resp.cookies:
        name = c.split("=", 1)[0].strip().lower()
        if name:
            names.add(name)
    return names


def _blob(resp):
    return "\n".join(f"{k}: {v}" for k, v in resp.headers_raw).lower()


def waf_detect(ip, hostname, port, timeout=SOCKET_TIMEOUT):
    """L7 WAF/CDN probe: baseline + attack probes + differential analysis."""
    result = WafResult(port=port)

    use_tls = port in TLS_PORTS
    base = None
    for try_tls in ([True] if use_tls else [False, True]):
        resp, chain = fetch_follow(ip, port, try_tls, hostname, "/", timeout)
        if resp.code:
            use_tls = try_tls
            base = resp
            if chain:
                result.redirect_note = " -> ".join(
                    f"{c}:{loc}" for c, loc in chain)
            break
    if base is None:
        result.error = "no HTTP response (not a web port, or filtered)"
        return result

    result.transport = base.transport
    result.baseline_status = base.status
    result.baseline_rtt_ms = round(base.rtt_ms, 1)
    result.baseline_length = base.length
    base_code = base.code
    base_cookies = _cookie_names(base)

    # Passive challenge detection on the baseline itself.
    low_body = base.body.lower()
    low_blob = _blob(base)
    if "cf-mitigated:" in low_blob or any(s in low_body for s in WAF_CHALLENGE_SIGS):
        result.challenge = "JS challenge / CAPTCHA page on baseline"

    responses = [base]
    probes = [(n, p, None) for n, p in WAF_PROBES]
    probes.append(("bad-user-agent", "/", {"User-Agent": WAF_BAD_UA}))
    for name, path, extra in probes:
        r = http_request(ip, port, use_tls, hostname, path,
                         extra_headers=extra, timeout=timeout)
        if not r.code and not r.body:
            continue
        responses.append(r)
        reason = ""
        if r.code in WAF_BLOCK_CODES and r.code != base_code:
            reason = f"status {base_code}->{r.code}"
        elif any(sig in r.body.lower() for sig in WAF_BLOCK_BODY):
            reason = "block-page body"
        elif (r.code == base_code and base.length > 1500
              and r.length < max(500, base.length * 0.4)):
            reason = f"body shrank {base.length}->{r.length} bytes"
        elif r.code in (301, 302, 303, 307, 308) and any(
                x in r.location.lower() for x in ("block", "captcha", "denied")):
            reason = f"redirect to {r.location}"
        else:
            # New WAF-looking cookies appearing only after an attack probe are
            # themselves a soft block signal.
            new_cookies = _cookie_names(r) - base_cookies
            for _, ck in WAF_COOKIE_SIGS:
                if any(ck.lower() in c for c in new_cookies):
                    reason = f"set new cookie '{ck}' on attack probe"
                    break
        if reason:
            result.blocked.append((name, r.code, reason))

    # Fingerprint vendor across all responses.
    names, evidence = set(), set()
    seen_cf_ray = claims_cf = False
    for resp in responses:
        blob = _blob(resp)
        body = resp.body.lower()
        if re.search(r"(?m)^cf-ray:", blob):
            seen_cf_ray = True
        if re.search(r"(?m)^server:.*cloudflare", blob):
            claims_cf = True
        for wname, hkey, hval in WAF_HEADER_SIGS:
            if hval is None:
                if re.search(rf"(?m)^{re.escape(hkey)}:", blob):
                    names.add(wname)
                    evidence.add(f"header '{hkey}' present -> {wname}")
            elif re.search(rf"(?m)^{re.escape(hkey)}:.*{re.escape(hval)}", blob):
                names.add(wname)
                evidence.add(f"header '{hkey}' contains '{hval}' -> {wname}")
        for wname, ck in WAF_COOKIE_SIGS:
            if re.search(rf"set-cookie:.*{re.escape(ck.lower())}", blob):
                names.add(wname)
                evidence.add(f"cookie '{ck}' -> {wname}")
        for wname, sig in WAF_BODY_SIGS:
            if sig in body:
                names.add(wname)
                evidence.add(f"body: '{sig}' -> {wname}")

    if claims_cf and not seen_cf_ray:
        result.spoof_note = ("Server claims Cloudflare but no 'cf-ray' in any "
                             "response -> spoofed header, not a real CF edge")
        names = {n for n in names if not n.startswith("Cloudflare")}
        evidence = {e for e in evidence if "-> Cloudflare" not in e}

    result.waf_names = sorted(names)
    result.evidence = sorted(evidence)
    return result


def waf_lines(res):
    out = []
    if res.error:
        out.append(f"  WAF probe: {res.error}")
        return out
    out.append(f"  [{res.transport}] baseline {res.baseline_status} "
               f"({res.baseline_length} bytes, {res.baseline_rtt_ms} ms)")
    if res.redirect_note:
        out.append(f"  baseline redirect: {res.redirect_note}")
    if res.challenge:
        out.append(f"  {YELLOW}[*] {res.challenge}{RESET}")
    if res.waf_names:
        out.append(f"  {RED}[!] WAF/CDN detected: {', '.join(res.waf_names)}{RESET}")
    elif res.blocked:
        out.append(f"  {RED}[!] Generic WAF present: attack patterns are "
                   f"blocked (no vendor fingerprint){RESET}")
    else:
        out.append("  No WAF detected: attack patterns passed through "
                   "(server answered them like normal requests)")
    if res.spoof_note:
        out.append(f"  {RED}[!] {res.spoof_note}{RESET}")
    if res.blocked:
        for name, code, reason in res.blocked:
            out.append(f"  blocked: {name} -> {code} ({reason})")
    else:
        out.append("  blocked: none (SQLi/XSS/LFI/RCE/bad-UA all got through)")
    for e in res.evidence:
        out.append(f"    - {e}")
    return out


def run_waf(spec, timeout=SOCKET_TIMEOUT):
    """Run the WAF probe on the first port that speaks HTTP; return struct."""
    ip, label = spec.ip, spec.hostname
    for port in spec.ports:
        print(f"WAF probe of {label}:{port} ...")
        res = waf_detect(ip, label, port, timeout)
        if res.error and len(spec.ports) > 1:
            print(f"  {res.error}; trying next port...")
            continue
        for line in waf_lines(res):
            print(line)
        return {
            "type": "waf",
            "target": {"input": spec.host_input, "hostname": label, "ip": ip},
            "port": port,
            "result": asdict(res),
        }
    print("  No web port responded.")
    return None


# --------------------------------------------------------------------------- #
# Self-update                                                                  #
# --------------------------------------------------------------------------- #

def fetch_latest(timeout=10):
    try:
        req = urllib.request.Request(
            UPDATE_URL, headers={"User-Agent": f"sxp-scanner/{VERSION}"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception:
        return None


def remote_version(remote_bytes):
    m = re.search(rb'^VERSION = "([^"]+)"', remote_bytes, re.MULTILINE)
    return m.group(1).decode() if m else "?"


def update_available(remote_bytes):
    try:
        with open(os.path.abspath(__file__), "rb") as f:
            local = f.read()
    except OSError:
        return False
    return hashlib.sha256(remote_bytes).digest() != hashlib.sha256(local).digest()


def self_update():
    print(f"Checking {UPDATE_URL} ...")
    remote = fetch_latest()
    if remote is None:
        print("Update check failed (network error or file not reachable).")
        return
    if not update_available(remote):
        print(f"Already up to date (version {VERSION}).")
        return
    print(f"Update available: {VERSION} -> {remote_version(remote)}")
    path = os.path.abspath(__file__)
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
        with os.fdopen(fd, "wb") as f:
            f.write(remote)
        os.chmod(tmp, os.stat(path).st_mode)
        os.replace(tmp, path)
    except PermissionError:
        print(f"Cannot write {path}: permission denied. Re-run with sudo.")
        return
    except OSError as e:
        print(f"Update failed: {e}")
        return
    print("Updated successfully. Restart sxp to run the new version.")


def startup_update_check():
    remote = fetch_latest(timeout=4)
    if remote is not None and update_available(remote):
        print(f"{GREEN}[*] Update available: {VERSION} -> "
              f"{remote_version(remote)}. Type 'update' to install.{RESET}")


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

class PortScanner(cmd.Cmd):
    intro = GREEN + """
================================================================================
SXP Scanner 1.3 - scanning, service unmasking, WAF detection & host intel
================================================================================
By: Egwyl666   GitHub: https://github.com/egwyl666
================================================================================
Targets accept host, host:port or URL (https://site.com:8443/path).
  syn <target> <ports>        raw half-open SYN scan      (root)
  connect <target> <ports>    TCP connect scan            (no root)
  xmas <target> <ports>       FIN+PSH+URG scan            (root)
  fp <target> [ports]         deep L7 fingerprint (default 80,443,8080,8443)
  waf <target> [port]         probe a web port for a WAF/CDN (L7)
  ping <host>                 ICMP echo / TTL / RTT       (root)
  verbose on|off              show closed/filtered ports & full evidence
  banner on|off               fingerprint open ports during a scan
  export <file.json>          save the last result as JSON
  update                      install the latest version
  exit
================================================================================
    """ + RESET
    prompt = BLUE + "(SXP) " + RESET

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.verbose = False
        self.banner = False
        self.last_result = None

    # -- helpers ----------------------------------------------------------- #

    def _target(self, arg, default_ports=None, need_ports=False):
        parts = arg.split()
        if not parts:
            print("Usage: <command> <target> [ports]")
            return None
        spec = parse_target(parts[0], port_args=parts[1:] or None,
                            default_ports=default_ports)
        if spec.error:
            print(spec.error)
            return None
        if need_ports and not spec.ports:
            print("Specify port(s), e.g. 'syn host 1-1024' or 'syn host:8443'")
            return None
        return spec

    # -- scans ------------------------------------------------------------- #

    def do_syn(self, arg):
        'Raw SYN scan: syn <target> <ports>   (needs root)'
        spec = self._target(arg, need_ports=True)
        if spec:
            res = run_scan(spec, "syn", self.verbose, self.banner)
            if res:
                self.last_result = res

    def do_connect(self, arg):
        'TCP connect scan: connect <target> <ports>'
        spec = self._target(arg, need_ports=True)
        if spec:
            self.last_result = run_scan(spec, "connect", self.verbose, self.banner)

    def do_xmas(self, arg):
        'XMAS scan: xmas <target> <ports>   (needs root)'
        spec = self._target(arg, need_ports=True)
        if spec:
            res = run_scan(spec, "xmas", self.verbose, self.banner)
            if res:
                self.last_result = res

    def do_fp(self, arg):
        'Deep L7 fingerprint: fp <target> [ports]  (default 80,443,8080,8443)'
        spec = self._target(arg, default_ports=[80, 443, 8080, 8443])
        if spec:
            self.last_result = run_fingerprint(spec, self.verbose)

    do_inspect = do_fp

    def do_waf(self, arg):
        'Probe a web port for a WAF/CDN: waf <target> [port]'
        spec = self._target(arg, default_ports=[443, 80])
        if spec:
            self.last_result = run_waf(spec)

    def do_ping(self, arg):
        'Ping a host with ICMP echo: ping <host>   (needs root)'
        if not arg.strip():
            print("Usage: ping <host>")
            return
        icmp_ping(arg.strip())

    # -- toggles / utility ------------------------------------------------- #

    def do_verbose(self, arg):
        'Show all port states and full evidence: verbose on|off'
        val = arg.strip().lower()
        if val in ("on", "true", "1"):
            self.verbose = True
        elif val in ("off", "false", "0"):
            self.verbose = False
        print(f"verbose = {self.verbose}")

    def do_banner(self, arg):
        'Fingerprint open ports during a scan: banner on|off'
        val = arg.strip().lower()
        if val in ("on", "true", "1"):
            self.banner = True
        elif val in ("off", "false", "0"):
            self.banner = False
        print(f"banner = {self.banner}")

    def do_export(self, arg):
        'Save the last scan/fp/waf result as JSON: export <file.json>'
        path = arg.strip()
        if not path:
            print("Usage: export <file.json>")
            return
        if self.last_result is None:
            print("Nothing to export yet. Run a scan, fp or waf first.")
            return
        try:
            with open(path, "w") as f:
                json.dump(self.last_result, f, indent=2, default=str)
        except OSError as e:
            print(f"Export failed: {e}")
            return
        print(f"Exported last result to {path}")

    def do_update(self, arg):
        'Download and install the latest version: update'
        self_update()

    def do_exit(self, arg):
        'Exit the scanner'
        print("GG")
        return True

    do_EOF = do_exit


if __name__ == "__main__":
    print(LOGO)
    if os.environ.get("SXP_NO_UPDATE_CHECK") != "1":
        threading.Thread(target=startup_update_check, daemon=True).start()
    try:
        PortScanner().cmdloop()
    except KeyboardInterrupt:
        print("\nGG")
