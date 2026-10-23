import cmd
import hashlib
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"

MAX_WORKERS = 200

VERSION = "1.2"
# Where `update` pulls a fresh sxp.py from. Both are overridable via env
# so a fork or a local mirror can be used for testing.
UPDATE_BASE = os.environ.get(
    "SXP_UPDATE_BASE",
    "https://raw.githubusercontent.com/egwyl666/SXP-Scanner")
UPDATE_BRANCH = os.environ.get("SXP_BRANCH", "work/fixit1.0")
UPDATE_URL = f"{UPDATE_BASE}/{UPDATE_BRANCH}/sxp.py"

LOGO = RED + r"""
███████╗██╗  ██╗██████╗
██╔════╝╚██╗██╔╝██╔══██╗
███████╗ ╚███╔╝ ██████╔╝
╚════██║ ██╔██╗ ██╔═══╝
███████║██╔╝ ██╗██║
╚══════╝╚═╝  ╚═╝╚═╝     """ + RESET


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
    """Find the local address the kernel would use to reach target_ip.

    No packet is sent: connecting a UDP socket only sets the route.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def service_name(port):
    """Well-known service name for a port, from the system services DB."""
    for proto in ("tcp", "udp"):
        try:
            return socket.getservbyport(port, proto)
        except OSError:
            continue
    return "unknown"


# --------------------------------------------------------------------------- #
# Service fingerprinting / unmasking                                          #
# --------------------------------------------------------------------------- #

# Ports assumed to speak TLS from the first byte.
TLS_PORTS = {443, 8443, 9443, 4443}
# Plaintext HTTP ports where an empty reply is normal (no TLS fallback).
PLAINTEXT_HTTP_PORTS = {80, 81, 591, 8000, 8008, 8080, 8081, 8888}
# Server headers commonly spoofed; seeing one is worth an error-page probe.
SPOOF_PRONE = {"cloudflare", "apache", "iis", "microsoft-iis", "gws",
               "openresty"}
# Issuer names that legitimately appear in front of public CDNs / sites.
PUBLIC_CA_HINTS = ("cloudflare", "google trust", "digicert", "lets encrypt",
                   "let's encrypt", "amazon", "sectigo", "globalsign",
                   "baltimore", "isrg")
SOCKET_TIMEOUT = 2.5
READ_LIMIT = 8192

# Default error-page body signatures admins often forget to mask.
_BODY_SIGS = [
    ("nginx", "<center>nginx</center>"),
    ("openresty", "openresty"),
    ("apache", "<address>apache"),
    ("apache", "apache/"),
    ("iis", "microsoft-iis"),
    ("litespeed", "litespeed"),
    ("caddy", "caddy"),
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
    source: str = ""           # how the cert was decoded

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
    transport: str = "TCP"          # "TCP" or a TLS version string
    tls_version: str = ""
    cipher: str = ""
    cert: Optional[CertInfo] = None
    http_status: str = ""
    title: str = ""
    server_header: str = ""
    headers_raw: List[Tuple[str, str]] = field(default_factory=list)
    headers_lower: dict = field(default_factory=dict)
    body_snippet: str = ""
    raw_banner: str = ""            # non-HTTP services (SSH, FTP, SMTP, ...)
    evidence: List[Evidence] = field(default_factory=list)
    inferred_service: str = ""
    spoofed: bool = False
    error: str = ""


# --- transport helpers ----------------------------------------------------- #

def _tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Accept legacy/odd servers too; we only want to read, not to trust.
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def _open_socket(host, port, use_tls, timeout=SOCKET_TIMEOUT):
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    if not use_tls:
        return raw
    ctx = _tls_context()
    try:
        return ctx.wrap_socket(raw, server_hostname=host)
    except (ssl.SSLError, ValueError, OSError):
        try:
            raw.close()
        except OSError:
            pass
        # Retry without SNI (e.g. host is a bare IP address).
        raw2 = socket.create_connection((host, port), timeout=timeout)
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
    # TLS record header: 0x16 handshake / 0x15 alert, then 0x03 version byte.
    return len(data) >= 2 and data[0] in (0x15, 0x16) and data[1] == 0x03


# --- HTTP helpers ----------------------------------------------------------- #

def _http_get(host):
    return (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: Mozilla/5.0 (compatible; SXP-Scanner/1.2)\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode()


def _http_bad():
    # Empty Host makes nginx and friends answer with their native 400 page.
    return b"GET / HTTP/1.1\r\nHost: \r\n\r\n"


def _parse_http(data):
    """Parse an HTTP response, or return None if `data` is not one."""
    if not data[:5].upper().startswith(b"HTTP/"):
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace").strip()
    headers_raw = []
    headers_lower = {}
    for ln in lines[1:]:
        if b":" not in ln:
            continue
        k, _, v = ln.partition(b":")
        key = k.decode("latin-1", "replace").strip()
        val = v.decode("latin-1", "replace").strip()
        headers_raw.append((key, val))
        headers_lower[key.lower()] = val
    body_text = body[:2048].decode("latin-1", "replace")
    m = re.search(r"<title[^>]*>(.*?)</title>", body_text,
                  re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
    return status_line, headers_raw, headers_lower, body_text, title


def _engine_from_body(body):
    """Identify a web engine from body signatures: (engine, matched_sig)."""
    if not body:
        return "", ""
    low = body.lower()
    for engine, sig in _BODY_SIGS:
        if sig in low:
            return engine, sig
    return "", ""


def _family(server_header):
    """First token of a Server header, lowercased: 'nginx/1.18' -> 'nginx'."""
    if not server_header or not server_header.strip():
        return ""
    return server_header.split("/")[0].split()[0].strip().lower()


# --- TLS certificate extraction (stdlib hack + fallbacks) ------------------- #

def _name_field(name_seq, key):
    """Pull a value from the ((('commonName','x'),),...) RDN structure."""
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
    """Last-resort: pull commonName strings straight out of the DER bytes."""
    ci = CertInfo(source="der-scan")
    cns = []
    marker = b"\x06\x03\x55\x04\x03"   # OID 2.5.4.3 = commonName
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
    """Decode the peer certificate even when verification is disabled."""
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
    """Lifetime of the cert in days, or None if the dates can't be parsed."""
    if not cert.not_before or not cert.not_after:
        return None
    try:
        nb = ssl.cert_time_to_seconds(cert.not_before)
        na = ssl.cert_time_to_seconds(cert.not_after)
    except (ValueError, OSError):
        return None
    return int((na - nb) / 86400)


def _cert_is_private(cert):
    """True if the cert is self-signed or from a non-public / internal CA."""
    if cert.self_signed:
        return True
    issuer = f"{cert.issuer_o} {cert.issuer_cn}".lower().strip()
    if not issuer:
        return True
    return not any(h in issuer for h in PUBLIC_CA_HINTS)


# --- probe pipeline --------------------------------------------------------- #

def _plaintext_probe(host, port, timeout):
    """Returns (http_bytes, greeting_or_None, tls_hint, marker)."""
    try:
        sock = _open_socket(host, port, False, timeout)
    except OSError:
        return b"", None, False, ""
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
                    return b"", first.strip()[:120], False, ""
            if is_http:
                rest = _recv_all(sock, READ_LIMIT - len(greet))
                return greet + rest, None, False, ""
            if is_tls:
                return greet, None, True, ""
        try:
            sock.sendall(_http_get(host))
            data = _recv_all(sock)
        except OSError:
            data = b""
    finally:
        sock.close()

    nginx_sig = b"plain HTTP request was sent to HTTPS port" in data
    tls_hint = (_looks_like_tls(data) or nginx_sig
                or (not data and port not in PLAINTEXT_HTTP_PORTS))
    marker = "nginx-https" if nginx_sig else ""
    return data, None, tls_hint, marker


def _tls_probe(host, port, timeout, fp):
    """Do the TLS handshake, fill transport/cert on `fp`, return HTTP bytes."""
    try:
        sock = _open_socket(host, port, True, timeout)
    except OSError as e:
        if not fp.error:
            fp.error = f"TLS handshake failed: {e}"
        return b""
    try:
        fp.transport = sock.version() or "TLS"
        fp.tls_version = fp.transport
        c = sock.cipher()
        fp.cipher = c[0] if c else ""
        fp.cert = extract_cert_info(sock)
        try:
            sock.sendall(_http_get(host))
            return _recv_all(sock)
        except OSError:
            return b""
    finally:
        sock.close()


def _error_probe(host, port, use_tls):
    """Send a malformed request to elicit the server's native error page."""
    try:
        sock = _open_socket(host, port, use_tls, SOCKET_TIMEOUT)
    except OSError:
        return ""
    try:
        sock.sendall(_http_bad())
        data = _recv_all(sock, 4096)
    except OSError:
        data = b""
    finally:
        sock.close()
    return data.decode("latin-1", "replace")


def fingerprint_port(host, port, timeout=SOCKET_TIMEOUT):
    """Smart probe + unmasking for a single open TCP port."""
    fp = Fingerprint(port=port)
    use_tls = port in TLS_PORTS
    marker = ""
    http_data = b""

    if not use_tls:
        http_data, greeting, tls_hint, marker = _plaintext_probe(
            host, port, timeout)
        if greeting is not None:
            fp.raw_banner = greeting
            return fp
        if tls_hint:
            use_tls = True
            http_data = b""

    if use_tls:
        http_data = _tls_probe(host, port, timeout, fp)

    if marker == "nginx-https":
        fp.evidence.append(Evidence(
            5, "plaintext request to a TLS port returned the nginx signature "
               "'The plain HTTP request was sent to HTTPS port'", "nginx"))

    if http_data:
        parsed = _parse_http(http_data)
        if parsed:
            (fp.http_status, fp.headers_raw, fp.headers_lower,
             fp.body_snippet, fp.title) = parsed
            fp.server_header = fp.headers_lower.get("server", "")
        elif not fp.raw_banner:
            fp.raw_banner = http_data.decode(
                "latin-1", "replace").splitlines()[0][:120]

    _unmask(fp, host, port, use_tls)
    return fp


# --- heuristics / unmasking engine ----------------------------------------- #

def _unmask(fp, host, port, use_tls):
    server_family = _family(fp.server_header)

    # Active error-page probe when the Server header is spoof-prone or absent.
    if fp.http_status and (server_family in SPOOF_PRONE or not fp.server_header):
        engine, sig = _engine_from_body(_error_probe(host, port, use_tls))
        if engine:
            fp.evidence.append(Evidence(
                5, f"default error page reveals {engine} ('{sig}')", engine))

    # Engine signature in the main response body.
    engine, sig = _engine_from_body(fp.body_snippet)
    if engine:
        fp.evidence.append(Evidence(
            4, f"response body reveals {engine} ('{sig}')", engine))

    # Fake-Cloudflare specific checks.
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

    # Certificate lifetime: since 2020 public CAs issue certs valid for at
    # most ~398 days, so anything much longer is an internal / self CA.
    if fp.cert:
        days = _cert_validity_days(fp.cert)
        if days and days > 398:
            fp.evidence.append(Evidence(
                2, f"TLS certificate valid for {days} days (> 398); public "
                   f"CAs no longer issue certificates this long "
                   f"(internal / self-signed CA)"))

    # A CDN that answers over plaintext HTTP is a contradiction in itself:
    # a real Cloudflare edge terminates TLS and never serves bare HTTP here.
    if "cloudflare" in server_family and fp.transport == "TCP":
        fp.evidence.append(Evidence(
            3, "Server claims Cloudflare but answers over plaintext HTTP "
               "(a real Cloudflare edge terminates TLS)"))

    # Verdict: pick the highest-weight evidence that names a service.
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

    # Claimed CDN contradicted by strong evidence even without a positive ID.
    if "cloudflare" in server_family and not fp.spoofed:
        if any(e.weight >= 3 for e in fp.evidence):
            fp.spoofed = True
            if not best:
                fp.inferred_service = "non-Cloudflare origin"


# --- output ----------------------------------------------------------------- #

def fingerprint_lines(fp, verbose):
    """Indented report lines for one port's fingerprint."""
    out = []
    if fp.raw_banner and not fp.http_status:
        out.append(f"        {fp.raw_banner}")
        return out
    if not fp.http_status:
        # No HTTP response, but we may still have learned something, e.g. an
        # nginx plaintext signature seen just before a failed TLS retry.
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

    head = f"        [{fp.transport}] {fp.http_status}"
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

    if fp.cert:
        out.append(f"        cert: {fp.cert.one_line()}")

    if verbose:
        for e in sorted(fp.evidence, key=lambda x: -x.weight):
            tag = f" -> {e.inferred_service}" if e.inferred_service else ""
            out.append(f"          - [w={e.weight}] {e.description}{tag}")
        if fp.tls_version:
            out.append(f"          TLS: {fp.tls_version} / {fp.cipher}")
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


def parse_ports(args):
    """Turn ['22', '80', '20-25'] into a sorted, de-duplicated list of ports.

    Raises ValueError on anything that is not a valid port or range.
    """
    ports = set()
    for port_arg in args:
        if '-' in port_arg:
            start_str, _, end_str = port_arg.partition('-')
            start, end = int(start_str), int(end_str)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                ports.add(p)
        else:
            ports.add(int(port_arg))
    for p in ports:
        if not 0 < p < 65536:
            raise ValueError(f"port out of range: {p}")
    return sorted(ports)


# --------------------------------------------------------------------------- #
# SYN / connect scanning                                                      #
# --------------------------------------------------------------------------- #

def connect_scan_port(host, port):
    """TCP connect() probe. No privileges required. Returns a state string."""
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


def connect_scan(host, ports, verbose=False, banner=False):
    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"Cannot resolve {host}: {e}")
        return
    print(f"Connect scan of {host} ({target_ip}) - {len(ports)} port(s)")
    _run_pool(connect_scan_port, host, ports, verbose, banner)


# --------------------------------------------------------------------------- #
# Raw-packet scanning (SYN / XMAS) - needs root                               #
# --------------------------------------------------------------------------- #

def build_ip_header(source_ip, dest_ip):
    ip_ihl_ver = (4 << 4) + 5
    ip_tot_len = 40                      # 20 IP + 20 TCP
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
    tcp_window = 1024                    # packed big-endian below, swapped once
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


def raw_scan(host, ports, flags, interpret, verbose=False, banner=False):
    """Send one crafted TCP packet per port and read replies on a shared
    IPPROTO_TCP socket, matching them back to the port by src/dst.

    `flags` is the TCP flag byte to send; `interpret(tcp_flags)` maps a
    reply's flags to a state, or returns None for 'no reply'.
    """
    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"Cannot resolve {host}: {e}")
        return

    source_ip = get_source_ip(target_ip)
    base_sport = 40000

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Replies to our crafted packets arrive here, not on IPPROTO_RAW.
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_TCP)
    except PermissionError:
        print("Raw sockets need root. Try: sudo python3 sxp.py")
        return

    print(f"Raw scan of {host} ({target_ip}) from {source_ip} - "
          f"{len(ports)} port(s)")

    results = {}
    # source port per scanned port lets us map a reply back to its probe
    sport_of = {(base_sport + i) % 65536 or 1: p for i, p in enumerate(ports)}

    for sport, port in sport_of.items():
        pkt = (build_ip_header(source_ip, target_ip) +
               build_tcp_header(source_ip, target_ip, sport, port, flags))
        try:
            send_sock.sendto(pkt, (target_ip, 0))
        except OSError as e:
            results[port] = f"error: {e}"

    deadline = time.time() + 2
    pending = {p for p in ports if p not in results}
    while pending and time.time() < deadline:
        recv_sock.settimeout(max(0.05, deadline - time.time()))
        try:
            data, addr = recv_sock.recvfrom(65535)
        except socket.timeout:
            break
        except OSError:
            continue
        if addr[0] != target_ip or len(data) < 40:
            continue
        ihl = (data[0] & 0x0f) * 4
        if len(data) < ihl + 20:
            continue
        src_port, dst_port = struct.unpack('!HH', data[ihl:ihl + 4])
        tcp_flags = data[ihl + 13]
        if dst_port not in sport_of or src_port != sport_of[dst_port]:
            continue
        state = interpret(tcp_flags)
        if state is not None:
            results[sport_of[dst_port]] = state
            pending.discard(sport_of[dst_port])

    send_sock.close()
    recv_sock.close()

    for port in ports:
        results.setdefault(port, "open|filtered")
    _report(host, results, verbose, banner)


def syn_interpret(tcp_flags):
    if tcp_flags & 0x12 == 0x12:          # SYN+ACK
        return "open"
    if tcp_flags & 0x04:                  # RST
        return "closed"
    return None


def xmas_interpret(tcp_flags):
    if tcp_flags & 0x04:                  # RST -> closed
        return "closed"
    return None                           # no reply -> open|filtered


# --------------------------------------------------------------------------- #
# ICMP ping                                                                   #
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
        # Read until we see our own echo reply, skipping other traffic
        # (including the echo request the kernel loops back on localhost).
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
                ttl = data[8]               # TTL byte in the reply's IP header
                print(f"Reply from {addr[0]}: {len(data)} bytes, "
                      f"ttl={ttl}, RTT {rtt:.2f} ms")
                return
        print(f"No reply from {host} (timed out)")
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# Shared helpers                                                              #
# --------------------------------------------------------------------------- #

def _run_pool(scan_fn, host, ports, verbose, banner=False):
    results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(scan_fn, host, p): p for p in ports}
        for fut in as_completed(futures):
            results[futures[fut]] = fut.result()
    _report(host, results, verbose, banner)


def _report(host, results, verbose, banner=False):
    open_ports = [p for p in sorted(results) if results[p] == "open"]

    # Fingerprint open ports in parallel so TLS/cert/error probes don't
    # serialize the scan. Fingerprinting must never crash the scan itself.
    fps = {}
    if banner and open_ports:
        workers = min(MAX_WORKERS, max(4, len(open_ports)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(fingerprint_port, host, p): p
                       for p in open_ports}
            for fut in as_completed(futures):
                port = futures[fut]
                try:
                    fps[port] = fut.result()
                except Exception as e:                       # noqa: BLE001
                    fp = Fingerprint(port=port)
                    fp.error = f"fingerprint error: {e}"
                    fps[port] = fp

    shown = 0
    for port in sorted(results):
        state = results[port]
        if not (verbose or state == "open" or state.startswith("error")):
            continue
        print(f"Port {port:>5}: {state:<12} {service_name(port)}")
        shown += 1
        if banner and state == "open" and port in fps:
            for line in fingerprint_lines(fps[port], verbose):
                print(line)

    if not verbose and shown == 0:
        print("No open ports found (use 'verbose on' to see all states).")
    print(f"Done. {len(open_ports)} open / {len(results)} scanned.")


# --------------------------------------------------------------------------- #
# Self-update                                                                 #
# --------------------------------------------------------------------------- #

def fetch_latest(timeout=10):
    """Download the latest sxp.py. Returns its bytes, or None on failure."""
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
    """True if the remote copy differs from the file we are running."""
    try:
        with open(os.path.abspath(__file__), "rb") as f:
            local = f.read()
    except OSError:
        return False
    return hashlib.sha256(remote_bytes).digest() != hashlib.sha256(local).digest()


def self_update():
    """Replace the running sxp.py with the latest copy from the repo."""
    print(f"Checking {UPDATE_URL} ...")
    remote = fetch_latest()
    if remote is None:
        print("Update check failed (network error or file not reachable).")
        return
    if not update_available(remote):
        print(f"Already up to date (version {VERSION}).")
        return

    rv = remote_version(remote)
    print(f"Update available: {VERSION} -> {rv}")
    path = os.path.abspath(__file__)
    try:
        # Write to a temp file in the same dir, then atomically swap it in,
        # so a half-written download can never corrupt the installed script.
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
        with os.fdopen(fd, "wb") as f:
            f.write(remote)
        os.chmod(tmp, os.stat(path).st_mode)
        os.replace(tmp, path)
    except PermissionError:
        print(f"Cannot write {path}: permission denied. Re-run with sudo "
              f"(or: sudo sxp, then 'update').")
        return
    except OSError as e:
        print(f"Update failed: {e}")
        return
    print("Updated successfully. Restart sxp to run the new version.")


def startup_update_check():
    """Non-blocking: print a one-line notice if a newer version exists."""
    remote = fetch_latest(timeout=4)
    if remote is not None and update_available(remote):
        print(f"{GREEN}[*] Update available: {VERSION} -> "
              f"{remote_version(remote)}. Type 'update' to install.{RESET}")


# --------------------------------------------------------------------------- #
# WAF / firewall detection (L7)                                               #
# --------------------------------------------------------------------------- #

# HTTP status codes a WAF typically returns when it blocks a request.
WAF_BLOCK_CODES = {403, 406, 418, 419, 429, 494, 495, 496, 501}

# Benign-looking requests carrying classic attack patterns. A plain web
# server serves/404s them; a WAF intercepts with a block or challenge.
WAF_PROBES = [
    ("sqli", "/?id=1%27%20OR%20%271%27%3D%271"),            # 1' OR '1'='1
    ("xss", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),     # <script>alert(1)</script>
    ("lfi", "/?file=../../../../../../../etc/passwd"),
    ("rce", "/?cmd=;cat%20/etc/passwd"),
]
# A hostile User-Agent (Shellshock) sent with an otherwise normal request.
WAF_BAD_UA = "() { :;}; /bin/bash -c 'id'"

# (name, header-key, value-substring or None = header presence alone)
WAF_HEADER_SIGS = [
    ("Cloudflare", "cf-ray", None),
    ("Cloudflare", "cf-cache-status", None),
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
]
# (name, cookie-name-substring)
WAF_COOKIE_SIGS = [
    ("Imperva Incapsula", "incap_ses"),
    ("Imperva Incapsula", "visid_incap"),
    ("F5 BIG-IP", "TS01"),
    ("Citrix NetScaler", "citrix_ns_id"),
    ("Citrix NetScaler", "ns_af"),
    ("Barracuda", "barra_counter_session"),
    ("FortiWeb", "FORTIWAFSID"),
    ("Airlock", "AL_SESS"),
]
# (name, body-substring, lowercased)
WAF_BODY_SIGS = [
    ("Cloudflare", "attention required!"),
    ("Cloudflare", "cloudflare ray id"),
    ("ModSecurity", "mod_security"),
    ("Sucuri CloudProxy", "sucuri website firewall"),
    ("Imperva Incapsula", "incapsula incident id"),
    ("Imperva Incapsula", "powered by incapsula"),
    ("Wordfence", "generated by wordfence"),
    ("Citrix NetScaler", "violation of security policy"),
]
# Generic block-page phrases (no specific vendor).
WAF_BLOCK_BODY = (
    "has been blocked", "request blocked", "access denied",
    "web application firewall", "not acceptable", "forbidden",
    "blocked by", "security policy",
)


@dataclass
class WafResult:
    port: int
    transport: str = "TCP"
    baseline_status: str = ""
    blocked: List[Tuple[str, int]] = field(default_factory=list)
    waf_names: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    spoof_note: str = ""
    error: str = ""


def _send_http(host, port, use_tls, path, timeout, extra_headers=None):
    """Send one HTTP request and return the parsed response, or None."""
    try:
        sock = _open_socket(host, port, use_tls, timeout)
    except OSError:
        return None
    try:
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}",
            "User-Agent: Mozilla/5.0 (compatible; SXP-Scanner/1.2)",
            "Accept: */*",
        ]
        for k, v in (extra_headers or {}).items():
            lines.append(f"{k}: {v}")
        lines += ["Connection: close", "", ""]
        sock.sendall("\r\n".join(lines).encode("latin-1", "replace"))
        data = _recv_all(sock)
    except OSError:
        return None
    finally:
        sock.close()
    return _parse_http(data)


def _status_code(status_line):
    parts = status_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return 0


def _headers_blob(resp):
    """Lowercased 'key: value' text of every header (keeps duplicates)."""
    _, raw, _, _, _ = resp
    return "\n".join(f"{k}: {v}" for k, v in raw).lower()


def _is_block_response(resp, base_code):
    code = _status_code(resp[0])
    body = (resp[3] or "").lower()
    if code in WAF_BLOCK_CODES and code != base_code:
        return True
    return any(sig in body for sig in WAF_BLOCK_BODY)


def waf_detect(host, port, timeout=SOCKET_TIMEOUT):
    """Probe one web port for a WAF / reverse proxy at the HTTP layer."""
    result = WafResult(port=port)

    # Establish transport (and prove the port speaks HTTP) with a baseline.
    base = None
    use_tls = port in TLS_PORTS
    for try_tls in ([True] if use_tls else [False, True]):
        base = _send_http(host, port, try_tls, "/", timeout)
        if base is not None:
            use_tls = try_tls
            break
    if base is None:
        result.error = "no HTTP response (not a web port, or filtered)"
        return result

    result.transport = "TLSv?" if use_tls else "TCP"
    if use_tls:
        try:
            s = _open_socket(host, port, True, timeout)
            result.transport = s.version() or "TLS"
            s.close()
        except OSError:
            pass
    result.baseline_status = base[0]
    base_code = _status_code(base[0])

    responses = [base]
    for name, path in WAF_PROBES:
        r = _send_http(host, port, use_tls, path, timeout)
        if r is None:
            continue
        responses.append(r)
        if _is_block_response(r, base_code):
            result.blocked.append((name, _status_code(r[0])))
    # Hostile User-Agent on a normal path.
    r = _send_http(host, port, use_tls, "/", timeout, {"User-Agent": WAF_BAD_UA})
    if r is not None:
        responses.append(r)
        if _is_block_response(r, base_code):
            result.blocked.append(("bad-user-agent", _status_code(r[0])))

    # Fingerprint the WAF/CDN across every response we collected.
    names, evidence = set(), set()
    seen_cf_ray = False
    claims_cloudflare = False
    for resp in responses:
        blob = _headers_blob(resp)
        body = (resp[3] or "").lower()
        if re.search(r"(?m)^cf-ray:", blob):
            seen_cf_ray = True
        if re.search(r"(?m)^server:.*cloudflare", blob):
            claims_cloudflare = True
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
                evidence.add(f"block page body: '{sig}' -> {wname}")

    # A Cloudflare *claim* with no cf-ray anywhere is the spoof we saw before.
    if claims_cloudflare and not seen_cf_ray:
        result.spoof_note = ("Server claims Cloudflare but no 'cf-ray' in any "
                             "response -> header is spoofed, not a real CF edge")
        names.discard("Cloudflare")
        evidence = {e for e in evidence if "-> Cloudflare" not in e}

    result.waf_names = sorted(names)
    result.evidence = sorted(evidence)
    return result


def waf_lines(res):
    out = []
    if res.error:
        out.append(f"  WAF probe: {res.error}")
        return out
    out.append(f"  [{res.transport}] baseline {res.baseline_status}")
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
        shown = ", ".join(f"{n}->{c}" for n, c in res.blocked)
        out.append(f"  Blocked probes: {shown}")
    else:
        out.append("  Blocked probes: none "
                   "(SQLi/XSS/LFI/RCE/bad-UA all got through)")
    for e in res.evidence:
        out.append(f"    - {e}")
    return out


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #

class PortScanner(cmd.Cmd):
    intro = GREEN + """
================================================================================
SXP Scanner 1.2 - Multi-threaded scanner with SYN/XMAS/ICMP + service unmasking
================================================================================
By: Egwyl666
GitHub: https://github.com/egwyl666
================================================================================
Usage:
  - Type 'help' or '?' to list commands
  - 'syn <host> <port1> <port2> ...' or 'syn <host> <start>-<end>'
  - 'connect <host> <ports>'  (TCP connect, no root needed)
  - 'xmas <host> <ports>'
  - 'ping <host>'
  - 'verbose on|off'  to show closed/filtered ports too
  - 'banner on|off'   fingerprint open ports & unmask spoofed services
  - 'waf <host> <port>'  probe a web port for a WAF/CDN (L7)
  - 'update'  to download and install the latest version
  - 'exit' to quit
================================================================================
    """ + RESET
    prompt = BLUE + "(SXP) " + RESET

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.verbose = False
        self.banner = False

    def _ports(self, args):
        try:
            return parse_ports(args)
        except ValueError as e:
            print(f"Invalid port(s): {e}")
            return None

    def do_syn(self, arg):
        'Raw SYN (stealth) scan: syn <host> <ports>   (needs root)'
        args = arg.split()
        if len(args) < 2:
            print("Usage: syn <host> <port1> <port2> ... | <start>-<end>")
            return
        ports = self._ports(args[1:])
        if ports:
            raw_scan(args[0], ports, 0x02, syn_interpret, self.verbose, self.banner)

    def do_connect(self, arg):
        'TCP connect scan (no root needed): connect <host> <ports>'
        args = arg.split()
        if len(args) < 2:
            print("Usage: connect <host> <port1> <port2> ... | <start>-<end>")
            return
        ports = self._ports(args[1:])
        if ports:
            connect_scan(args[0], ports, self.verbose, self.banner)

    def do_xmas(self, arg):
        'Raw XMAS scan (FIN+PSH+URG): xmas <host> <ports>   (needs root)'
        args = arg.split()
        if len(args) < 2:
            print("Usage: xmas <host> <port1> <port2> ... | <start>-<end>")
            return
        ports = self._ports(args[1:])
        if ports:
            raw_scan(args[0], ports, 0x29, xmas_interpret, self.verbose, self.banner)

    def do_waf(self, arg):
        'Probe a web port for a WAF/CDN at the HTTP layer: waf <host> <port>'
        args = arg.split()
        if len(args) != 2 or not args[1].isdigit():
            print("Usage: waf <host> <port>")
            return
        port = int(args[1])
        if not 0 < port < 65536:
            print("Invalid port.")
            return
        print(f"WAF probe of {args[0]}:{port} ...")
        for line in waf_lines(waf_detect(args[0], port)):
            print(line)

    def do_ping(self, arg):
        'Ping a host with ICMP echo: ping <host>   (needs root)'
        if not arg.strip():
            print("Usage: ping <host>")
            return
        icmp_ping(arg.strip())

    def do_verbose(self, arg):
        'Show all port states, not just open: verbose on|off'
        val = arg.strip().lower()
        if val in ("on", "true", "1"):
            self.verbose = True
        elif val in ("off", "false", "0"):
            self.verbose = False
        print(f"verbose = {self.verbose}")

    def do_banner(self, arg):
        'Grab a service banner from each open port: banner on|off'
        val = arg.strip().lower()
        if val in ("on", "true", "1"):
            self.banner = True
        elif val in ("off", "false", "0"):
            self.banner = False
        print(f"banner = {self.banner}")

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
    # Check for a newer version in the background so it never delays startup.
    if os.environ.get("SXP_NO_UPDATE_CHECK") != "1":
        threading.Thread(target=startup_update_check, daemon=True).start()
    try:
        PortScanner().cmdloop()
    except KeyboardInterrupt:
        print("\nGG")
