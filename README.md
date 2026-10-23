# SXP Scanner

SXP Scanner is a lightweight, multi-threaded network scanner (SYN, XMAS, TCP connect, ICMP) with HTTPS-aware service fingerprinting and reverse-proxy/CDN unmasking. It is implemented in Python using only the standard library — no `scapy` or other dependencies.

## Features

- **Targets**: every command accepts a host, `host:port`, or a full URL (`https://site.com:8443/path?a=1`). Domains are resolved to an IP, but the original hostname is kept for TLS SNI and the `Host` header.
- **SYN Scan**: Raw half-open scan. SYN/ACK = open, RST = closed, **no reply = filtered** (a default-drop firewall). Ports are shuffled and silent ports get a second retransmit pass. Captures each reply's **per-port TTL** (`ttl=126 (win?, ~2 hops)`) for OS/hop estimation. Stealthy; requires root.
- **Connect Scan**: Full TCP `connect()` handshake. Needs no privileges, but is logged by the target.
- **XMAS Scan**: Sends FIN + PSH + URG. RST = closed; silence = open|filtered (per RFC 793).
- **ICMP Ping**: ICMP Echo with size, TTL and round-trip time.
- **Deep fingerprint** (`fp <target> [ports]`): run the L7 fingerprint, certificate check and unmasking on specific ports (default `80,443,8080,8443`) without a full port scan.
- **Host intelligence**: every scan ends with a summary (`N open, N closed, N filtered`, default-drop firewall note) and infrastructure insights — control-panel ports (cPanel/WHM/Webmail, Plesk, Proxmox, Portainer, Grafana, MikroTik, …), a Cloudflare-port-mimicry flag, a **split-stack / DNAT** warning when open ports answer with different TTL profiles (different devices / backends behind one IP), and **tcpwrapped** ports that accept a connection but speak nothing (firewall / dead backend).
- **Export** (`export <file.json>`): save the last scan / fingerprint / WAF result as structured JSON (ports, evidence, certificates, insights).
- **Service detection & unmasking** (`banner on`, or `fp`): a multi-probe fingerprint that sees through services masquerading as something else (e.g. a reverse proxy faking `Server: cloudflare`):
  - Auto-detects TLS and falls back to a TLS handshake on HTTPS ports; follows up to 2 same-host redirects to reach the real endpoint.
  - Sends profiled probes: a standard `GET`, an `OPTIONS` (reads `Allow`), a random path to trigger the native 404 page (often reveals the real engine), and a malformed HTTP/1.0 request for the native error page.
  - Parses full HTTP responses (status, `<title>`, headers in original case), decodes `Transfer-Encoding: chunked`, and reads the TLS certificate even with verification off (subject/issuer/SAN/validity/self-signed) plus TLS version, cipher and the negotiated **ALPN** (`h2` vs `http/1.1`).
  - Runs an **unmasking engine** with weighted evidence (fake Cloudflare: no `cf-ray`, non-public-CA/self-signed cert, >398-day cert, CDN over plaintext; engine signatures in the 404/error body) and prints a verdict such as `[!] SPOOFED: claims 'cloudflare' -> likely 'nginx'`.
  - Still grabs plain banners from greeting services (SSH/FTP/SMTP).
- **WAF / CDN detection** (`waf <target> [port]`): an L7 probe that sends a benign baseline (following redirects) plus attack-pattern requests (SQLi, XSS, LFI, RCE, hostile User-Agent) and does a differential analysis — status change, block-page body, body-size collapse, new WAF cookies, redirect to a block page — with per-request RTT. Detects JS/CAPTCHA challenges (`cf-mitigated`, "Just a moment", DDoS-Guard, Qrator, StormWall, …), a **baseline-lockdown** mode (origin denies every request with the same code — strict ACL / mTLS / WAF block-all — where payload diffing is inconclusive and only passive signals apply), fingerprints the vendor (Cloudflare, Imperva, Akamai, Sucuri, AWS WAF, F5, Barracuda, FortiWeb, NAXSI, ModSecurity, …), and flags a spoofed `Server: cloudflare` with no `cf-ray`.
- **Self-update**: SXP checks for a newer version on startup and can update itself in place with the `update` command.
- Multi-threaded with a bounded thread pool (scans and fingerprinting), so large port ranges won't exhaust file descriptors.
- `verbose` shows closed/filtered ports and, with `banner on`, the full evidence list, header dump, and certificate detail behind each verdict.

## Requirements

- Python 3.6+
- Root / Administrator privileges for the raw-socket scans (`syn`, `xmas`, `ping`). The `connect` scan runs without privileges.
- Linux. On Windows, raw TCP sends are blocked by the OS since XP SP2, so `syn`/`xmas` will not work there without a packet driver such as Npcap.

## Installation

**One command** (installs `sxp` to `/usr/local/bin`):

```bash
curl -fsSL https://raw.githubusercontent.com/egwyl666/SXP-Scanner/work/fixit1.0/install.sh | sudo bash
```

**Or from a clone:**

```bash
git clone -b work/fixit1.0 https://github.com/egwyl666/SXP-Scanner.git
cd SXP-Scanner
sudo ./install.sh
```

After installing, launch it from anywhere (the launcher re-execs under `sudo` automatically so raw sockets work):

```bash
sxp
```

To run without installing:

```bash
sudo python3 sxp.py
```

## Commands

Targets accept a host, `host:port`, or a URL. Ports can be a list, a range,
a comma list, or a mix:

```
syn     scanme.nmap.org 22 80 443
syn     scanme.nmap.org 20-25
connect scanme.nmap.org 1-1024
xmas    scanme.nmap.org 22 80 443
fp      https://site.com:8443/login       # deep fingerprint, one endpoint
fp      site.com                          # defaults to 80,443,8080,8443
waf     site.com                          # auto-tries 443 then 80
waf     site.com 8443
ping    scanme.nmap.org
verbose on        # also show closed/filtered ports and full evidence
banner  on        # fingerprint open ports during a scan
export  out.json  # save the last result as JSON
exit
```

| Command | What it does | Needs root |
|---------|--------------|:----------:|
| `syn <target> <ports>`     | Raw half-open SYN scan      | yes |
| `connect <target> <ports>` | TCP connect scan            | no  |
| `xmas <target> <ports>`    | FIN+PSH+URG scan            | yes |
| `fp <target> [ports]`      | Deep L7 fingerprint + unmasking | no |
| `waf <target> [port]`      | Probe a web port for a WAF/CDN (L7) | no |
| `ping <host>`              | ICMP echo / TTL / RTT       | yes |
| `verbose on\|off`          | Show all port states & full evidence | — |
| `banner on\|off`           | Fingerprint open ports during a scan | — |
| `export <file.json>`       | Save the last result as JSON | no |
| `update`                   | Install the latest version   | yes* |

\* `update` needs write access to the installed script, so run it under `sudo` (the `sxp` launcher already re-execs as root). It downloads `sxp.py` from the repo and swaps it in atomically; restart SXP afterwards. A newer version is also announced automatically at startup. Set `SXP_NO_UPDATE_CHECK=1` to silence that check.

## Notes

Use responsibly and only scan hosts you have permission to scan.

## Acknowledgments

Inspired by the Nmap network scanner and Ares.

## License

MIT. See [LICENSE](LICENSE).
