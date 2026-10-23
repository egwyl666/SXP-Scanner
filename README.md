# SXP Scanner

SXP Scanner is a lightweight, multi-threaded network scanner (SYN, XMAS, TCP connect, ICMP) with HTTPS-aware service fingerprinting and reverse-proxy/CDN unmasking. It is implemented in Python using only the standard library — no `scapy` or other dependencies.

## Features

- **SYN Scan**: Raw half-open scan. A SYN/ACK reply means the port is open, RST means closed. Stealthier than a full connect and requires root.
- **Connect Scan**: Full TCP `connect()` handshake. Needs no privileges, but is logged by the target.
- **XMAS Scan**: Sends FIN + PSH + URG. A RST reply means closed; silence means open or filtered (per RFC 793).
- **ICMP Ping**: Sends an ICMP Echo request and reports round-trip time.
- **Service detection & unmasking** (`banner on`): a smart probe fingerprints each open port and sees through services that masquerade as something else (e.g. a reverse proxy faking `Server: cloudflare`):
  - Auto-detects TLS and falls back to a TLS handshake on HTTPS ports (standard 443/8443/9443/4443 and any port that answers plaintext with a TLS alert or the nginx "plain HTTP request was sent to HTTPS port" signature).
  - Parses the full HTTP response: status, `<title>`, and all headers (original case preserved).
  - Extracts the TLS certificate even with verification off (subject/issuer/SAN/validity, self-signed flag) plus the negotiated TLS version and cipher.
  - Runs an **unmasking engine**: flags a fake Cloudflare (no `cf-ray` header, non-public-CA or self-signed cert), reads the server's native error page (`<center>nginx</center>`, `Apache/`, `LiteSpeed`, …), and prints a verdict such as `[!] SPOOFED: claims 'cloudflare' -> likely 'nginx'`.
  - Still grabs plain banners from greeting services (SSH/FTP/SMTP).
- **WAF / CDN detection** (`waf <host> <port>`): an L7 probe that sends a benign baseline plus attack-pattern requests (SQLi, XSS, LFI, RCE, hostile User-Agent) and compares the responses. Reports whether a WAF blocks the attacks, fingerprints the vendor from headers/cookies/block pages (Cloudflare, Imperva, Akamai, Sucuri, AWS WAF, F5, Barracuda, FortiWeb, ModSecurity, …), and flags a spoofed `Server: cloudflare` with no `cf-ray`.
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

Ports can be given as a list, a range, or a mix:

```
syn     scanme.nmap.org 22 80 443
syn     scanme.nmap.org 20-25
connect scanme.nmap.org 1-1024
xmas    scanme.nmap.org 22 80 443
ping    scanme.nmap.org
verbose on        # also show closed/filtered ports
banner  on        # grab service banners from open ports
exit
```

| Command | What it does | Needs root |
|---------|--------------|:----------:|
| `syn <host> <ports>`     | Raw half-open SYN scan      | yes |
| `connect <host> <ports>` | TCP connect scan            | no  |
| `xmas <host> <ports>`    | FIN+PSH+URG scan            | yes |
| `ping <host>`            | ICMP echo / RTT             | yes |
| `verbose on\|off`        | Show all port states        | —   |
| `banner on\|off`         | Fingerprint & unmask open ports | —  |
| `waf <host> <port>`      | Probe a web port for a WAF/CDN (L7) | no |
| `update`                 | Install the latest version   | yes* |

\* `update` needs write access to the installed script, so run it under `sudo` (the `sxp` launcher already re-execs as root). It downloads `sxp.py` from the repo and swaps it in atomically; restart SXP afterwards. A newer version is also announced automatically at startup. Set `SXP_NO_UPDATE_CHECK=1` to silence that check.

## Notes

Use responsibly and only scan hosts you have permission to scan.

## Acknowledgments

Inspired by the Nmap network scanner and Ares.

## License

MIT. See [LICENSE](LICENSE).
