# SXP Scanner

SXP Scanner is a lightweight, multi-threaded network scanner that supports SYN, XMAS, TCP connect, and ICMP Ping scans. It is implemented in Python using only the standard library — no `scapy` or other dependencies.

## Features

- **SYN Scan**: Raw half-open scan. A SYN/ACK reply means the port is open, RST means closed. Stealthier than a full connect and requires root.
- **Connect Scan**: Full TCP `connect()` handshake. Needs no privileges, but is logged by the target.
- **XMAS Scan**: Sends FIN + PSH + URG. A RST reply means closed; silence means open or filtered (per RFC 793).
- **ICMP Ping**: Sends an ICMP Echo request and reports round-trip time.
- Multi-threaded with a bounded thread pool, so large port ranges won't exhaust file descriptors.
- `verbose` toggle to show closed/filtered ports in addition to open ones.

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
exit
```

| Command | What it does | Needs root |
|---------|--------------|:----------:|
| `syn <host> <ports>`     | Raw half-open SYN scan      | yes |
| `connect <host> <ports>` | TCP connect scan            | no  |
| `xmas <host> <ports>`    | FIN+PSH+URG scan            | yes |
| `ping <host>`            | ICMP echo / RTT             | yes |
| `verbose on\|off`        | Show all port states        | —   |

## Notes

Use responsibly and only scan hosts you have permission to scan.

## Acknowledgments

Inspired by the Nmap network scanner and Ares.

## License

MIT. See [LICENSE](LICENSE).
