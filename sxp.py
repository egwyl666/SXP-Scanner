import cmd
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"

MAX_WORKERS = 200

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


# Ports where a server stays silent until the client speaks first.
_HTTP_PORTS = {80, 81, 591, 8000, 8008, 8080, 8081, 8443, 8888}


def grab_banner(host, port):
    """Connect to an open TCP port and read a short service banner.

    Many services greet immediately (SSH, FTP, SMTP); HTTP-like ports need
    a nudge first. Returns a one-line string, or '' if nothing came back.
    """
    try:
        with socket.create_connection((host, port), timeout=2) as s:
            s.settimeout(2)
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            if not data:
                probe = (b"HEAD / HTTP/1.0\r\n\r\n"
                         if port in _HTTP_PORTS else b"\r\n")
                try:
                    s.sendall(probe)
                    data = s.recv(256)
                except OSError:
                    data = b""
    except OSError:
        return ""
    text = data.decode("latin-1", "replace").strip()
    line = text.splitlines()[0] if text else ""
    return line[:80]


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
    shown = 0
    for port in sorted(results):
        state = results[port]
        if not (verbose or state == "open" or state.startswith("error")):
            continue
        line = f"Port {port:>5}: {state:<12} {service_name(port)}"
        if banner and state == "open":
            b = grab_banner(host, port)
            if b:
                line += f"  | {b}"
        print(line)
        shown += 1
    open_count = sum(1 for s in results.values() if s == "open")
    if not verbose and shown == 0:
        print("No open ports found (use 'verbose on' to see all states).")
    print(f"Done. {open_count} open / {len(results)} scanned.")


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #

class PortScanner(cmd.Cmd):
    intro = GREEN + """
================================================================================
SXP Scanner 1.1 - Multi-threaded network scanner for SYN, XMAS, and ICMP scans
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
  - 'banner on|off'   to grab a service banner from open ports
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

    def do_exit(self, arg):
        'Exit the scanner'
        print("GG")
        return True

    do_EOF = do_exit


if __name__ == "__main__":
    print(LOGO)
    try:
        PortScanner().cmdloop()
    except KeyboardInterrupt:
        print("\nGG")
