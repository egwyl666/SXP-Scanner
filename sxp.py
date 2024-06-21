import cmd
import socket
import threading
import struct
import time
import binascii

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"

colored_logo = (
    RED + """
███████╗██╗  ██╗██████╗ 
██╔════╝╚██╗██╔╝██╔══██╗
███████╗ ╚███╔╝ ██████╔╝
╚════██║ ██╔██╗ ██╔═══╝ 
███████║██╔╝ ██╗██║     
╚══════╝╚═╝  ╚═╝╚═╝     """ + RESET
   
)

print(colored_logo)

class PortScanner(cmd.Cmd):
    intro = GREEN + """
================================================================================
SXP Scanner 1.0 - Multi-threaded network scanner for SYN, XMAS, and ICMP scans
================================================================================
By: Egwyl666
GitHub: https://github.com/egwyl666
================================================================================
Usage:
  - Type 'help' or '?' to list commands
  - Type 'syn <host> <port1> <port2> ...' or 'syn <host> <start_port>-<end_port>'
  - Type 'xmas <host> <port>' or 'xmas <host> <start_port>-<end_port>'
  - Type 'ping <host>' to send ICMP Ping
  - Type 'exit' to quit the scanner
================================================================================
    """
    prompt = BLUE + "(SXP) " + RESET
    
    def do_syn(self, arg):
        'Scan ports on a target host: syn <host> <port1> <port2> ... or syn <host> <start_port>-<end_port>'
        args = arg.split()
        if len(args) < 2:
            print("Usage: syn <host> <port1> <port2> ... or syn <host> <start_port>-<end_port>")
            return
        host = args[0]
        ports = []
        for port_arg in args[1:]:
            if '-' in port_arg:
                start_port, end_port = map(int, port_arg.split('-'))
                ports.extend(range(start_port, end_port + 1))
            else:
                ports.append(int(port_arg))
        multi_scan(host, ports)

    
    def do_ping(self, arg):
        'Ping a target host: ping <host>'
        if not arg:
            print("Usage: ping <host>")
            return
        icmp_ping(arg.strip())

    def do_xmas(self, arg):
        'Scan a target host: scan <host> <port> or scan <host> <start_port>-<end_port>'
        args = arg.split()
        if len(args) != 2:
            print("Usage: scan <host> <port> or scan <host> <start_port>-<end_port>")
            return
        target_host = args[0]
        port_arg = args[1]
        
        if '-' in port_arg:
            start_port, end_port = map(int, port_arg.split('-'))
            scan_range(target_host, start_port, end_port)
        else:
            target_port = int(port_arg)
            xmas_scan(target_host, target_port)

    def do_exit(self, arg):
        'Exit the SXP'
        print("GG")
        return True
    

def syn(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, port))
            print(f"Port {port} is open")
        except socket.timeout:
            print(f"Port {port} is filtered (timeout).")
        except socket.error as e:
            if e.errno == socket.errno.ECONNREFUSED:
                print(f"Port {port} is closed (connection refused).")
            else:
                print(f"Port {port} is closed with error: {e}")

def multi_scan(host, ports):
    ths = []
    for port in ports:
        th = threading.Thread(target=syn, args=(host, port))
        ths.append(thread)
        th.start()

    for th in ths:
        th.join()

def checksum_icmp(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_icmp_packet(packet_id):
    header = struct.pack('!BBHHH', 8, 0, 0, packet_id, 1)
    data = b'hello'
    my_checksum_icmp = checksum_icmp(header + data)
    header = struct.pack('!BBHHH', 8, 0, my_checksum_icmp, packet_id, 1)
    return header + data

def icmp_ping(host):
    try:
        packet_id = int((id(time.time()) * time.time()) % 65535)
        icmp_packet = create_icmp_packet(packet_id)

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(1)

        start_time = time.time()
        sock.sendto(icmp_packet, (host, 1))
        data, addr = sock.recvfrom(1024)
        end_time = time.time()

        icmp_header = data[20:28]
        icmp_type, icmp_code, _, reply_packet_id, _ = struct.unpack('!BBHHH', icmp_header)
        
        rtt = (end_time - start_time) * 1000  
        packet_size = len(data)

        if icmp_type == 0 and reply_packet_id == packet_id:
            print(f"Ping to {host} succes!")
            print(f"Time delay(RTT): {rtt:.2f} ms")
            print(f"Weigth pocket: {packet_size} байт")
            if addr[0] != host:
                print(f"Answer from: {addr[0]}")
        else:
            print(f"Ping to {host} was failed, type ICMP: {icmp_type}, code: {icmp_code}")

    except socket.error as e:
        print(f"Ping error to {host}: {e}")

def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_ip_header(source_ip, dest_ip):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 20 + 20  # IP Header + TCP Header
    ip_id = 0x6ea9  # Example ID
    ip_frag_off = 0
    ip_ttl = 46
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    ip_check = checksum(ip_header)
    
    # Repack with the correct checksum
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    
    return ip_header

def create_tcp_header(source_ip, dest_ip, dest_port, flags):
    tcp_source = 36747
    tcp_dest = dest_port
    tcp_seq = 1
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_window = socket.htons(1024)
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0

    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, flags, tcp_window, tcp_check, tcp_urg_ptr)

    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    pseudo_header = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    tcp_check = checksum(pseudo_header + tcp_header)

    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, flags, tcp_window, tcp_check, tcp_urg_ptr)

    return tcp_header

def xmas_scan(target_host, target_port):
    try:
        source_ip = "127.0.0.1" 
        target_ip = socket.gethostbyname(target_host)  
        print(f"Source IP: {source_ip}")
        print(f"Target IP: {target_ip}")
        
        ip_header = create_ip_header(source_ip, target_ip)
        tcp_header = create_tcp_header(source_ip, target_ip, target_port, 0x29)  # FIN, PSH, URG flags
        packet = ip_header + tcp_header


        # print(f"IP Header: {binascii.hexlify(ip_header)}")            --verbose
        # print(f"TCP Header: {binascii.hexlify(tcp_header)}")          --verbose
        # print(f"Packet: {binascii.hexlify(packet)}")                  --verbose

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.settimeout(1)
        sock.sendto(packet, (target_ip, 0))
        print(f"XMAS-packet was sent to {target_host}:{target_port}")

        try:
            data = sock.recvfrom(1024)
            ip_header = data[:20]
            tcp_header = data[20:40]
            tcp_flags = struct.unpack('!HHLLBBHHH', tcp_header)[5]

            if tcp_flags & 0x04:  # RST flag is set
                print(f"Port {target_port} in {target_host} closed")
            else:
                print(f"Port {target_port} in {target_host} is filtered")
        except socket.timeout:
            print(f"Port {target_port} in {target_host} is open | filtered (no answer).")

    except Exception as e:
        print(f"Error XMAS request: {target_host}:{target_port} - {e}")

def th_xmas_scan(target_host, port):
    xmas_scan(target_host, port)

def scan_range(target_host, start_port, end_port):
    ths = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=th_xmas_scan, args=(target_host, port))
        ths.append(t)
        t.start()

    for t in ths:
        t.join()

# def scan_range(target_host, start_port, end_port):
#     for port in range(start_port, end_port + 1):
#         xmas_scan(target_host, port)

if __name__ == "__main__":
    PortScanner().cmdloop()
