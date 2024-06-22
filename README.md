# SXP Scanner

SXP Scanner is a lightweight, multi-threaded network scanner that supports SYN, XMAS, and ICMP Ping scans. This scanner is implemented in Python using built-in libraries and does not require additional dependencies such as `scapy`.

## Features

- **SYN Scan**: Checks if ports are open, closed, or filtered.
- **XMAS Scan**: Uses FIN, PSH, and URG flags to determine port state.
- **ICMP Ping**: Sends ICMP Echo requests to check if a host is reachable.

## Libraries Used

This project uses the following Python standard libraries:

- `socket`: For creating network connections and handling raw packets.
- `struct`: For working with C-style data structures.
- `binascii`: For binary to ASCII conversions.
- `threading`: For multi-threading support.
- `cmd`: For creating command-line interfaces.
- `time`: For handling time-related tasks.

## Requirements

- Python 3.x
- Administrative privileges (required for sending raw packets)
- Linux or Windows operating system

## Installation

 Clone the repository:
    ```bash
    git clone https://github.com/yourusername/sxp-scanner.git
    cd sxp-scanner
    ```

## Usage

Run the scanner with administrative privileges:

```bash
    sudo python3 sxp.py
```

## Commands

***Scan specific ports or a range of ports on a target host using the SYN scan method.***

**Single or Multiple Ports in SYN:**

```bash
syn <host> <port1> <port2> ...
```

```bash
syn scanme.nmap.org 22 80 443
```

```bash
syn <host> <start_port>-<end_port>
```

```bash
syn scanme.nmap.org 20-25
```

**Single or Multiple Ports in XMAS:**

```bash
xmas <host> <port1> <port2> ...
```


```bash
xmas scanme.nmap.org 22 80 443
```

```bash
xmas <host> <start_port>-<end_port>
```

```bash
xmas scanme.nmap.org 20-25
```
**ICMP Ping**

  Ping a target host using ICMP Echo requests.


```bash
ping <host>
```
```bash
ping scanme.nmap.org
```

## Notes
Ensure you have administrative privileges to run this scanner.
Use responsibly and only scan hosts you have permission to scan.

**Known Issue:** 
- There is a redirection error on Windows systems that affects the accuracy of the scan results. This issue is being investigated.
## Future Plans:
`--verbose` option will be added in future versions to provide more detailed output.

## Acknowledgments
This project is inspired by the Nmap network scanner and Ares.

## License
This project is licensed under the MIT License. See the [LICENSE](https://github.com/egwyl666/SXP-Scanner/blob/main/LICENSE) file for details.
