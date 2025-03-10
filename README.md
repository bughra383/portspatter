# PortSpatter

PortSpatter is a stealthy port scanner that uses various scanning techniques to detect open ports on a target machine. It incorporates advanced stealth techniques such as packet fragmentation, decoy traffic, and randomized delays to avoid detection.

## Features

- **Multiple Scanning Techniques**: Supports SYN, FIN, Xmas, and ACK scans.
- **Stealth Mode**: Uses packet fragmentation, decoy traffic, and randomized delays to avoid detection.
- **Randomized Decoy IPs**: Generates random decoy IPs to make the scan traffic less predictable.
- **Multi-threading**: Utilizes multi-threading to speed up the scanning process.

## Dependencies

- Python 3.x
- Scapy
- Logging

You can install the required dependencies using the following command:

```sh
pip install scapy
```

## Usage

Run the script with the following command:

```sh
sudo python portspatter.py <target> <start_port> <end_port> <scan_type>
```

- `<target>`: The target IP address or hostname.
- `<start_port>`: The starting port number.
- `<end_port>`: The ending port number.
- `<scan_type>`: The type of scan to perform. Choose from `SYN`, `FIN`, `Xmas`, `ACK`.

### Example

```sh
sudo python portspatter.py 192.168.1.1 80 90 SYN
```

This command will perform a SYN scan on ports 80 to 90 on the target `192.168.1.1`.

## How It Works

1. **Randomized Decoy IPs**: The script generates random decoy IPs to make the scan traffic less predictable.
2. **Packet Fragmentation**: The script fragments packets to make detection harder.
3. **Randomized Delays**: The script introduces random delays between packet sends to avoid detection.
4. **Multiple Scanning Techniques**:
    - **SYN Scan**: Sends a TCP packet with the SYN flag set.
    - **FIN Scan**: Sends a TCP packet with the FIN flag set.
    - **Xmas Scan**: Sends a TCP packet with the FIN, PSH, and URG flags set.
    - **ACK Scan**: Sends a TCP packet with the ACK flag set.

## Code Overview

### Functions

- `map_service_names(open_ports, service)`: Maps open ports to their respective service names.
- `generate_random_ip()`: Generates a random IP address.
- `send_fragmented_packets(target, ports, rate_limit, decoy_ips)`: Sends fragmented packets to the target.
- `scan_port_syn(target, port, open_ports, lock, rate_limit, decoy_ips)`: Performs a SYN scan on the target port.
- `scan_port_fin(target, port, open_ports, lock, rate_limit, decoy_ips)`: Performs a FIN scan on the target port.
- `scan_port_xmas(target, port, open_ports, lock, rate_limit, decoy_ips)`: Performs a Xmas scan on the target port.
- `scan_port_ack(target, port, open_ports, lock, rate_limit, decoy_ips)`: Performs an ACK scan on the target port.
- `scan_ports(target, ports, open_ports, scan_type, max_threads, rate_limit, decoy_ips)`: Manages the scanning process using multi-threading.
- `main()`: The main function that parses command-line arguments and initiates the scanning process.

## Disclaimer

This script is intended for educational purposes only. Use it responsibly and only on networks you own or have permission to test. Unauthorized scanning of networks is illegal and unethical.

## License

This project is licensed under the MIT License.
