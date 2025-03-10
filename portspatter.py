import sys
import time
import random
from scapy.all import *
import threading
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def map_service_names(open_ports, service):
    services = {
        20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 119: "NNTP", 143: "IMAP", 161: "SNMP",
        443: "HTTPS", 445: "Microsoft-DS", 465: "SMTPS", 587: "SMTP (Submission)",
        631: "IPP", 993: "IMAPS", 995: "POP3S", 1433: "Microsoft SQL Server",
        1434: "Microsoft SQL Monitor", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
        8080: "HTTP Proxy", 8443: "HTTPS Proxy", 8888: "HTTP Proxy (alternative)"
    }
    for port in open_ports:
        if port in services:
            service[services[port]] = port

# random ips
def generate_random_ip():
    return "203." + str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + "." + str(random.randint(0, 255))

def send_fragmented_packets(target, ports, rate_limit, decoy_ips):
    for _ in range(len(ports)):
        try:
            # source ip addresses
            src_ip = random.choice(decoy_ips) if random.random() < 0.5 else generate_random_ip()
            ip = IP(src=src_ip, dst=target, ttl=random.randint(64, 128))
            tcp = TCP(dport=random.choice(ports), sport=random.randint(1024, 65535), flags=random.choice(["S", "A", "F", "P"]), seq=random.randint(1000, 9999))

            # random raw load
            raw_data = Raw(load="".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(4, 16))))
            
            # packet fragmentation 
            frags = fragment(ip / tcp / raw_data, fragsize=random.randint(8, 24))

            for frag in frags:
                send(frag, verbose=False)
                logging.info(f"Packet fragment sent from {src_ip}: {frag.summary()}")

            # random delay
            time.sleep(random.uniform(rate_limit[0], rate_limit[1]))
        except Exception as e:
            logging.error(f"Error sending fragmented packets: {e}")


# syn flag
def scan_port_syn(target, port, open_ports, lock, rate_limit, decoy_ips):
    try:
        src_ip = random.choice(decoy_ips) if random.random() < 0.5 else generate_random_ip()
        ip = IP(src=src_ip, dst=target, ttl=random.randint(64, 128))
        tcp = TCP(dport=port, flags="S", sport=random.randint(1024, 65535))
        packet = ip / tcp

        response = sr1(packet, timeout=2, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            logging.info(f"Port {port} is open (SYN scan).")
            with lock:
                open_ports.append(port)
        elif response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            logging.info(f"Port {port} is closed (SYN scan).")
        else:
            logging.info(f"Port {port} is filtered or no response (SYN scan).")
        time.sleep(random.uniform(rate_limit[0], rate_limit[1]))
    except Exception as e:
        logging.error(f"Error scanning port {port} (SYN scan): {e}")

# fin flag
def scan_port_fin(target, port, open_ports, lock, rate_limit, decoy_ips):
    try:
        src_ip = random.choice(decoy_ips) if random.random() < 0.5 else generate_random_ip()
        ip = IP(src=src_ip, dst=target, ttl=random.randint(64, 128))
        tcp = TCP(dport=port, flags="F", sport=random.randint(1024, 65535))
        packet = ip / tcp

        response = sr1(packet, timeout=2, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # rst flag
            logging.info(f"Port {port} is closed (FIN scan).")
        else:
            logging.info(f"Port {port} is open or filtered (FIN scan).")
            with lock:
                open_ports.append(port)
        time.sleep(random.uniform(rate_limit[0], rate_limit[1]))
    except Exception as e:
        logging.error(f"Error scanning port {port} (FIN scan): {e}")

# xmas flag
def scan_port_xmas(target, port, open_ports, lock, rate_limit, decoy_ips):
    try:
        src_ip = random.choice(decoy_ips) if random.random() < 0.5 else generate_random_ip()
        ip = IP(src=src_ip, dst=target, ttl=random.randint(64, 128))
        tcp = TCP(dport=port, flags="FPU", sport=random.randint(1024, 65535))
        packet = ip / tcp

        response = sr1(packet, timeout=2, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # rst flag
            logging.info(f"Port {port} is closed (Xmas scan).")
        else:
            logging.info(f"Port {port} is open or filtered (Xmas scan).")
            with lock:
                open_ports.append(port)
        time.sleep(random.uniform(rate_limit[0], rate_limit[1]))
    except Exception as e:
        logging.error(f"Error scanning port {port} (Xmas scan): {e}")

# ack flag
def scan_port_ack(target, port, open_ports, lock, rate_limit, decoy_ips):
    try:
        src_ip = random.choice(decoy_ips) if random.random() < 0.5 else generate_random_ip()
        ip = IP(src=src_ip, dst=target, ttl=random.randint(64, 128))
        tcp = TCP(dport=port, flags="A", sport=random.randint(1024, 65535))
        packet = ip / tcp

        response = sr1(packet, timeout=2, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x04: # rst flag
            logging.info(f"Port {port} is unfiltered (ACK scan).")
        else:
            logging.info(f"Port {port} is filtered (ACK scan).")
        time.sleep(random.uniform(rate_limit[0], rate_limit[1]))
    except Exception as e:
        logging.error(f"Error scanning port {port} (ACK scan): {e}")

# port scanning & threading
def scan_ports(target, ports, open_ports, scan_type, max_threads=5, rate_limit=(5, 15), decoy_ips=[]):
    lock = threading.Lock()
    threads = []
    for port in ports:
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads.clear()

        t = threading.Thread(target=scan_type, args=(target, port, open_ports, lock, rate_limit, decoy_ips))
        threads.append(t)
        t.start()

        time.sleep(random.uniform(rate_limit[0], rate_limit[1]))

    for t in threads:
        t.join()

def main():
    if len(sys.argv) != 5:
        print("Usage: sudo python portspatter.py <target> <start_port> <end_port> <scan_type>")
        print("Scan types: SYN, FIN, Xmas, ACK")
        sys.exit(1)

    target = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    scan_type_str = sys.argv[4].upper()

    scan_type = {
        "SYN": scan_port_syn,
        "FIN": scan_port_fin,
        "XMAS": scan_port_xmas,
        "ACK": scan_port_ack
    }.get(scan_type_str)

    if not scan_type:
        print("Invalid scan type. Choose from SYN, FIN, Xmas, ACK.")
        sys.exit(1)

    open_ports = []       
    service = {}

    ports = list(range(start_port, end_port + 1))
    random.shuffle(ports)

    rate_limit = (5, 30) # rate limit in seconds (min,max)
    decoy_ips = [generate_random_ip() for _ in range(10)]  # 10 random decoy ips

    send_fragmented_packets(target, ports, rate_limit, decoy_ips)
    scan_ports(target, ports, open_ports, scan_type, rate_limit=rate_limit, decoy_ips=decoy_ips)
    map_service_names(open_ports, service)

    print("\nRunning services:")
    for service_name, port in service.items():
        print(f"{service_name}: {port}")

if __name__ == "__main__":
    main()