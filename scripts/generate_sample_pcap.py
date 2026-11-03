"""Sample PCAP Generator for UniGuard AI.

Creates a safe, controlled synthetic PCAP containing:
1. Benign Web & DNS requests
2. Fast Port Scan activity
3. SYN Flood DoS burst
All generated strictly on loopback / private IP ranges without external network activity.
"""

import os
import time
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap


def generate_synthetic_pcap(output_path: str = "data/samples/sample_unidirectional.pcap") -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    packets = []
    base_time = 1700000000.0

    print(f"[*] Generating controlled synthetic traffic for UniGuard AI validation...")

    # 1. Benign Traffic (Simulated Web Browsing & DNS queries)
    # DNS lookup
    dns_pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.100", dst="192.168.1.1")
        / UDP(sport=53535, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    dns_pkt.time = base_time + 0.1
    packets.append(dns_pkt)

    # HTTP GET Request (SYN, ACK, PSH+ACK payload)
    # Flow 1: 192.168.1.100 -> 93.184.216.34:80
    syn_1 = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="S", seq=1000)
    )
    syn_1.time = base_time + 0.2
    packets.append(syn_1)

    ack_1 = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001)
    )
    ack_1.time = base_time + 0.25
    packets.append(ack_1)

    data_1 = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=5001)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    )
    data_1.time = base_time + 0.26
    packets.append(data_1)

    # 2. Port Scan Attack (Host 10.0.0.99 scanning ports 21, 22, 23, 25, 80, 443, 8080)
    scanner_ip = "10.0.0.99"
    target_ip = "192.168.1.50"
    target_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

    scan_t = base_time + 2.0
    for idx, p in enumerate(target_ports):
        scan_pkt = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src=scanner_ip, dst=target_ip)
            / TCP(sport=50000 + idx, dport=p, flags="S", seq=50000)
        )
        scan_pkt.time = scan_t
        packets.append(scan_pkt)
        scan_t += 0.05

    # 3. SYN Flood Attack (High rate bursts to 192.168.1.50:80)
    attacker_ip = "172.16.0.45"
    flood_t = base_time + 5.0
    for i in range(150):
        flood_pkt = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src=attacker_ip, dst=target_ip)
            / TCP(sport=1024 + i, dport=80, flags="S", seq=100000 + i)
        )
        flood_pkt.time = flood_t + (i * 0.002) # Rapid 2ms inter-arrival time (500 pkts/sec)
        packets.append(flood_pkt)

    wrpcap(output_path, packets)
    print(f"[OK] Generated synthetic PCAP with {len(packets)} packets saved to '{output_path}'")


if __name__ == "__main__":
    generate_synthetic_pcap()
