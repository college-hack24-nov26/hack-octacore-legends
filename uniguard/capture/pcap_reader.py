"""Offline PCAP Ingestion and Unidirectional Packet Processing.

Reads standard PCAP / PCAPNG files using Scapy and feeds them into the
FlowTracker engine to construct unidirectional flows.
"""

from typing import Generator, Tuple, Optional
import os
from scapy.all import PcapReader, IP, TCP, UDP, ICMP


class PcapIngestor:
    """Streams packets from a PCAP file and normalizes them for flow processing."""

    def __init__(self, pcap_path: str) -> None:
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        self.pcap_path = pcap_path

    def stream_packets(self) -> Generator[Tuple[str, str, int, int, int, int, float, Optional[int]], None, None]:
        """Yields normalized packet tuples:
        (src_ip, dst_ip, src_port, dst_port, proto, pkt_len, timestamp, tcp_flags)
        """
        with PcapReader(self.pcap_path) as reader:
            for pkt in reader:
                if not pkt.haslayer(IP):
                    continue

                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto = int(ip_layer.proto)
                pkt_len = len(pkt)
                timestamp = float(pkt.time)

                src_port = 0
                dst_port = 0
                tcp_flags = None

                if pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    src_port = int(tcp_layer.sport)
                    dst_port = int(tcp_layer.dport)
                    tcp_flags = int(tcp_layer.flags)
                elif pkt.haslayer(UDP):
                    udp_layer = pkt[UDP]
                    src_port = int(udp_layer.sport)
                    dst_port = int(udp_layer.dport)
                elif pkt.haslayer(ICMP):
                    # For ICMP, encode type and code into port fields for flow distinctness
                    icmp_layer = pkt[ICMP]
                    src_port = int(getattr(icmp_layer, "type", 0))
                    dst_port = int(getattr(icmp_layer, "code", 0))

                yield (src_ip, dst_ip, src_port, dst_port, proto, pkt_len, timestamp, tcp_flags)
