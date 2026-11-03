"""Live Packet Sniffer Module for UniGuard AI.

Captures continuous live IP packets from a network interface (NIC) or loopback adapter
using Scapy AsyncSniffer or raw socket streaming, and emits normalized packet tuples
for real-time flow engine processing.
"""

from typing import Callable, Optional, Tuple
import time
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
from uniguard.capture.base import BasePacketCapture


class LiveSniffer(BasePacketCapture):
    """Captures live network packets from an interface and invokes a callback per packet."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "ip and not (ether multicast or ether broadcast)",
        packet_callback: Optional[Callable[[Tuple[str, str, int, int, int, int, float, Optional[int]]], None]] = None,
    ) -> None:
        super().__init__(interface=interface, bpf_filter=bpf_filter, packet_callback=packet_callback)
        self.sniffer: Optional[AsyncSniffer] = None

    def _process_packet(self, pkt) -> None:
        try:
            if not pkt.haslayer(IP):
                return

            ip_layer = pkt[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
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
                icmp_layer = pkt[ICMP]
                src_port = int(getattr(icmp_layer, "type", 0))
                dst_port = int(getattr(icmp_layer, "code", 0))

            normalized_pkt = (src_ip, dst_ip, src_port, dst_port, proto, pkt_len, timestamp, tcp_flags)

            self.packets_captured_count += 1
            self.bytes_captured_count += pkt_len

            if self.packet_callback:
                self.packet_callback(normalized_pkt)
        except Exception:
            self.packets_dropped_count += 1
            return

    def start(self) -> None:
        """Starts asynchronous live packet sniffing."""
        self.is_running = True
        self.start_time = time.time()
        sniff_kwargs = {
            "prn": self._process_packet,
            "filter": self.bpf_filter,
            "store": False,
        }
        if self.interface:
            sniff_kwargs["iface"] = self.interface

        try:
            self.sniffer = AsyncSniffer(**sniff_kwargs)
            self.sniffer.start()
        except Exception:
            # Fallback for Windows if ether broadcast filter keyword causes Npcap BPF parser issues
            if "ether" in self.bpf_filter:
                sniff_kwargs["filter"] = "ip"
                self.sniffer = AsyncSniffer(**sniff_kwargs)
                self.sniffer.start()
            else:
                raise

    def stop(self) -> None:
        """Stops live packet sniffing."""
        self.is_running = False
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
