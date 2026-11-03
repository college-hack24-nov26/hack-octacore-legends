"""Cross-Platform Packet Capture Abstraction Layer for UniGuard AI.

Provides a unified interface for capturing live unidirectional IP packets across:
- Windows (Npcap / WinPcap driver)
- Linux / Ubuntu (AF_PACKET zero-copy ring / libpcap)
- Offline PCAP Replay
"""

from abc import ABC, abstractmethod
from typing import Callable, Optional, Tuple, Dict, Any
from dataclasses import dataclass
import platform
import time


@dataclass(slots=True)
class NormalizedPacket:
    """Normalized wire representation of a captured IP packet."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    pkt_len: int
    timestamp: float
    tcp_flags: Optional[int] = None

    def to_tuple(self) -> Tuple[str, str, int, int, int, int, float, Optional[int]]:
        return (
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.proto,
            self.pkt_len,
            self.timestamp,
            self.tcp_flags,
        )


class BasePacketCapture(ABC):
    """Abstract Base Class for high-throughput packet capture engines."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "ip and not (ether multicast or ether broadcast)",
        packet_callback: Optional[Callable[[Tuple[str, str, int, int, int, int, float, Optional[int]]], None]] = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_callback = packet_callback
        self.is_running = False
        self.packets_captured_count = 0
        self.packets_dropped_count = 0
        self.bytes_captured_count = 0
        self.start_time = 0.0

    @abstractmethod
    def start(self) -> None:
        """Starts asynchronous packet capture on the target network interface."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stops packet capture and releases driver/socket handles."""
        pass

    def get_stats(self) -> Dict[str, Any]:
        """Returns capture performance and drop statistics."""
        elapsed = max(1e-4, time.time() - self.start_time) if self.is_running else 1.0
        return {
            "platform": platform.system(),
            "interface": self.interface or "default",
            "is_running": self.is_running,
            "packets_captured": self.packets_captured_count,
            "packets_dropped": self.packets_dropped_count,
            "bytes_captured": self.bytes_captured_count,
            "capture_rate_pps": round(self.packets_captured_count / elapsed, 1),
            "bandwidth_mbps": round((self.bytes_captured_count * 8) / (elapsed * 1_000_000), 2),
        }
