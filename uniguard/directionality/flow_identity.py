"""Canonical 5-Tuple Flow Identity and Directional Counters.

Maintains bidirectional flow continuity where A:p1 -> B:p2 and B:p2 -> A:p1
are recognized as the same conversation while maintaining separate O(1) streaming
metrics for forward (initiator) and reverse (responder) directions.
"""

from __future__ import annotations

import math
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CanonicalFlowKey:
    """Immutable canonical 5-tuple key identifying a 2-way conversation."""
    endpoint_low: Tuple[str, int]   # Lower sorted (IP, port)
    endpoint_high: Tuple[str, int]  # Higher sorted (IP, port)
    proto: int                      # Transport protocol (6=TCP, 17=UDP, 1=ICMP)

    @classmethod
    def from_endpoints(
        cls,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: int,
    ) -> CanonicalFlowKey:
        """Constructs a canonical key regardless of which endpoint is source or destination."""
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        if ep1 <= ep2:
            return cls(endpoint_low=ep1, endpoint_high=ep2, proto=proto)
        else:
            return cls(endpoint_low=ep2, endpoint_high=ep1, proto=proto)

    def to_string(self) -> str:
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_str = proto_map.get(self.proto, f"P{self.proto}")
        return f"{self.endpoint_low[0]}:{self.endpoint_low[1]} <-> {self.endpoint_high[0]}:{self.endpoint_high[1]} [{proto_str}]"


class DirectionalCounters:
    """Maintains lightweight O(1) streaming counters and Welford moments for a single direction."""

    def __init__(self, direction_name: str = "forward") -> None:
        self.direction_name = direction_name
        self.packet_count: int = 0
        self.byte_count: int = 0
        self.first_seen: float = 0.0
        self.last_seen: float = 0.0

        # Welford O(1) moments for packet lengths
        self.pkt_len_min: float = 0.0
        self.pkt_len_max: float = 0.0
        self.pkt_len_mean: float = 0.0
        self._pkt_len_m2: float = 0.0

        # Welford O(1) moments for inter-arrival times (IAT)
        self.iat_count: int = 0
        self.iat_min: float = 0.0
        self.iat_max: float = 0.0
        self.iat_mean: float = 0.0
        self._iat_m2: float = 0.0

        # Protocol metrics (TCP Flags)
        self.tcp_syn_cnt: int = 0
        self.tcp_psh_cnt: int = 0
        self.tcp_ack_cnt: int = 0
        self.tcp_fin_cnt: int = 0
        self.tcp_rst_cnt: int = 0
        self.tcp_urg_cnt: int = 0

        # Burst tracking
        self.current_burst_packets: int = 0
        self.max_burst_packets: int = 0

    @property
    def duration(self) -> float:
        if self.packet_count <= 1:
            return 0.0
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def packet_rate(self) -> float:
        dur = self.duration
        return (float(self.packet_count) / dur) if (dur > 1e-6 and self.packet_count > 1) else 0.0

    @property
    def byte_rate(self) -> float:
        dur = self.duration
        return (float(self.byte_count) / dur) if (dur > 1e-6 and self.packet_count > 1) else 0.0

    @property
    def pkt_len_std(self) -> float:
        if self.packet_count <= 1:
            return 0.0
        var = max(0.0, self._pkt_len_m2 / self.packet_count)
        return math.sqrt(var)

    @property
    def iat_std(self) -> float:
        if self.iat_count <= 1:
            return 0.0
        var = max(0.0, self._iat_m2 / self.iat_count)
        return math.sqrt(var)

    def add_packet(
        self,
        pkt_len: int,
        timestamp: float,
        tcp_flags: Optional[int] = None,
    ) -> None:
        """Incorporates an observed packet in this direction using O(1) streaming updates."""
        self.packet_count += 1
        self.byte_count += pkt_len

        if self.packet_count == 1:
            self.first_seen = timestamp
            self.last_seen = timestamp
            self.pkt_len_min = float(pkt_len)
            self.pkt_len_max = float(pkt_len)
            self.pkt_len_mean = float(pkt_len)
            self._pkt_len_m2 = 0.0
        else:
            # Welford packet length
            f_len = float(pkt_len)
            if f_len < self.pkt_len_min:
                self.pkt_len_min = f_len
            if f_len > self.pkt_len_max:
                self.pkt_len_max = f_len
            delta = f_len - self.pkt_len_mean
            self.pkt_len_mean += delta / self.packet_count
            delta2 = f_len - self.pkt_len_mean
            self._pkt_len_m2 += delta * delta2

            # Welford IAT
            iat = max(0.0, timestamp - self.last_seen)
            self.iat_count += 1
            if self.iat_count == 1:
                self.iat_min = iat
                self.iat_max = iat
                self.iat_mean = iat
                self._iat_m2 = 0.0
            else:
                if iat < self.iat_min:
                    self.iat_min = iat
                if iat > self.iat_max:
                    self.iat_max = iat
                delta_iat = iat - self.iat_mean
                self.iat_mean += delta_iat / self.iat_count
                delta_iat2 = iat - self.iat_mean
                self._iat_m2 += delta_iat * delta_iat2

            self.last_seen = timestamp

        # TCP Flag parsing
        if tcp_flags is not None:
            if tcp_flags & 0x01:
                self.tcp_fin_cnt += 1
            if tcp_flags & 0x02:
                self.tcp_syn_cnt += 1
            if tcp_flags & 0x04:
                self.tcp_rst_cnt += 1
            if tcp_flags & 0x08:
                self.tcp_psh_cnt += 1
            if tcp_flags & 0x10:
                self.tcp_ack_cnt += 1
            if tcp_flags & 0x20:
                self.tcp_urg_cnt += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "direction": self.direction_name,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": round(self.duration, 4),
            "packet_rate": round(self.packet_rate, 2),
            "byte_rate": round(self.byte_rate, 2),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "pkt_len_mean": round(self.pkt_len_mean, 2),
            "pkt_len_std": round(self.pkt_len_std, 2),
            "pkt_len_min": self.pkt_len_min,
            "pkt_len_max": self.pkt_len_max,
            "iat_mean": round(self.iat_mean, 6),
            "iat_std": round(self.iat_std, 6),
            "tcp_syn_cnt": self.tcp_syn_cnt,
            "tcp_ack_cnt": self.tcp_ack_cnt,
            "tcp_fin_cnt": self.tcp_fin_cnt,
            "tcp_rst_cnt": self.tcp_rst_cnt,
            "tcp_psh_cnt": self.tcp_psh_cnt,
        }
