"""Traffic Asymmetry and Packet Dependency Feature Engine.

Computes mathematically validated directionality features (Packet Asymmetry Ap,
Byte Asymmetry Ab, Safe Direction Ratio R), inter-direction temporal dependency,
alternating burst transitions, and TCP handshake/ACK response indicators.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Any
import numpy as np

from uniguard.directionality.flow_identity import DirectionalCounters


DIRECTIONALITY_FEATURE_NAMES: List[str] = [
    "forward_packet_count",
    "reverse_packet_count",
    "forward_byte_count",
    "reverse_byte_count",
    "packet_asymmetry",
    "byte_asymmetry",
    "directional_ratio",
    "forward_packet_rate",
    "reverse_packet_rate",
    "forward_byte_rate",
    "reverse_byte_rate",
    "duration",
    "reverse_presence",
    "burst_transition_rate",
    "temporal_dependency_lag",
    "tcp_handshake_presence",
    "reverse_ack_ratio",
]


class AsymmetryEngine:
    """Calculates directional and dependency features from forward and reverse counters."""

    EPSILON: float = 1e-6

    @classmethod
    def calculate_features(
        cls,
        fwd: DirectionalCounters,
        rev: DirectionalCounters,
        overall_duration: float,
        burst_transitions: int = 0,
        inter_direction_lags: Optional[List[float]] = None,
        is_client_initiated: bool = True,
    ) -> Dict[str, float]:
        """Extracts complete directionality and dependency metrics.

        Args:
            fwd: Forward (initiator) directional counters.
            rev: Reverse (responder) directional counters.
            overall_duration: Total active conversation duration.
            burst_transitions: Number of times packet transmission switched between fwd and rev.
            inter_direction_lags: List of observed response delays (seconds).
            is_client_initiated: True if forward direction originated from client port.
        """
        pf = float(fwd.packet_count)
        pr = float(rev.packet_count)
        bf = float(fwd.byte_count)
        br = float(rev.byte_count)

        # -------------------------------------------------------------
        # Feature Group A: Packet Asymmetry (Task 5)
        # Ap = |Pf - Pr| / (Pf + Pr + eps) in [0.0, 1.0]
        # -------------------------------------------------------------
        packet_asymmetry = abs(pf - pr) / (pf + pr + cls.EPSILON)

        # -------------------------------------------------------------
        # Feature Group B: Byte Asymmetry (Task 5)
        # Ab = |Bf - Br| / (Bf + Br + eps) in [0.0, 1.0]
        # -------------------------------------------------------------
        byte_asymmetry = abs(bf - br) / (bf + br + cls.EPSILON)

        # -------------------------------------------------------------
        # Feature Group C: Direction Ratio (Task 5)
        # Numerically stable, signed logarithmic ratio: log10((Pf + 1) / (Pr + 1))
        # 0.0 -> balanced (1:1)
        # +1.0 -> 10:1 forward
        # +2.0 -> 100:1 forward
        # -1.0 -> 1:10 reverse
        # -------------------------------------------------------------
        directional_ratio = math.log10((pf + 1.0) / (pr + 1.0))

        # Rates
        eff_dur = max(cls.EPSILON, overall_duration)
        forward_packet_rate = pf / eff_dur
        reverse_packet_rate = pr / eff_dur
        forward_byte_rate = bf / eff_dur
        reverse_byte_rate = br / eff_dur

        # -------------------------------------------------------------
        # Feature Group D: Packet Dependency Features (Task 6)
        # -------------------------------------------------------------
        # 1. Reverse-Response Presence
        reverse_presence = 1.0 if pr > 0 else 0.0

        # 2. Burst Transition Rate: Switch count normalized by total packets
        # In conversational traffic (interactive HTTP, SSH, gaming), transitions are frequent.
        # In blind one-way attacks (SYN flood, UDP flood, pure exfil), transitions are zero or near zero.
        total_packets = max(1.0, pf + pr)
        burst_transition_rate = float(burst_transitions) / total_packets

        # 3. Temporal Dependency: Inter-directional response latency
        if inter_direction_lags and len(inter_direction_lags) > 0:
            temporal_dependency_lag = float(np.mean(inter_direction_lags[:50]))
        else:
            temporal_dependency_lag = 0.0

        # 4. TCP Handshake Presence
        # Forward SYN observed and Reverse SYN+ACK or ACK observed
        tcp_handshake_presence = 0.0
        if fwd.tcp_syn_cnt > 0 and rev.tcp_syn_cnt > 0:
            tcp_handshake_presence = 1.0 # Both directions exchanged SYN/SYN-ACK
        elif fwd.tcp_syn_cnt > 0 and rev.tcp_ack_cnt > 0:
            tcp_handshake_presence = 0.8 # Reverse responded with ACK

        # 5. Reverse ACK Ratio (Did reverse acknowledge forward packets?)
        reverse_ack_ratio = (rev.tcp_ack_cnt / max(1.0, pf)) if pr > 0 else 0.0

        return {
            "forward_packet_count": pf,
            "reverse_packet_count": pr,
            "forward_byte_count": bf,
            "reverse_byte_count": br,
            "packet_asymmetry": float(np.clip(packet_asymmetry, 0.0, 1.0)),
            "byte_asymmetry": float(np.clip(byte_asymmetry, 0.0, 1.0)),
            "directional_ratio": float(directional_ratio),
            "forward_packet_rate": float(forward_packet_rate),
            "reverse_packet_rate": float(reverse_packet_rate),
            "forward_byte_rate": float(forward_byte_rate),
            "reverse_byte_rate": float(reverse_byte_rate),
            "duration": float(overall_duration),
            "reverse_presence": float(reverse_presence),
            "burst_transition_rate": float(burst_transition_rate),
            "temporal_dependency_lag": float(temporal_dependency_lag),
            "tcp_handshake_presence": float(tcp_handshake_presence),
            "reverse_ack_ratio": float(np.clip(reverse_ack_ratio, 0.0, 2.0)),
        }

    @classmethod
    def to_vector(cls, features_dict: Dict[str, float]) -> np.ndarray:
        """Converts feature dictionary to a 1D NumPy float array in canonical order."""
        return np.array([features_dict.get(name, 0.0) for name in DIRECTIONALITY_FEATURE_NAMES], dtype=np.float32)
