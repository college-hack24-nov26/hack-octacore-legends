"""Unidirectional Feature Extractor.

Transforms a UnidirectionalFlow object into the canonical 24-feature vector.
Handles numerical stability, zero-duration edge cases, and statistical moments.
"""

from typing import Dict, Any, List
import numpy as np
from uniguard.flow_engine.flow import UnidirectionalFlow
from uniguard.features.schema import UNIDIRECTIONAL_FEATURES


class FeatureExtractor:
    """Extracts mathematically validated unidirectional flow features."""

    EPSILON: float = 1e-7

    @classmethod
    def extract_features(cls, flow: UnidirectionalFlow) -> Dict[str, float]:
        """Extracts the 24 unidirectional features from a flow.

        Args:
            flow: A UnidirectionalFlow instance.

        Returns:
            Dictionary mapping feature names to computed float values.
        """
        duration = flow.duration
        pkt_count = flow.packet_count
        byte_count = flow.byte_count

        # Rates (packets/sec, bytes/sec)
        # For zero-duration or single-packet flows, rate is mathematically undefined
        # and conventionally assigned 0.0 to prevent artificial rate spikes (e.g. 10,000,000 pkts/s).
        if duration <= 1e-6 or pkt_count <= 1:
            pkt_rate = 0.0
            byte_rate = 0.0
        else:
            pkt_rate = float(pkt_count) / duration
            byte_rate = float(byte_count) / duration

        # Packet Length Statistics (O(1) from Welford moments or fallback)
        if hasattr(flow, "pkt_len_mean") and flow.packet_count > 0:
            pkt_len_mean = float(flow.pkt_len_mean)
            pkt_len_std = float(flow.pkt_len_std)
            pkt_len_min = float(flow.pkt_len_min)
            pkt_len_max = float(flow.pkt_len_max)
        elif flow.packet_lengths:
            lengths = flow.packet_lengths
            pkt_len_mean = float(np.mean(lengths))
            pkt_len_std = float(np.std(lengths)) if len(lengths) > 1 else 0.0
            pkt_len_min = float(np.min(lengths))
            pkt_len_max = float(np.max(lengths))
        else:
            pkt_len_mean = 0.0
            pkt_len_std = 0.0
            pkt_len_min = 0.0
            pkt_len_max = 0.0

        # Inter-Arrival Time (IAT) Statistics (O(1) from Welford moments or fallback)
        if hasattr(flow, "iat_mean") and getattr(flow, "iat_count", 0) > 0:
            iat_mean = float(flow.iat_mean)
            iat_std = float(flow.iat_std)
            iat_min = float(flow.iat_min)
            iat_max = float(flow.iat_max)
            burstiness = float(iat_std / (iat_mean + cls.EPSILON))
        elif flow.inter_arrival_times:
            iats = flow.inter_arrival_times
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats)) if len(iats) > 1 else 0.0
            iat_min = float(np.min(iats))
            iat_max = float(np.max(iats))
            burstiness = float(iat_std / (iat_mean + cls.EPSILON))
        else:
            iat_mean = 0.0
            iat_std = 0.0
            iat_min = 0.0
            iat_max = 0.0
            burstiness = 0.0

        # Packet Length Entropy
        entropy_pkt_len = flow.calculate_entropy()

        features: Dict[str, float] = {
            "proto": float(flow.proto),
            "dst_port": float(flow.dst_port),
            "src_port": float(flow.src_port),
            "pkt_count": float(pkt_count),
            "byte_count": float(byte_count),
            "duration": float(duration),
            "pkt_rate": float(pkt_rate),
            "byte_rate": float(byte_rate),
            "pkt_len_mean": float(pkt_len_mean),
            "pkt_len_std": float(pkt_len_std),
            "pkt_len_min": float(pkt_len_min),
            "pkt_len_max": float(pkt_len_max),
            "iat_mean": float(iat_mean),
            "iat_std": float(iat_std),
            "iat_min": float(iat_min),
            "iat_max": float(iat_max),
            "tcp_syn_cnt": float(flow.tcp_syn_cnt),
            "tcp_psh_cnt": float(flow.tcp_psh_cnt),
            "tcp_ack_cnt": float(flow.tcp_ack_cnt),
            "tcp_fin_cnt": float(flow.tcp_fin_cnt),
            "tcp_rst_cnt": float(flow.tcp_rst_cnt),
            "tcp_urg_cnt": float(flow.tcp_urg_cnt),
            "entropy_pkt_len": float(entropy_pkt_len),
            "burstiness": float(burstiness),
        }

        return features

    @classmethod
    def extract_vector(cls, flow: UnidirectionalFlow) -> np.ndarray:
        """Extracts features as a 1D NumPy array in canonical order."""
        features_dict = cls.extract_features(flow)
        return np.array([features_dict[f] for f in UNIDIRECTIONAL_FEATURES], dtype=np.float32)
