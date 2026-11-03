"""Feature Schema and Definitions for Unidirectional IP Flow Analysis.

This module defines the strict 24-feature unidirectional schema.
Every feature in this schema can be computed exclusively from traffic observed
in a single direction (e.g., ingress or egress) without requiring reverse
acknowledgments, response packets, or bidirectional handshake matching.
"""

from dataclasses import dataclass
from typing import List, Dict, Any

# Strict 24 Unidirectional Feature Names in exact canonical order
UNIDIRECTIONAL_FEATURES: List[str] = [
    "proto",            # Transport protocol number (6=TCP, 17=UDP, 1=ICMP)
    "dst_port",         # Target service port (0 - 65535)
    "src_port",         # Source/client port (0 - 65535)
    "pkt_count",        # Total packets in flow observation window
    "byte_count",       # Total bytes in flow observation window
    "duration",         # Time elapsed between first and last observed packet (seconds)
    "pkt_rate",         # Packets per second
    "byte_rate",        # Bytes per second
    "pkt_len_mean",     # Mean packet size in bytes
    "pkt_len_std",      # Standard deviation of packet sizes
    "pkt_len_min",      # Minimum packet size observed
    "pkt_len_max",      # Maximum packet size observed
    "iat_mean",         # Mean inter-arrival time between consecutive packets (seconds)
    "iat_std",          # Standard deviation of packet inter-arrival times
    "iat_min",          # Minimum inter-arrival time observed
    "iat_max",          # Maximum inter-arrival time observed
    "tcp_syn_cnt",      # Count of packets with SYN flag set
    "tcp_psh_cnt",      # Count of packets with PSH flag set
    "tcp_ack_cnt",      # Count of packets with ACK flag set (one-way sender ACKs)
    "tcp_fin_cnt",      # Count of packets with FIN flag set
    "tcp_rst_cnt",      # Count of packets with RST flag set
    "tcp_urg_cnt",      # Count of packets with URG flag set
    "entropy_pkt_len",  # Shannon entropy of packet length distribution
    "burstiness",       # Coefficient of variation of inter-arrival times (std / mean)
]

# Prohibited Bidirectional Features that MUST NOT be used in UniGuard AI:
PROHIBITED_BIDIRECTIONAL_FEATURES: List[str] = [
    "bwd_pkt_count",
    "bwd_byte_count",
    "fwd_bwd_ratio",
    "fwd_bwd_pkt_ratio",
    "fwd_bwd_byte_ratio",
    "init_win_bytes_backward",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_pkt_len_mean",
    "syn_ack_latency_rtt",
    "response_time",
    "http_response_code",
]

@dataclass(frozen=True)
class FeatureMetadata:
    name: str
    description: str
    data_type: str
    min_value: float
    max_value: float
    unit: str

FEATURE_METADATA: Dict[str, FeatureMetadata] = {
    "proto": FeatureMetadata("proto", "IP Protocol Number (6=TCP, 17=UDP, 1=ICMP)", "int", 0, 255, "id"),
    "dst_port": FeatureMetadata("dst_port", "Destination Port", "int", 0, 65535, "port"),
    "src_port": FeatureMetadata("src_port", "Source Port", "int", 0, 65535, "port"),
    "pkt_count": FeatureMetadata("pkt_count", "Total Packets Observed", "int", 1, float("inf"), "packets"),
    "byte_count": FeatureMetadata("byte_count", "Total Bytes Observed", "int", 20, float("inf"), "bytes"),
    "duration": FeatureMetadata("duration", "Flow Duration", "float", 0.0, float("inf"), "seconds"),
    "pkt_rate": FeatureMetadata("pkt_rate", "Packet Rate", "float", 0.0, float("inf"), "pkts/sec"),
    "byte_rate": FeatureMetadata("byte_rate", "Byte Rate / Throughput", "float", 0.0, float("inf"), "bytes/sec"),
    "pkt_len_mean": FeatureMetadata("pkt_len_mean", "Mean Packet Length", "float", 0.0, 65535.0, "bytes"),
    "pkt_len_std": FeatureMetadata("pkt_len_std", "Std Dev of Packet Length", "float", 0.0, 65535.0, "bytes"),
    "pkt_len_min": FeatureMetadata("pkt_len_min", "Minimum Packet Length", "float", 0.0, 65535.0, "bytes"),
    "pkt_len_max": FeatureMetadata("pkt_len_max", "Maximum Packet Length", "float", 0.0, 65535.0, "bytes"),
    "iat_mean": FeatureMetadata("iat_mean", "Mean Inter-Arrival Time", "float", 0.0, float("inf"), "seconds"),
    "iat_std": FeatureMetadata("iat_std", "Std Dev of Inter-Arrival Times", "float", 0.0, float("inf"), "seconds"),
    "iat_min": FeatureMetadata("iat_min", "Minimum Inter-Arrival Time", "float", 0.0, float("inf"), "seconds"),
    "iat_max": FeatureMetadata("iat_max", "Maximum Inter-Arrival Time", "float", 0.0, float("inf"), "seconds"),
    "tcp_syn_cnt": FeatureMetadata("tcp_syn_cnt", "SYN Flag Count", "int", 0, float("inf"), "flags"),
    "tcp_psh_cnt": FeatureMetadata("tcp_psh_cnt", "PSH Flag Count", "int", 0, float("inf"), "flags"),
    "tcp_ack_cnt": FeatureMetadata("tcp_ack_cnt", "ACK Flag Count", "int", 0, float("inf"), "flags"),
    "tcp_fin_cnt": FeatureMetadata("tcp_fin_cnt", "FIN Flag Count", "int", 0, float("inf"), "flags"),
    "tcp_rst_cnt": FeatureMetadata("tcp_rst_cnt", "RST Flag Count", "int", 0, float("inf"), "flags"),
    "tcp_urg_cnt": FeatureMetadata("tcp_urg_cnt", "URG Flag Count", "int", 0, float("inf"), "flags"),
    "entropy_pkt_len": FeatureMetadata("entropy_pkt_len", "Shannon Entropy of Packet Lengths", "float", 0.0, 16.0, "bits"),
    "burstiness": FeatureMetadata("burstiness", "Coefficient of Variation of IAT", "float", 0.0, float("inf"), "ratio"),
}
