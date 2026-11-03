"""Traffic Behavior Analysis Engine for UniGuard AI UTIE.

Performs behavioral characterization of unidirectional and asymmetric flows:
- Packet size distributions & dispersion
- Inter-arrival time (IAT) dynamics and burstiness index
- TCP flag signatures and state reconstruction
- Shannon information entropy
- Periodic beaconing and machine-generated frequency detection
- Transparent rule-based anomaly indicators + Isolation Forest integration
"""

from __future__ import annotations

import math
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import numpy as np

from uniguard.flow_engine.flow import UnidirectionalFlow


@dataclass
class TrafficBehaviorSummary:
    """Comprehensive behavioral profile of an observed network flow."""
    # Size metrics
    pkt_len_min: float
    pkt_len_max: float
    pkt_len_mean: float
    pkt_len_std: float
    size_homogeneity: float           # 1.0 = identical packets (fixed-size flood/beacon), 0.0 = variable payload
    
    # Timing & Dynamics
    duration: float
    pkt_rate: float
    byte_rate: float
    iat_mean: float
    iat_std: float
    burstiness_index: float           # Variance to mean ratio / coefficient of variation
    is_periodic_beacon: bool          # Very low IAT variance at steady interval
    
    # Protocol & TCP Flags
    proto_name: str
    flag_pattern: str                 # "SYN_ONLY", "ACK_FLOOD", "ESTABLISHED_DATA", "RST_BURST", "FIN_STEALTH", "UDP_STREAM", "ICMP_PROBE", "STANDARD"
    flag_details: Dict[str, int]
    
    # Information Theory
    entropy_pkt_len: float            # Shannon entropy of packet lengths
    
    # Behavioral Tags & Findings
    behavior_tags: List[str] = field(default_factory=list)
    behavior_findings: List[str] = field(default_factory=list)
    is_suspicious_behavior: bool = False
    anomaly_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pkt_len_stats": {
                "min": round(self.pkt_len_min, 1),
                "max": round(self.pkt_len_max, 1),
                "mean": round(self.pkt_len_mean, 2),
                "std": round(self.pkt_len_std, 2),
                "homogeneity": round(self.size_homogeneity, 3),
            },
            "timing_dynamics": {
                "duration": round(self.duration, 4),
                "pkt_rate": round(self.pkt_rate, 2),
                "byte_rate": round(self.byte_rate, 2),
                "iat_mean": round(self.iat_mean, 5),
                "iat_std": round(self.iat_std, 5),
                "burstiness_index": round(self.burstiness_index, 3),
                "is_periodic_beacon": self.is_periodic_beacon,
            },
            "protocol": self.proto_name,
            "flag_pattern": self.flag_pattern,
            "flag_details": self.flag_details,
            "entropy_pkt_len": round(self.entropy_pkt_len, 3),
            "behavior_tags": self.behavior_tags,
            "behavior_findings": self.behavior_findings,
            "is_suspicious_behavior": self.is_suspicious_behavior,
            "anomaly_score": round(self.anomaly_score, 4),
        }


class TrafficBehaviorAnalyzer:
    """Extracts behavioral insights and flags structural anomalies in flow observations."""

    def __init__(self, anomaly_detector: Optional[Any] = None) -> None:
        self.anomaly_detector = anomaly_detector

    def analyze(self, flow: UnidirectionalFlow) -> TrafficBehaviorSummary:
        """Evaluates flow dynamics and returns a structured behavioral summary."""
        dur = max(0.0001, flow.duration)
        pkt_cnt = max(1, flow.packet_count)
        pkt_rate = float(flow.packet_count) / dur if dur > 0 else 0.0
        byte_rate = float(flow.byte_count) / dur if dur > 0 else 0.0

        # 1. Size Homogeneity (Fixed-size packet generation is common in floods/beacons)
        pkt_std = flow.pkt_len_std
        pkt_mean = max(1.0, flow.pkt_len_mean)
        # Coefficient of variation for lengths
        len_cov = pkt_std / pkt_mean
        size_homogeneity = float(np.clip(1.0 - min(1.0, len_cov), 0.0, 1.0))

        # 2. Timing & Burstiness
        iat_mean = flow.iat_mean
        iat_std = flow.iat_std
        if iat_mean > 0.00001:
            # Coefficient of variation of inter-arrival times
            burstiness = float(iat_std / iat_mean)
        else:
            burstiness = 0.0

        # Periodic beaconing heuristic: >= 5 packets, consistent interval (std < 15% of mean), non-zero IAT
        is_beacon = (
            pkt_cnt >= 5
            and iat_mean >= 0.05
            and (iat_std / max(0.0001, iat_mean)) < 0.15
        )

        # 3. Protocol semantics & TCP Flag Patterns
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_name = proto_map.get(flow.proto, f"IP-Proto-{flow.proto}")

        flag_details = {
            "SYN": flow.tcp_syn_cnt,
            "ACK": flow.tcp_ack_cnt,
            "FIN": flow.tcp_fin_cnt,
            "RST": flow.tcp_rst_cnt,
            "PSH": flow.tcp_psh_cnt,
            "URG": flow.tcp_urg_cnt,
        }

        flag_pattern = "STANDARD"
        tags: List[str] = []
        findings: List[str] = []
        is_suspicious = False

        if flow.proto == 6:  # TCP
            syn = flow.tcp_syn_cnt
            ack = flow.tcp_ack_cnt
            fin = flow.tcp_fin_cnt
            rst = flow.tcp_rst_cnt
            psh = flow.tcp_psh_cnt

            if syn > 0 and ack == 0 and fin == 0 and rst == 0:
                flag_pattern = "SYN_ONLY"
                tags.append("TCP-SYN-ONLY")
                if pkt_cnt > 3:
                    findings.append(f"Pure SYN packet stream ({syn} SYNs) with zero ACKs. Typical of TCP SYN Flooding or Stealth Scanning.")
                    is_suspicious = True
                else:
                    findings.append("Initial connection handshake initiation (SYN without follow-up).")
            elif ack > 0 and syn == 0 and fin == 0:
                if pkt_rate > 50.0:
                    flag_pattern = "ACK_FLOOD"
                    tags.append("TCP-ACK-FLOOD")
                    findings.append(f"High-rate ACK packet flood ({ack} ACKs at {pkt_rate:.1f} pps) without preceding handshake context.")
                    is_suspicious = True
                else:
                    flag_pattern = "ESTABLISHED_DATA"
                    tags.append("TCP-ESTABLISHED")
                    findings.append("Established TCP session carrying data/acknowledgments.")
            elif rst > 0 and rst >= (pkt_cnt * 0.5):
                flag_pattern = "RST_BURST"
                tags.append("TCP-RST-BURST")
                findings.append(f"Excessive TCP RST resets observed ({rst} RSTs). Indicates closed port rejection or abrupt teardown.")
                if pkt_cnt > 2:
                    is_suspicious = True
            elif fin > 0 and ack == 0:
                flag_pattern = "FIN_STEALTH"
                tags.append("TCP-FIN-STEALTH")
                findings.append(f"TCP FIN packets observed without ACK ({fin} FINs). Potential stealth port scan.")
                is_suspicious = True
            elif psh > 0 and ack > 0:
                flag_pattern = "PSH_DATA_STREAM"
                tags.append("TCP-PSH-STREAM")
                findings.append(f"Active data push stream ({psh} PSH packets, {flow.byte_count} total bytes).")

        elif flow.proto == 17:  # UDP
            flag_pattern = "UDP_STREAM"
            tags.append("UDP-STREAM")
            if pkt_rate > 1000.0:
                tags.append("UDP-HIGH-RATE")
                findings.append(f"Very high packet rate UDP stream ({pkt_rate:.1f} pps). Characteristic of UDP volumetric flooding or DNS/NTP amplification.")
                is_suspicious = True
            elif size_homogeneity > 0.95 and pkt_cnt > 10:
                tags.append("UDP-FIXED-SIZE")
                findings.append(f"Monolithic identical UDP packets ({flow.pkt_len_mean:.0f} bytes). Typical of synthetic traffic generators or DDoS tools.")
                is_suspicious = True
            else:
                findings.append(f"Standard UDP communication ({pkt_cnt} packets, {flow.byte_count} bytes).")

        elif flow.proto == 1:  # ICMP
            flag_pattern = "ICMP_PROBE"
            tags.append("ICMP-TRAFFIC")
            if pkt_rate > 100.0:
                tags.append("ICMP-FLOOD")
                findings.append(f"High-rate ICMP flood ({pkt_rate:.1f} pps).")
                is_suspicious = True
            else:
                findings.append(f"ICMP diagnostic activity ({pkt_cnt} packets).")
        else:
            flag_pattern = f"PROTO_{flow.proto}"
            findings.append(f"Network traffic on IP protocol number {flow.proto}.")

        # 4. Burstiness & Homogeneity Findings
        if is_beacon:
            tags.append("PERIODIC-BEACON")
            findings.append(f"Strict periodic transmission interval detected (mean IAT={iat_mean:.3f}s, variance < 15%). Common in C2 heartbeat polling or scheduled IoT telemetry.")
            is_suspicious = True

        if burstiness > 3.0:
            tags.append("HIGH-BURSTINESS")
            findings.append(f"High burstiness coefficient ({burstiness:.2f}). Traffic arrives in intermittent spikes rather than steady streaming.")

        # 5. Shannon Entropy
        entropy = flow.entropy_pkt_len
        if entropy < 0.2 and pkt_cnt >= 5:
            tags.append("ZERO-ENTROPY-SIZES")
            findings.append("Near-zero packet size entropy. Flow consists of strictly uniform packet buffers.")

        # 6. Out-of-Distribution Anomaly Score (via IsolationForest if available)
        anomaly_val = 0.05
        if self.anomaly_detector is not None:
            try:
                # Use standard 24-feature vector or behavioral subset
                from uniguard.features.extractor import FeatureExtractor
                feats = FeatureExtractor.extract_features(flow)
                pred_label, raw_score = self.anomaly_detector.predict_single(feats)
                anomaly_val = float(raw_score)
                if pred_label == -1:
                    tags.append("ISOLATION-FOREST-ANOMALY")
                    findings.append(f"Unsupervised Isolation Forest detected statistical outlier (Anomaly Score: {anomaly_val:.3f}).")
                    is_suspicious = True
            except Exception:
                pass

        if not findings:
            findings.append(f"Nominal network traffic pattern ({pkt_cnt} packets, {flow.byte_count} bytes, duration {dur:.2f}s).")

        return TrafficBehaviorSummary(
            pkt_len_min=flow.pkt_len_min,
            pkt_len_max=flow.pkt_len_max,
            pkt_len_mean=flow.pkt_len_mean,
            pkt_len_std=pkt_std,
            size_homogeneity=size_homogeneity,
            duration=flow.duration,
            pkt_rate=pkt_rate,
            byte_rate=byte_rate,
            iat_mean=iat_mean,
            iat_std=iat_std,
            burstiness_index=burstiness,
            is_periodic_beacon=is_beacon,
            proto_name=proto_name,
            flag_pattern=flag_pattern,
            flag_details=flag_details,
            entropy_pkt_len=entropy,
            behavior_tags=tags,
            behavior_findings=findings,
            is_suspicious_behavior=is_suspicious,
            anomaly_score=anomaly_val,
        )
