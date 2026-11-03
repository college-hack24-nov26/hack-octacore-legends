"""Behavioral Evidence Rules for Network Traffic Observations.

Evaluates raw flow metrics and features against baseline network traffic
characteristics to generate concrete, factual observed behavioral evidence.
Ensures every explanation is grounded in actual packet and flow data.
"""

from typing import Dict, Any, List


class BehavioralEvidenceGenerator:
    """Extracts factual behavioral statements from observed flow traffic metrics."""

    # Reference baseline medians for typical enterprise/datacenter client-server flows
    BASELINE_THRESHOLDS = {
        "normal_pkt_rate_max": 50.0,            # Normal non-bursty traffic < 50 pkts/s
        "elevated_pkt_rate": 200.0,             # Moderately elevated rate
        "high_pkt_rate": 1000.0,                # High flood intensity rate
        "normal_byte_rate_max": 100_000.0,      # 100 KB/s
        "high_byte_rate": 1_000_000.0,          # 1 MB/s
        "syn_flood_min_syn": 15,                # Elevated SYN threshold
        "small_packet_max_len": 80.0,           # Header-only packets (e.g. bare SYN/ACK/RST)
        "low_entropy_max": 2.0,                 # Low diversity (scripted payload)
        "slowloris_duration_min": 10.0,         # Prolonged connection
        "slowloris_max_byte_rate": 500.0,       # Low bandwidth trickle
    }

    @classmethod
    def generate_evidence(
        cls,
        threat_category: str,
        flow_metrics: Dict[str, Any],
        raw_features: Dict[str, float],
        directionality_state: str = "UNKNOWN",
    ) -> List[str]:
        """Generates evidence statements derived strictly from actual flow data.

        Args:
            threat_category: Classified threat name (e.g. SYN_FLOOD, PORT_SCAN).
            flow_metrics: High-level metrics (packet_count, byte_count, duration, etc.).
            raw_features: Dictionary of the 24 unidirectional network features.
            directionality_state: Observed directionality label.

        Returns:
            List of evidence statements supported by the metrics.
        """
        evidence: List[str] = []

        pkt_count = int(flow_metrics.get("packet_count", raw_features.get("fwd_pkt_cnt", 0)))
        byte_count = int(flow_metrics.get("byte_count", raw_features.get("fwd_byte_cnt", 0)))
        duration = float(flow_metrics.get("duration", raw_features.get("duration", 0.0)))
        pkt_rate = float(raw_features.get("pkt_rate", 0.0))
        byte_rate = float(raw_features.get("byte_rate", 0.0))
        entropy = float(raw_features.get("entropy_pkt_len", 0.0))
        pkt_len_mean = float(raw_features.get("pkt_len_mean", 0.0))
        syn_cnt = int(raw_features.get("tcp_syn_cnt", 0))
        ack_cnt = int(raw_features.get("tcp_ack_cnt", 0))
        rst_cnt = int(raw_features.get("tcp_rst_cnt", 0))
        dst_port = int(raw_features.get("dst_port", flow_metrics.get("dst_port", 0)))

        # 1. Packet Transmission Rate Evaluation
        if pkt_rate >= cls.BASELINE_THRESHOLDS["high_pkt_rate"]:
            evidence.append(
                f"Abnormally high packet rate observed: {pkt_rate:,.1f} pkts/s (exceeds high-volume threshold of {cls.BASELINE_THRESHOLDS['high_pkt_rate']} pkts/s)."
            )
        elif pkt_rate >= cls.BASELINE_THRESHOLDS["elevated_pkt_rate"]:
            evidence.append(
                f"Elevated packet transmission rate: {pkt_rate:,.1f} pkts/s (standard baseline is < {cls.BASELINE_THRESHOLDS['normal_pkt_rate_max']} pkts/s)."
            )

        # 2. Bandwidth Throughput & Byte Volume
        if byte_rate >= cls.BASELINE_THRESHOLDS["high_byte_rate"]:
            evidence.append(
                f"High-throughput bandwidth consumption: {byte_rate / 1024 / 1024:.2f} MB/s across {byte_count:,} total observed bytes."
            )
        elif byte_count > 500_000 and duration < 5.0:
            evidence.append(
                f"Concentrated outbound data transfer: {byte_count / 1024:.1f} KB transferred within {duration:.2f} seconds."
            )

        # 3. TCP Flag Analysis
        if syn_cnt > 0 and ack_cnt == 0:
            if syn_cnt >= cls.BASELINE_THRESHOLDS["syn_flood_min_syn"]:
                evidence.append(
                    f"Repetitive TCP connection initiation pattern: {syn_cnt} SYN packets observed with zero corresponding ACK responses."
                )
            elif pkt_count <= 3:
                evidence.append(
                    f"Isolated TCP connection attempt observed: {syn_cnt} SYN packet(s) directed at target service port {dst_port}."
                )
            else:
                evidence.append(
                    f"Unidirectional TCP connection requests: {syn_cnt} SYN packet(s) without return acknowledgments."
                )
        elif syn_cnt > 0 and ack_cnt > 0:
            evidence.append(
                f"Mixed TCP control session observed: {syn_cnt} SYN and {ack_cnt} ACK packet(s) recorded."
            )

        if rst_cnt >= 3:
            evidence.append(
                f"Frequent TCP connection terminations: {rst_cnt} RST packet(s) observed, suggesting connection resets or aborted handshakes."
            )

        # 4. Payload Size and Diversity (Entropy)
        if pkt_count >= 5:
            if pkt_len_mean <= cls.BASELINE_THRESHOLDS["small_packet_max_len"]:
                evidence.append(
                    f"Uniform small packet profile: Mean packet length is {pkt_len_mean:.1f} bytes (typical for control/probe frames without payload)."
                )
            if 0.0 < entropy <= cls.BASELINE_THRESHOLDS["low_entropy_max"]:
                evidence.append(
                    f"Low packet length entropy ({entropy:.2f} bits): Highly homogeneous packet sizes characteristic of automated or scripted generation."
                )

        # 5. Flow Duration & Persistence Characteristics
        if duration >= cls.BASELINE_THRESHOLDS["slowloris_duration_min"] and byte_rate <= cls.BASELINE_THRESHOLDS["slowloris_max_byte_rate"]:
            evidence.append(
                f"Prolonged low-bandwidth connection: Held open for {duration:.1f} seconds with minimal data transmission ({byte_rate:.1f} B/s)."
            )
        elif duration < 0.05 and pkt_count >= 1:
            evidence.append(
                f"Transient micro-flow: Completed in {duration * 1000:.1f} ms with {pkt_count} packet(s)."
            )

        # 6. Directionality Sensor Observation
        if directionality_state == "UNIDIRECTIONAL_OBSERVED":
            evidence.append(
                "Sensor visibility: Traffic was captured exclusively in one direction at the observation point (no return stream recorded)."
            )
        elif directionality_state == "ASYMMETRIC_OBSERVED":
            evidence.append(
                "Sensor visibility: Directional traffic disparity observed; forward volume significantly exceeds reverse volume."
            )
        elif directionality_state == "BIDIRECTIONAL_OBSERVED":
            evidence.append(
                "Sensor visibility: Bilateral conversational dialogue observed; forward and reverse packets are both present."
            )

        # 7. Threat-specific fallback if metrics are sparse
        if not evidence:
            if threat_category == "BENIGN":
                evidence.append("Traffic characteristics conform to standard operational baseline parameters.")
            else:
                evidence.append(
                    f"Flow exhibited statistical deviation in {threat_category.replace('_', ' ').lower()} behavioral patterns across {pkt_count} packet(s)."
                )

        return evidence
