"""Transparent Multi-Factor Risk Scoring Engine.

Calculates risk score (0-100), severity level, and contributing factor breakdown
based on supervised classification confidence, anomaly score, threat criticality,
and flow behavioral volume/rate impact.
"""

from typing import Dict, Any, Tuple


class RiskScorer:
    """Computes transparent, explainable risk scores for detected network events."""

    # Base Threat Criticality Weights (C_threat in [0.0, 1.0])
    THREAT_CRITICALITY: Dict[str, float] = {
        "BENIGN": 0.0,
        "PORT_SCAN": 0.50,
        "SYN_FLOOD": 0.85,
        "UDP_FLOOD": 0.85,
        "SLOWLORIS": 0.75,
        "DATA_EXFILTRATION": 0.90,
        "C2_BEACON": 0.80,
        "UNKNOWN_ANOMALY": 0.65,
    }

    def __init__(
        self,
        w_classifier: float = 0.40,
        w_anomaly: float = 0.30,
        w_category: float = 0.20,
        w_impact: float = 0.10,
    ) -> None:
        """Initializes the risk scorer with calibrated weights."""
        total_w = w_classifier + w_anomaly + w_category + w_impact
        if abs(total_w - 1.0) > 1e-4:
            raise ValueError(f"Risk weights must sum to 1.0, got {total_w}")

        self.w_cls = w_classifier
        self.w_anom = w_anomaly
        self.w_cat = w_category
        self.w_imp = w_impact

    def calculate_risk(
        self,
        threat_type: str,
        classifier_confidence: float,
        anomaly_score: float,
        pkt_rate: float,
        byte_rate: float,
        directionality_score: float = 0.5,
        directionality_confidence: float = 0.5,
    ) -> Dict[str, Any]:
        """Calculates the composite multi-signal risk score and severity (Task 16).

        Args:
            threat_type: Predicted threat class string.
            classifier_confidence: Supervised probability in [0.0, 1.0].
            anomaly_score: Normalized anomaly severity in [0.0, 1.0].
            pkt_rate: Packets per second observed in flow.
            byte_rate: Bytes per second observed in flow.
            directionality_score: Normalized directionality score (0.0=Balanced, 1.0=One-Way).
            directionality_confidence: Directionality observation confidence in [0.0, 1.0].

        Returns:
            Dictionary containing risk score, severity, and component breakdown.
        """
        threat_key = threat_type.upper().replace(" ", "_")
        c_threat = self.THREAT_CRITICALITY.get(threat_key, 0.60)

        # Behavioral Impact multiplier: High rates add impact
        # Normal web flows typically < 500 pkts/sec; Floods reach thousands
        b_impact = 0.0
        if pkt_rate > 1000.0 or byte_rate > 1_000_000.0:
            b_impact = 1.0
        elif pkt_rate > 100.0 or byte_rate > 100_000.0:
            b_impact = 0.5
        elif pkt_rate > 20.0:
            b_impact = 0.2

        # Directionality Modulation (Task 16):
        # A true unidirectional threat (SYN flood, port scan, pure exfil) exhibits high directionality.
        # If directionality is balanced (< 0.35) with high confidence (> 0.5), attenuate risk to prevent false positives.
        dir_factor = 1.0
        if threat_key != "BENIGN":
            if directionality_score < 0.35 and directionality_confidence > 0.50:
                # Strong conversational / reverse traffic observed -> significantly dampen false alarms
                dir_factor = 0.50
            elif directionality_score >= 0.80 and directionality_confidence >= 0.50:
                # Confirmed unidirectional attack pattern -> reinforce risk
                dir_factor = 1.10

        # If threat is BENIGN, classifier confidence in benign state should NOT add to risk
        threat_confidence = 0.0 if threat_key == "BENIGN" else (classifier_confidence * dir_factor)

        if threat_key == "BENIGN":
            # For benign traffic, risk is driven purely by unexpected anomalies and extreme behavioral impact
            raw_score = (self.w_anom * anomaly_score + self.w_imp * b_impact * 0.5) * 100.0
            # If anomaly score is low/normal (< 0.50), strictly cap risk to safe benign levels (<= 25)
            if anomaly_score < 0.50:
                raw_score = min(25.0, raw_score)
        else:
            weighted_sum = (
                self.w_cls * min(1.0, threat_confidence)
                + self.w_anom * anomaly_score
                + self.w_cat * c_threat
                + self.w_imp * b_impact
            )
            raw_score = weighted_sum * 100.0

        risk_score = int(round(max(0.0, min(100.0, raw_score))))

        # Determine Severity Level
        if risk_score >= 80:
            severity = "CRITICAL"
        elif risk_score >= 60:
            severity = "HIGH"
        elif risk_score >= 35:
            severity = "MEDIUM"
        elif risk_score >= 15:
            severity = "LOW"
        else:
            severity = "INFORMATIONAL"

        return {
            "risk_score": risk_score,
            "severity": severity,
            "confidence_pct": round(classifier_confidence * 100, 1),
            "threat_type": threat_type,
            "directionality_score": round(directionality_score, 3),
            "directionality_confidence": round(directionality_confidence, 3),
            "components": {
                "classifier_contribution": round(self.w_cls * min(1.0, threat_confidence) * 100, 1),
                "anomaly_contribution": round(self.w_anom * anomaly_score * 100, 1),
                "criticality_contribution": round(self.w_cat * c_threat * 100, 1),
                "impact_contribution": round(self.w_imp * b_impact * 100, 1),
                "directionality_factor": round(dir_factor, 2),
            },
        }
