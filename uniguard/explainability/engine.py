"""AI Threat Explanation Engine for UniGuard AI.

Answers the fundamental analyst question:
'WHY WAS THIS NETWORK FLOW DETECTED AS A THREAT?'

Integrates:
- Short contextual threat summaries
- Local feature attributions (SHAP TreeExplainer & heuristic attributions)
- Ground-truth behavioral evidence from actual traffic metrics
- Directionality & sensor visibility contextualization (including UTIE)
- Transparent multi-factor risk score explanations
- Actionable, defensive SOC investigation playbooks
"""

from typing import Dict, Any, List, Optional
import time
import logging

from uniguard.explainability.schema import (
    AIThreatExplanation,
    FeatureContribution,
    DirectionalityExplanation,
)
from uniguard.explainability.behavior_rules import BehavioralEvidenceGenerator
from uniguard.explainability.investigation_playbooks import DefensiveInvestigationPlaybooks
from uniguard.explainability.explainer import FlowExplainer

logger = logging.getLogger(__name__)


class AIThreatExplanationEngine:
    """Core explanation orchestrator generating transparent 'Why Was This Detected?' reports."""

    # Plain-language interpretations of specific threat categories
    THREAT_SUMMARIES = {
        "PORT_SCAN": "The system observed reconnaissance activity characterized by repeated connection probes directed across network services. This pattern commonly precedes targeted exploitation and warrants investigation.",
        "SYN_FLOOD": "The system detected an abnormal volume of TCP SYN connection initiation packets lacking corresponding completion handshakes. This behavior is indicative of a Denial-of-Service (DoS) state exhaustion attempt.",
        "UDP_FLOOD": "The system identified high-rate, connectionless UDP datagram transmission directed at target endpoints, consistent with bandwidth saturation or packet amplification attacks.",
        "SLOWLORIS": "The system observed prolonged open HTTP/TCP connections transmitting minimal, fragmented headers. This signature is designed to exhaust web server connection pools while bypassing volumetric thresholds.",
        "DATA_EXFILTRATION": "The system detected high-volume or concentrated outbound data transfer in a unidirectional stream. This pattern requires verification against authorized data transfer workflows.",
        "C2_BEACON": "The system observed repetitive, low-volume communication intervals to an external destination, indicating potential Command-and-Control (C2) heartbeat traffic.",
        "ANOMALOUS": "The system identified statistical anomalies in flow timing, packet length variance, or flag distributions that deviate significantly from established normal network baselines.",
        "BENIGN": "The system evaluated the network flow and found that its behavioral characteristics, packet rates, and protocol flags conform to expected operational baselines.",
    }

    FEATURE_SECURITY_IMPACTS = {
        "pkt_rate": "Packet transmission rate strongly influenced the model toward a volumetric flood or scan assessment.",
        "byte_rate": "Bandwidth consumption rate influenced the model's evaluation of data transfer intensity.",
        "tcp_syn_cnt": "Isolated TCP SYN count supported the model's classification of connection initiation behavior.",
        "tcp_ack_cnt": "Acknowledgment count provided evidence regarding whether bidirectional dialogue was established.",
        "tcp_rst_cnt": "Abrupt reset packet frequency supported the identification of aborted or rejected sessions.",
        "tcp_psh_cnt": "Immediate buffer push flags influenced the model's view of active payload delivery.",
        "pkt_len_mean": "Average packet payload size influenced the distinction between bare control probes and bulk transfers.",
        "pkt_len_std": "Uniformity or variance in packet sizes supported the identification of automated tool signatures.",
        "entropy_pkt_len": "Payload size randomness influenced the model; low entropy supports scripted or automated generation.",
        "burstiness": "Inter-arrival timing irregularity supported the detection of concentrated packet bursts.",
        "duration": "Observed flow persistence supported the model's evaluation of session longevity.",
        "dst_port": "Target destination port provided context on whether targeted services are standard or vulnerable.",
    }

    def __init__(self, explainer: Optional[FlowExplainer] = None) -> None:
        self.explainer = explainer

    def explain_detection(
        self,
        alert_id: str,
        flow_id: str,
        threat_category: str,
        model_name: str,
        model_confidence: Optional[float],
        risk_score: int,
        severity: str,
        risk_components: Optional[Dict[str, Any]] = None,
        flow_metrics: Optional[Dict[str, Any]] = None,
        raw_features: Optional[Dict[str, float]] = None,
        contributing_factors: Optional[List[Dict[str, Any]]] = None,
        directionality_state: str = "UNKNOWN",
        directionality_score: float = 0.0,
        directionality_confidence: float = 0.0,
        directionality_explanation: Optional[List[str]] = None,
        utie_report: Optional[Any] = None,
        timestamp: Optional[str] = None,
    ) -> AIThreatExplanation:
        """Constructs a comprehensive, evidence-based threat explanation.

        Args:
            alert_id: Unique identifier of the security event / alert.
            flow_id: Identifier of the evaluated flow session.
            threat_category: Supervised threat category or anomaly label.
            model_name: Human-readable name of the executing ML model.
            model_confidence: Supervised classification probability in [0.0, 1.0], or None.
            risk_score: Multi-factor risk score (0-100).
            severity: Assigned severity ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL').
            risk_components: Sub-components breakdown from RiskScorer.
            flow_metrics: High-level metrics dictionary.
            raw_features: 24-feature schema values.
            contributing_factors: Local SHAP or heuristic feature attributions.
            directionality_state: Directionality state string.
            directionality_score: Directionality asymmetry score in [0.0, 1.0].
            directionality_confidence: Directionality confidence in [0.0, 1.0].
            directionality_explanation: Bullets from DirectionalityClassifier / UTIE.
            utie_report: Optional UTIEIntelligenceReport instance if available.
            timestamp: Formatted timestamp string.

        Returns:
            Structured AIThreatExplanation instance.
        """
        try:
            flow_metrics = flow_metrics or {}
            raw_features = raw_features or {}
            ts_str = timestamp or time.strftime("%Y-%m-%d %H:%M:%S")

            # 1. Behavioral Evidence from actual observations
            observed_behavior = BehavioralEvidenceGenerator.generate_evidence(
                threat_category=threat_category,
                flow_metrics=flow_metrics,
                raw_features=raw_features,
                directionality_state=directionality_state,
            )

            # 2. Contextual Threat Summary
            summary = self.generate_summary(
                threat_category=threat_category,
                observed_behavior=observed_behavior,
                model_name=model_name,
                model_confidence=model_confidence,
                risk_score=risk_score,
                severity=severity,
            )

            # 3. Local Feature Contributions (SHAP / Attributions)
            formatted_contributions = self.format_feature_contributions(
                contributing_factors=contributing_factors,
                raw_features=raw_features,
            )

            # 4. Directionality & Sensor Visibility Explanation
            dir_explanation = self.generate_directionality_explanation(
                directionality_state=directionality_state,
                directionality_score=directionality_score,
                directionality_confidence=directionality_confidence,
                directionality_bullets=directionality_explanation,
                utie_report=utie_report,
            )

            # 5. Risk Assessment Explanation
            risk_explanation = self.generate_risk_explanation(
                risk_score=risk_score,
                severity=severity,
                risk_components=risk_components,
                threat_category=threat_category,
                model_confidence=model_confidence,
            )

            # 6. Actionable Defensive Playbook Suggestions
            investigation_suggestions = DefensiveInvestigationPlaybooks.get_suggestions(
                threat_category=threat_category
            )

            return AIThreatExplanation(
                alert_id=alert_id,
                flow_id=flow_id,
                threat_category=threat_category,
                model_name=model_name,
                model_confidence=model_confidence,
                risk_score=risk_score,
                severity=severity,
                summary=summary,
                observed_behavior=observed_behavior,
                feature_contributions=formatted_contributions,
                directionality=dir_explanation.to_dict(),
                risk_explanation=risk_explanation,
                investigation_suggestions=investigation_suggestions,
                timestamp=ts_str,
            )

        except Exception as exc:
            logger.warning(f"Error generating AI threat explanation for {alert_id}: {exc}")
            # Graceful fallback adhering to Section 9 requirement
            return AIThreatExplanation(
                alert_id=alert_id,
                flow_id=flow_id,
                threat_category=threat_category,
                model_name=model_name or "Unknown Model",
                model_confidence=model_confidence,
                risk_score=risk_score,
                severity=severity,
                summary="Explanation unavailable: insufficient supporting information.",
                observed_behavior=["Flow captured and analyzed by detection engine."],
                feature_contributions=[],
                directionality={"state": directionality_state, "explanation": "Directionality assessment unavailable."},
                risk_explanation=f"Assigned risk score of {risk_score} ({severity}).",
                investigation_suggestions=DefensiveInvestigationPlaybooks.get_suggestions(threat_category),
                timestamp=timestamp or time.strftime("%Y-%m-%d %H:%M:%S"),
            )

    def generate_summary(
        self,
        threat_category: str,
        observed_behavior: List[str],
        model_name: str,
        model_confidence: Optional[float],
        risk_score: int,
        severity: str,
    ) -> str:
        """Generates a concise, context-aware threat summary."""
        key = threat_category.upper().replace(" ", "_")
        base_desc = self.THREAT_SUMMARIES.get(
            key,
            f"The system detected an unusual pattern classified as {threat_category} requiring analyst verification."
        )

        conf_str = f" with {model_confidence * 100:.1f}% confidence" if model_confidence is not None else ""
        summary = (
            f"{base_desc} Evaluated by {model_name}{conf_str} and assigned {severity} severity "
            f"(Risk Score: {risk_score}/100)."
        )
        return summary

    def format_feature_contributions(
        self,
        contributing_factors: Optional[List[Dict[str, Any]]],
        raw_features: Dict[str, float],
    ) -> List[Dict[str, Any]]:
        """Formats and contextualizes local feature attributions."""
        results: List[Dict[str, Any]] = []

        if contributing_factors:
            for factor in contributing_factors:
                if not isinstance(factor, dict):
                    continue
                feat = factor.get("feature", "unknown")
                obs_val = factor.get("value", raw_features.get(feat, "N/A"))
                impact = float(factor.get("impact_score", 0.0))
                direction = factor.get("direction", "RISK_INCREASING" if impact >= 0 else "RISK_REDUCING")
                contrib_type = "positive" if direction == "RISK_INCREASING" or impact >= 0 else "negative"

                generic_desc = self.FEATURE_SECURITY_IMPACTS.get(
                    feat,
                    f"Feature '{feat}' influenced the model toward this classification."
                )
                custom_expl = factor.get("explanation")
                explanation_text = custom_expl if custom_expl and custom_expl != feat else generic_desc

                fc = FeatureContribution(
                    feature=feat,
                    observed_value=obs_val,
                    contribution=contrib_type,
                    impact_score=impact,
                    explanation=explanation_text,
                )
                results.append(fc.to_dict())

        # If no attributions provided, generate baseline heuristic attributions
        if not results and raw_features:
            for feat_name in ["pkt_rate", "tcp_syn_cnt", "byte_rate", "duration"]:
                if feat_name in raw_features:
                    val = raw_features[feat_name]
                    impact = 0.5 if val > 0 else 0.0
                    fc = FeatureContribution(
                        feature=feat_name,
                        observed_value=round(val, 2) if isinstance(val, float) else val,
                        contribution="positive" if val > 0 else "neutral",
                        impact_score=impact,
                        explanation=self.FEATURE_SECURITY_IMPACTS.get(
                            feat_name, f"Observed feature '{feat_name}' influenced prediction."
                        ),
                    )
                    results.append(fc.to_dict())

        return results

    def generate_directionality_explanation(
        self,
        directionality_state: str,
        directionality_score: float,
        directionality_confidence: float,
        directionality_bullets: Optional[List[str]] = None,
        utie_report: Optional[Any] = None,
    ) -> DirectionalityExplanation:
        """Creates a balanced directionality explanation separating visibility from malice."""
        # Check if UTIE report provides enhanced visibility assessment
        if utie_report and hasattr(utie_report, "sensor_assessment"):
            sa = utie_report.sensor_assessment
            obs_pt = getattr(sa, "observation_point", "SENSOR_TAP")
            vis_note = (
                f"Observation point is configured as '{obs_pt}'. Note: Unidirectional observed traffic at a passive "
                "sensor tap or data diode does not automatically imply malicious intent; reverse packets may travel "
                "via alternate network routing or bypass the monitoring sensor."
            )
        else:
            vis_note = (
                "Sensor visibility context: Observation of one-way traffic reflects wire visibility at the monitoring interface. "
                "Unidirectional observation does not prove an attack on its own, as asymmetric routing or tap placement "
                "can prevent the sensor from observing return packets."
            )

        if directionality_state == "UNIDIRECTIONAL_OBSERVED":
            expl = (
                f"Only forward packets were observed at this sensor (Asymmetry Score: {directionality_score:.2f}, "
                f"Confidence: {directionality_confidence * 100:.1f}%). Return traffic was either absent or traveled "
                "via an unmonitored path."
            )
        elif directionality_state == "BIDIRECTIONAL_OBSERVED":
            expl = (
                f"Both forward and reverse traffic streams were captured at this sensor (Asymmetry Score: {directionality_score:.2f}, "
                f"Confidence: {directionality_confidence * 100:.1f}%). Valid bilateral dialogue was confirmed."
            )
        elif directionality_state == "ASYMMETRIC_OBSERVED":
            expl = (
                f"Directional traffic volume disparity observed (Asymmetry Score: {directionality_score:.2f}). "
                "Forward traffic significantly exceeded reverse traffic."
            )
        else:
            expl = f"Directionality status evaluated as {directionality_state}."

        if directionality_bullets:
            expl += " " + " ".join(directionality_bullets)

        return DirectionalityExplanation(
            state=directionality_state,
            score=directionality_score,
            confidence=directionality_confidence,
            explanation=expl,
            sensor_visibility_note=vis_note,
        )

    def generate_risk_explanation(
        self,
        risk_score: int,
        severity: str,
        risk_components: Optional[Dict[str, Any]],
        threat_category: str,
        model_confidence: Optional[float],
    ) -> str:
        """Explains why the risk level was assigned based on the multi-factor risk engine."""
        conf_pct = f"{model_confidence * 100:.1f}%" if model_confidence is not None else "N/A"

        if not risk_components:
            return (
                f"Assigned {severity} severity with a composite risk score of {risk_score}/100. "
                f"The score reflects threat criticality for {threat_category} modulated by model confidence ({conf_pct})."
            )

        cls_contrib = risk_components.get("classifier_contribution", 0.0)
        anom_contrib = risk_components.get("anomaly_contribution", 0.0)
        crit_contrib = risk_components.get("criticality_contribution", 0.0)
        imp_contrib = risk_components.get("impact_contribution", 0.0)
        dir_mod = risk_components.get("directionality_factor", 1.0)

        parts = [
            f"The composite risk score ({risk_score}/100, {severity}) was computed by the multi-factor risk engine based on:",
            f"1) Supervised Classifier Confidence: contributed {cls_contrib:.1f} pts (model confidence: {conf_pct})",
            f"2) Threat Category Criticality: contributed {crit_contrib:.1f} pts (inherent severity of {threat_category})",
            f"3) Anomaly Severity: contributed {anom_contrib:.1f} pts (Isolation Forest deviation)",
            f"4) Behavioral Impact: contributed {imp_contrib:.1f} pts (flow throughput/packet volume)",
        ]

        if dir_mod != 1.0:
            parts.append(f"5) Directionality Modulation Factor: {dir_mod:.2f}x multiplier applied based on flow asymmetry.")

        return " ".join(parts)

