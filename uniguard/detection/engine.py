"""Threat Detection Orchestration Engine for UniGuard AI.

Integrates feature extraction, scaling, supervised threat classification,
unsupervised anomaly detection, multi-factor risk scoring, and explainable AI.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from dataclasses import dataclass, asdict, field
import time
import numpy as np
import pandas as pd

from uniguard.flow_engine.flow import UnidirectionalFlow
from uniguard.features.extractor import FeatureExtractor
from uniguard.features.schema import UNIDIRECTIONAL_FEATURES
from uniguard.preprocessing.pipeline import FlowDataPreprocessor
from uniguard.models.supervised import SupervisedThreatClassifier
from uniguard.models.anomaly import IsolationForestAnomalyDetector
from uniguard.risk.scorer import RiskScorer
from uniguard.explainability.explainer import FlowExplainer


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: float
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    threat_type: str
    risk_score: int
    severity: str
    confidence_pct: float
    anomaly_score: float
    contributing_factors: List[Dict[str, Any]]
    flow_metrics: Dict[str, Any]
    directionality_state: str = "UNKNOWN"
    directionality_score: float = 0.0
    directionality_confidence: float = 0.0
    directionality_explanation: List[str] = field(default_factory=list)
    baseline_5_20_result: str = "N/A"
    is_excluded_from_unidirectional_security: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DetectionEngine:
    """Core detection orchestrator for UniGuard AI."""

    def __init__(
        self,
        classifier: Optional[SupervisedThreatClassifier] = None,
        anomaly_detector: Optional[IsolationForestAnomalyDetector] = None,
        preprocessor: Optional[FlowDataPreprocessor] = None,
        risk_scorer: Optional[RiskScorer] = None,
    ) -> None:
        self.classifier = classifier
        self.anomaly_detector = anomaly_detector
        self.preprocessor = preprocessor
        self.risk_scorer = risk_scorer or RiskScorer()
        self.explainer: Optional[FlowExplainer] = None

        if self.classifier is not None:
            self.explainer = FlowExplainer(
                trained_model=self.classifier.model,
                feature_names=list(UNIDIRECTIONAL_FEATURES),
            )

        self.events_processed_count: int = 0
        self.threats_detected_count: int = 0

    def analyze_flow(self, flow: UnidirectionalFlow, skip_shap: bool = False) -> SecurityEvent:
        """Analyzes a completed flow through the full AI and directionality pipeline."""
        self.events_processed_count += 1
        now = time.time()
        event_id = f"EVT-{int(now * 1000)}-{self.events_processed_count:05d}"
        flow_key = f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} [P{flow.proto}]"

        # Directionality Metadata Extraction
        raw_dir_score = getattr(flow, "directionality_score", None)
        if raw_dir_score is not None:
            dir_score = float(raw_dir_score)
            dir_state = str(getattr(flow, "directionality_state", "UNKNOWN"))
            dir_conf = float(getattr(flow, "directionality_confidence", 0.5))
        else:
            # Fallback for standalone UnidirectionalFlow without upstream biflow engine
            if flow.tcp_syn_cnt > 0 and flow.tcp_ack_cnt == 0:
                dir_state = "UNIDIRECTIONAL_OBSERVED"
                dir_score = 0.95
                dir_conf = 0.90
            else:
                dir_state = "UNKNOWN"
                dir_score = 0.50
                dir_conf = 0.50

        is_excluded = bool(getattr(flow, "is_excluded_from_unidirectional_security", False))
        
        b520_info = getattr(flow, "baseline_5_20", {})
        if isinstance(b520_info, dict) and "baseline_5_20" in b520_info:
            b520_label = str(b520_info["baseline_5_20"].get("baseline_label", "N/A"))
        else:
            b520_label = "N/A"

        dir_result = getattr(flow, "directionality_result", None)
        if dir_result is not None and hasattr(dir_result, "explanation_bullets"):
            dir_explanation = dir_result.explanation_bullets
        else:
            dir_explanation = [f"Directionality State: {dir_state}"]

        # 1. Feature Extraction (Strict 24 Features)
        raw_features = FeatureExtractor.extract_features(flow)

        # -------------------------------------------------------------
        # Bidirectional Traffic Exclusion Gate (Task 11 & 12)
        # -------------------------------------------------------------
        # If the directionality engine identified this flow as balanced/conversational BIDIRECTIONAL,
        # it is EXCLUDED from the unidirectional ML threat pipeline to eliminate normal download/web false alarms,
        # while still recording telemetry for the dashboard and database.
        if is_excluded:
            return SecurityEvent(
                event_id=event_id,
                timestamp=now,
                flow_key=flow_key,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                proto=flow.proto,
                threat_type="BENIGN",
                risk_score=5,
                severity="INFORMATIONAL",
                confidence_pct=99.0,
                anomaly_score=0.01,
                contributing_factors=[
                    {"feature": "directionality", "value": round(dir_score, 3), "explanation": "Balanced bidirectional traffic excluded from unidirectional detection"},
                    {"feature": "pkt_count", "value": flow.packet_count, "explanation": "Observed packets in forward direction"},
                    {"feature": "byte_count", "value": flow.byte_count, "explanation": "Total forward bytes"},
                ],
                flow_metrics={
                    "packet_count": flow.packet_count,
                    "byte_count": flow.byte_count,
                    "duration": round(flow.duration, 4),
                    "pkt_rate": round(raw_features["pkt_rate"], 2),
                    "byte_rate": round(raw_features["byte_rate"], 2),
                    "entropy": round(raw_features["entropy_pkt_len"], 3),
                },
                directionality_state=dir_state,
                directionality_score=dir_score,
                directionality_confidence=dir_conf,
                directionality_explanation=dir_explanation,
                baseline_5_20_result=b520_label,
                is_excluded_from_unidirectional_security=True,
            )

        # Elephant Flow Fast-Path Optimization (Section 4)
        # Established benign elephant flows bypass repeated 120-tree ML and Isolation Forest inference
        # while continuously tracking volume, rates, and duration in O(1) time.
        is_established_benign_elephant = (
            getattr(flow, "is_elephant", False)
            and getattr(flow, "is_benign", True)
            and flow.tcp_rst_cnt <= 3
            and raw_features["pkt_rate"] < 15000.0
        )

        if is_established_benign_elephant and skip_shap:
            threat_type = "BENIGN"
            confidence = 0.98
            anomaly_score = 0.05
            risk_score = 10
            severity = "LOW"
            contributing = [
                {"feature": "pkt_count", "value": flow.packet_count, "explanation": "Elephant flow fast-path bypass"},
                {"feature": "byte_count", "value": flow.byte_count, "explanation": "Total bulk bytes"},
                {"feature": "duration", "value": round(flow.duration, 4), "explanation": "Flow duration"},
                {"feature": "pkt_rate", "value": round(raw_features["pkt_rate"], 2), "explanation": "Packet rate"},
            ]
            return SecurityEvent(
                event_id=event_id,
                timestamp=now,
                flow_key=flow_key,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                proto=flow.proto,
                threat_type=threat_type,
                risk_score=risk_score,
                severity=severity,
                confidence_pct=round(confidence * 100, 1),
                anomaly_score=anomaly_score,
                contributing_factors=contributing,
                flow_metrics={
                    "packet_count": flow.packet_count,
                    "byte_count": flow.byte_count,
                    "duration": round(flow.duration, 4),
                    "pkt_rate": round(raw_features["pkt_rate"], 2),
                    "byte_rate": round(raw_features["byte_rate"], 2),
                    "entropy": round(raw_features["entropy_pkt_len"], 3),
                },
            )

        raw_df = pd.DataFrame([raw_features])

        # 2. Preprocessing & Scaling
        if self.preprocessor is not None and self.preprocessor.is_fitted:
            scaled_vector = self.preprocessor.transform_features(raw_df)
        else:
            scaled_vector = np.array([[raw_features[f] for f in UNIDIRECTIONAL_FEATURES]], dtype=np.float32)

        # 3. Supervised Classification
        if self.classifier is not None and getattr(self.classifier, "classes_", None) is not None:
            y_pred = self.classifier.predict(scaled_vector)[0]
            y_proba = self.classifier.predict_proba(scaled_vector)[0]
            # Map index or label
            if isinstance(y_pred, (int, np.integer)):
                if self.preprocessor and getattr(self.preprocessor, "label_encoder", None) is not None:
                    threat_type = str(self.preprocessor.label_encoder.inverse_transform([int(y_pred)])[0])
                else:
                    threat_type = str(y_pred)
            else:
                threat_type = str(y_pred)
            confidence = float(np.max(y_proba))

            # Domain-Knowledge Guard: Inbound Server Traffic Cannot Be Data Exfiltration
            # When traffic originates from well-known server ports (443, 80, 8443, 8080) to client,
            # this represents a legitimate inbound download (streaming, file download, updates).
            if threat_type == "DATA_EXFILTRATION" and flow.src_port in (80, 443, 8080, 8443, 8000):
                threat_type = "BENIGN"
                confidence = 0.95
        else:
            # Fallback heuristic if models are not yet loaded
            if flow.tcp_syn_cnt > 0 and flow.tcp_ack_cnt == 0:
                if flow.packet_count >= 20 and raw_features["pkt_rate"] > 50.0:
                    threat_type = "SYN_FLOOD"
                    confidence = 0.95
                elif flow.packet_count == 1:
                    threat_type = "PORT_SCAN"
                    confidence = 0.85
                else:
                    threat_type = "SUSPICIOUS"
                    confidence = 0.60
            else:
                threat_type = "BENIGN"
                confidence = 0.95

        # 4. Anomaly Detection
        if self.anomaly_detector is not None and self.anomaly_detector.is_fitted:
            anomaly_eval = self.anomaly_detector.evaluate_sample(scaled_vector)
            anomaly_score = anomaly_eval["anomaly_score"]
        else:
            anomaly_score = 0.05 if threat_type == "BENIGN" else 0.80

        # 5. Multi-Factor Risk Scoring (Task 16)
        risk_eval = self.risk_scorer.calculate_risk(
            threat_type=threat_type,
            classifier_confidence=confidence,
            anomaly_score=anomaly_score,
            pkt_rate=raw_features["pkt_rate"],
            byte_rate=raw_features["byte_rate"],
            directionality_score=dir_score,
            directionality_confidence=dir_conf,
        )

        # 6. Explainable AI Attributions (computed for threats or novel anomalies)
        should_explain = (
            self.explainer is not None
            and not skip_shap
            and (threat_type != "BENIGN" or not getattr(flow, "is_elephant", False))
        )

        if should_explain:
            contributing = self.explainer.explain_instance(
                raw_feature_dict=raw_features,
                scaled_vector=scaled_vector,
                predicted_class=threat_type,
                top_k=4,
            )
        else:
            contributing = [
                {"feature": "pkt_rate", "value": round(raw_features["pkt_rate"], 2), "explanation": "Packet rate"},
                {"feature": "tcp_syn_cnt", "value": flow.tcp_syn_cnt, "explanation": "SYN count"},
                {"feature": "byte_count", "value": flow.byte_count, "explanation": "Byte count"},
                {"feature": "duration", "value": round(flow.duration, 4), "explanation": "Flow duration"},
            ]

        if risk_eval["risk_score"] >= 35:
            self.threats_detected_count += 1

        return SecurityEvent(
            event_id=event_id,
            timestamp=now,
            flow_key=flow_key,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            proto=flow.proto,
            threat_type=threat_type,
            risk_score=risk_eval["risk_score"],
            severity=risk_eval["severity"],
            confidence_pct=risk_eval["confidence_pct"],
            anomaly_score=round(anomaly_score, 3),
            contributing_factors=contributing,
            flow_metrics={
                "packet_count": flow.packet_count,
                "byte_count": flow.byte_count,
                "duration": round(flow.duration, 4),
                "pkt_rate": round(raw_features["pkt_rate"], 2),
                "byte_rate": round(raw_features["byte_rate"], 2),
                "entropy": round(raw_features["entropy_pkt_len"], 3),
            },
            directionality_state=dir_state,
            directionality_score=dir_score,
            directionality_confidence=dir_conf,
            directionality_explanation=dir_explanation,
            baseline_5_20_result=b520_label,
            is_excluded_from_unidirectional_security=False,
        )
