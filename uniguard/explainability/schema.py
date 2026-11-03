"""Standardized Data Models for AI Threat Explanation Engine.

Defines structured schemas for:
- Individual feature contributions (local attribution)
- Observed network behavioral evidence
- Directionality & sensor visibility insights
- Risk assessment rationales
- Defensive SOC analyst investigation suggestions
- Comprehensive 'Why Was This Detected?' structured explanation
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
import time


@dataclass
class FeatureContribution:
    """Local attribution for an individual traffic feature."""
    feature: str
    observed_value: Any
    contribution: str                       # 'positive' (supports threat) or 'negative' (reduces threat)
    impact_score: float                     # Numerical attribution weight / SHAP value
    explanation: str                        # Plain-language explanation of influence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "observed_value": self.observed_value,
            "contribution": self.contribution,
            "impact_score": round(self.impact_score, 4),
            "explanation": self.explanation,
        }


@dataclass
class DirectionalityExplanation:
    """Contextual explanation of flow directionality and sensor visibility."""
    state: str                              # e.g., 'UNIDIRECTIONAL_OBSERVED', 'BIDIRECTIONAL_OBSERVED'
    score: float                            # 0.0 to 1.0 asymmetry score
    confidence: float                       # Confidence in directionality classification
    explanation: str                        # Plain-language directionality description
    sensor_visibility_note: str             # Clarification that unidirectional does not imply malicious

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "score": round(self.score, 3),
            "confidence": round(self.confidence, 3),
            "explanation": self.explanation,
            "sensor_visibility_note": self.sensor_visibility_note,
        }


@dataclass
class AIThreatExplanation:
    """Complete, transparent explanation answering: 'Why Was This Detected?'"""
    alert_id: str
    flow_id: str
    threat_category: str
    model_name: str
    model_confidence: Optional[float]
    risk_score: int
    severity: str
    summary: str
    observed_behavior: List[str]
    feature_contributions: List[Dict[str, Any]]
    directionality: Dict[str, Any]
    risk_explanation: str
    investigation_suggestions: List[str]
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "flow_id": self.flow_id,
            "threat_category": self.threat_category,
            "model_name": self.model_name,
            "model_confidence": round(self.model_confidence, 4) if self.model_confidence is not None else None,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "summary": self.summary,
            "observed_behavior": list(self.observed_behavior),
            "feature_contributions": list(self.feature_contributions),
            "directionality": dict(self.directionality),
            "risk_explanation": self.risk_explanation,
            "investigation_suggestions": list(self.investigation_suggestions),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AIThreatExplanation":
        return cls(
            alert_id=str(data.get("alert_id", "UNKNOWN")),
            flow_id=str(data.get("flow_id", "UNKNOWN")),
            threat_category=str(data.get("threat_category", "UNKNOWN")),
            model_name=str(data.get("model_name", "Unknown Model")),
            model_confidence=data.get("model_confidence"),
            risk_score=int(data.get("risk_score", 0)),
            severity=str(data.get("severity", "INFORMATIONAL")),
            summary=str(data.get("summary", "No summary available.")),
            observed_behavior=list(data.get("observed_behavior", [])),
            feature_contributions=list(data.get("feature_contributions", [])),
            directionality=dict(data.get("directionality", {})),
            risk_explanation=str(data.get("risk_explanation", "")),
            investigation_suggestions=list(data.get("investigation_suggestions", [])),
            timestamp=str(data.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))),
        )

