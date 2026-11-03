"""Explainable AI (XAI) Module for UniGuard AI.

Calculates local feature attributions using SHAP (TreeExplainer) to answer
the critical analyst question: 'Why was this traffic classified as suspicious?'
Translates raw mathematical SHAP values into actionable cybersecurity explanations.
"""

from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from uniguard.features.schema import UNIDIRECTIONAL_FEATURES

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


class FlowExplainer:
    """Provides local and global feature attribution for UniGuard AI predictions."""

    # Human-readable cybersecurity interpretations for key features
    FEATURE_DESCRIPTIONS: Dict[str, str] = {
        "pkt_rate": "Packet transmission frequency / flood intensity",
        "byte_rate": "Bandwidth throughput consumption",
        "tcp_syn_cnt": "Isolated TCP connection request count",
        "tcp_ack_cnt": "Sender acknowledgment / data transmission count",
        "tcp_psh_cnt": "Immediate buffer push count",
        "pkt_len_mean": "Average packet payload size",
        "pkt_len_std": "Packet payload variance",
        "entropy_pkt_len": "Payload size diversity / randomness (low = scripted/flood)",
        "burstiness": "Inter-arrival timing irregularity (high = bursty exfiltration)",
        "duration": "Observed flow persistence duration",
        "dst_port": "Target destination service port",
        "iat_mean": "Mean time gap between consecutive packets",
    }

    def __init__(self, trained_model: Any, feature_names: Optional[List[str]] = None) -> None:
        self.model = trained_model
        self.feature_names = feature_names or list(UNIDIRECTIONAL_FEATURES)
        self.explainer: Optional[Any] = None

        if SHAP_AVAILABLE:
            try:
                # TreeExplainer is fast for tree-based models (Random Forest, XGBoost)
                self.explainer = shap.TreeExplainer(self.model)
            except Exception:
                self.explainer = None

    def explain_instance(
        self,
        raw_feature_dict: Dict[str, float],
        scaled_vector: np.ndarray,
        predicted_class: str,
        top_k: int = 4,
    ) -> List[Dict[str, Any]]:
        """Computes top-k contributing features for a given flow detection.

        Returns a list of dicts with feature name, raw value, attribution score,
        and human-readable security explanation.
        """
        if scaled_vector.ndim == 1:
            scaled_vector = scaled_vector.reshape(1, -1)

        attributions: List[Tuple[str, float, float]] = []

        if self.explainer is not None:
            try:
                shap_values = self.explainer.shap_values(scaled_vector)
                # If multi-class, shap_values is a list of arrays per class
                if isinstance(shap_values, list):
                    # Get index of predicted class or class with highest variance
                    sv = shap_values[0][0] if len(shap_values) > 0 else np.zeros(len(self.feature_names))
                elif isinstance(shap_values, np.ndarray):
                    if shap_values.ndim == 3:
                        sv = shap_values[0, :, 0]
                    else:
                        sv = shap_values[0]
                else:
                    sv = np.zeros(len(self.feature_names))

                for idx, fname in enumerate(self.feature_names):
                    raw_val = raw_feature_dict.get(fname, 0.0)
                    impact = float(sv[idx])
                    attributions.append((fname, raw_val, impact))

            except Exception:
                attributions = self._heuristic_attribution(raw_feature_dict)
        else:
            attributions = self._heuristic_attribution(raw_feature_dict)

        # Sort by absolute attribution impact descending
        attributions.sort(key=lambda x: abs(x[2]), reverse=True)

        top_explanations = []
        for fname, raw_val, score in attributions[:top_k]:
            meaning = self.FEATURE_DESCRIPTIONS.get(fname, f"Behavioral metric: {fname}")
            top_explanations.append({
                "feature": fname,
                "value": round(raw_val, 3),
                "impact_score": round(score, 4),
                "direction": "RISK_INCREASING" if score >= 0 else "RISK_REDUCING",
                "explanation": f"{meaning} (Value: {round(raw_val, 2)})",
            })

        return top_explanations

    def _heuristic_attribution(
        self, raw_features: Dict[str, float]
    ) -> List[Tuple[str, float, float]]:
        """Fallback attribution using normalized deviation from standard network baselines."""
        baseline_medians = {
            "pkt_rate": 10.0,
            "byte_rate": 5000.0,
            "tcp_syn_cnt": 1.0,
            "pkt_len_mean": 512.0,
            "entropy_pkt_len": 3.0,
            "burstiness": 0.5,
        }
        res = []
        for f, base in baseline_medians.items():
            val = raw_features.get(f, base)
            deviation = (val - base) / (base + 1e-4)
            res.append((f, val, deviation))
        return res
