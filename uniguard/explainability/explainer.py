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

        Correctly indexes multi-class SHAP attributions for the specific predicted class
        and filters out irrelevant or unobserved metrics (e.g. TCP flags on UDP, IAT on 1-packet flows).
        """
        if scaled_vector.ndim == 1:
            scaled_vector = scaled_vector.reshape(1, -1)

        attributions: List[Tuple[str, float, float]] = []

        # Determine class index for multi-class SHAP attributions
        class_idx = 0
        canonical_classes = ["BENIGN", "DATA_EXFILTRATION", "PORT_SCAN", "SLOWLORIS", "SYN_FLOOD"]
        if hasattr(self.model, "classes_"):
            classes_list = list(self.model.classes_)
            if predicted_class in classes_list:
                class_idx = classes_list.index(predicted_class)
            elif isinstance(predicted_class, str) and predicted_class in canonical_classes:
                pos = canonical_classes.index(predicted_class)
                if pos < len(classes_list):
                    class_idx = pos
            elif isinstance(predicted_class, (int, np.integer)) and int(predicted_class) < len(classes_list):
                class_idx = int(predicted_class)
        elif isinstance(predicted_class, str) and predicted_class in canonical_classes:
            class_idx = canonical_classes.index(predicted_class)
        elif isinstance(predicted_class, (int, np.integer)):
            class_idx = int(predicted_class)

        proto = int(raw_feature_dict.get("proto", 6))
        pkt_count = int(raw_feature_dict.get("pkt_count", 1))
        duration = float(raw_feature_dict.get("duration", 0.0))

        tcp_flags_set = {"tcp_syn_cnt", "tcp_ack_cnt", "tcp_fin_cnt", "tcp_rst_cnt", "tcp_psh_cnt", "tcp_urg_cnt"}
        iat_metrics_set = {"iat_mean", "iat_std", "iat_min", "iat_max", "burstiness"}

        if self.explainer is not None:
            try:
                shap_values = self.explainer.shap_values(scaled_vector)
                # If multi-class, shap_values is a list of arrays per class, or 3D ndarray
                if isinstance(shap_values, list):
                    safe_idx = min(class_idx, len(shap_values) - 1)
                    target_arr = shap_values[safe_idx]
                    sv = target_arr[0] if target_arr.ndim >= 2 else target_arr
                elif isinstance(shap_values, np.ndarray):
                    if shap_values.ndim == 3:
                        # Shape: (n_samples, n_features, n_classes)
                        safe_idx = min(class_idx, shap_values.shape[2] - 1)
                        sv = shap_values[0, :, safe_idx]
                    elif shap_values.ndim == 2:
                        sv = shap_values[0]
                    else:
                        sv = shap_values
                else:
                    sv = np.zeros(len(self.feature_names))

                for idx, fname in enumerate(self.feature_names):
                    raw_val = raw_feature_dict.get(fname, 0.0)
                    impact = float(sv[idx])

                    # Contextual relevance filter:
                    # 1. Non-TCP protocols do not carry TCP flags; suppress them from explaining threats
                    if proto != 6 and fname in tcp_flags_set:
                        continue
                    # 2. Flows with <= 1 packet have no inter-arrival time or burstiness
                    if pkt_count <= 1 and fname in iat_metrics_set:
                        continue
                    # 3. For zero-duration single packet flows, rate features are 0.0 by definition
                    if duration <= 1e-6 and pkt_count <= 1 and fname in {"pkt_rate", "byte_rate"}:
                        continue

                    attributions.append((fname, raw_val, impact))

            except Exception:
                attributions = self._heuristic_attribution(raw_feature_dict, proto=proto, pkt_count=pkt_count)
        else:
            attributions = self._heuristic_attribution(raw_feature_dict, proto=proto, pkt_count=pkt_count)

        # Sort by absolute attribution impact descending
        attributions.sort(key=lambda x: abs(x[2]), reverse=True)

        top_explanations = []
        for fname, raw_val, score in attributions[:top_k]:
            meaning = self._format_feature_explanation(fname, raw_val, score, raw_feature_dict)
            top_explanations.append({
                "feature": fname,
                "value": round(raw_val, 3),
                "impact_score": round(score, 4),
                "direction": "RISK_INCREASING" if score >= 0 else "RISK_REDUCING",
                "explanation": meaning,
            })

        return top_explanations

    def _format_feature_explanation(
        self, fname: str, val: float, score: float, raw_features: Dict[str, float]
    ) -> str:
        """Formats a contextual human-readable explanation for a contributing feature."""
        if fname == "dst_port":
            return f"Target destination port {int(val)} indicates service-targeted activity"
        elif fname == "src_port":
            return f"Source ephemeral client port: {int(val)}"
        elif fname == "tcp_syn_cnt":
            return f"Isolated TCP SYN packets ({int(val)}) without completed handshake"
        elif fname == "tcp_ack_cnt":
            return f"Observed TCP ACK responses ({int(val)})"
        elif fname == "pkt_count":
            return f"Observed packet volume ({int(val)} packets)"
        elif fname == "byte_count":
            return f"Total data volume transferred ({int(val):,} bytes)"
        elif fname == "pkt_rate":
            return f"Packet transmission rate ({val:,.1f} pkts/s)"
        elif fname == "byte_rate":
            return f"Throughput consumption ({val:,.1f} bytes/s)"
        elif fname == "duration":
            return f"Flow observation duration ({val:.4f} s)"
        elif fname == "entropy_pkt_len":
            return f"Payload size entropy ({val:.2f}) - low value indicates automated or scripted pattern"
        elif fname == "burstiness":
            return f"Inter-arrival timing burstiness ({val:.2f})"
        elif fname == "pkt_len_mean":
            return f"Average packet size ({val:.1f} bytes)"
        else:
            desc = self.FEATURE_DESCRIPTIONS.get(fname, f"Behavioral metric {fname}")
            return f"{desc} (Value: {round(val, 2)})"

    def _heuristic_attribution(
        self, raw_features: Dict[str, float], proto: int = 6, pkt_count: int = 1
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
        tcp_flags_set = {"tcp_syn_cnt", "tcp_ack_cnt", "tcp_fin_cnt", "tcp_rst_cnt", "tcp_psh_cnt", "tcp_urg_cnt"}
        iat_metrics_set = {"iat_mean", "iat_std", "iat_min", "iat_max", "burstiness"}

        res = []
        for f, base in baseline_medians.items():
            if proto != 6 and f in tcp_flags_set:
                continue
            if pkt_count <= 1 and f in iat_metrics_set:
                continue
            val = raw_features.get(f, base)
            deviation = (val - base) / (base + 1e-4)
            res.append((f, val, deviation))
        return res
