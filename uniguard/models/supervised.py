"""Supervised Threat Classification Models for UniGuard AI.

Implements Random Forest (Baseline) and XGBoost (Advanced) multi-class classifiers.
Provides evaluation methods computing Precision, Recall, F1-score, False Positive Rate (FPR),
False Negative Rate (FNR), confusion matrices, and inference latency.
"""

from typing import Dict, Any, List, Optional, Tuple
import time
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.utils.parallel import Parallel, delayed
from sklearn import get_config, config_context
import joblib

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False


class SupervisedThreatClassifier:
    """Wrapper for supervised threat classification models."""

    def __init__(self, model_type: str = "random_forest", **kwargs: Any) -> None:
        self.model_type = model_type.lower()
        self.classes_: Optional[np.ndarray] = None
        self.feature_names: Optional[List[str]] = None

        if self.model_type == "random_forest":
            rf_params = {
                "n_estimators": 100,
                "max_depth": 16,
                "min_samples_split": 5,
                "random_state": 42,
                "n_jobs": -1,
            }
            rf_params.update(kwargs)
            self.model = RandomForestClassifier(**rf_params)

        elif self.model_type == "xgboost":
            if not XGB_AVAILABLE:
                raise ImportError("xgboost is not installed. Run 'pip install xgboost'")
            xgb_params = {
                "n_estimators": 100,
                "max_depth": 6,
                "learning_rate": 0.1,
                "random_state": 42,
                "eval_metric": "mlogloss",
                "n_jobs": -1,
            }
            xgb_params.update(kwargs)
            self.model = xgb.XGBClassifier(**xgb_params)

        else:
            raise ValueError(f"Unsupported model_type: '{model_type}'. Choose 'random_forest' or 'xgboost'.")

    def train(self, X: np.ndarray, y: np.ndarray, feature_names: Optional[List[str]] = None) -> None:
        """Fits the supervised model on training features and labels."""
        self.feature_names = feature_names
        self.model.fit(X, y)
        self.classes_ = np.unique(y)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predicts class labels for input feature matrix."""
        with config_context(**get_config()):
            if hasattr(self.model, "n_jobs") and getattr(X, "shape", [0])[0] == 1 and getattr(self.model, "n_jobs", 1) != 1:
                orig_jobs = self.model.n_jobs
                self.model.n_jobs = 1
                try:
                    return self.model.predict(X)
                finally:
                    self.model.n_jobs = orig_jobs
            return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predicts class probability distributions."""
        with config_context(**get_config()):
            if hasattr(self.model, "n_jobs") and getattr(X, "shape", [0])[0] == 1 and getattr(self.model, "n_jobs", 1) != 1:
                orig_jobs = self.model.n_jobs
                self.model.n_jobs = 1
                try:
                    return self.model.predict_proba(X)
                finally:
                    self.model.n_jobs = orig_jobs
            return self.model.predict_proba(X)

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Comprehensive cybersecurity evaluation of model performance.

        Computes:
        - Weighted and Macro Precision, Recall, F1
        - Per-class metrics
        - Confusion Matrix
        - False Positive Rate (FPR) and False Negative Rate (FNR)
        - Mean inference latency per sample (microseconds)
        """
        start_t = time.perf_counter()
        y_pred = self.predict(X_test)
        inference_latency_ms = ((time.perf_counter() - start_t) / len(X_test)) * 1000.0

        p_micro, r_micro, f1_micro, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)
        p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred, average="macro", zero_division=0)

        cm = confusion_matrix(y_test, y_pred)

        # False Positive Rate (FPR) and False Negative Rate (FNR)
        # For multi-class, compute one-vs-rest FPR and FNR
        fp = cm.sum(axis=0) - np.diag(cm)
        fn = cm.sum(axis=1) - np.diag(cm)
        tp = np.diag(cm)
        tn = cm.sum() - (fp + fn + tp)

        with np.errstate(divide="ignore", invalid="ignore"):
            fpr_per_class = np.where((fp + tn) > 0, fp / (fp + tn), 0.0)
            fnr_per_class = np.where((tp + fn) > 0, fn / (tp + fn), 0.0)

        mean_fpr = float(np.mean(fpr_per_class))
        mean_fnr = float(np.mean(fnr_per_class))

        report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        return {
            "model_type": self.model_type,
            "weighted_precision": float(p_micro),
            "weighted_recall": float(r_micro),
            "weighted_f1": float(f1_micro),
            "macro_precision": float(p_macro),
            "macro_recall": float(r_macro),
            "macro_f1": float(f1_macro),
            "mean_fpr": mean_fpr,
            "mean_fnr": mean_fnr,
            "inference_latency_ms_per_flow": float(inference_latency_ms),
            "confusion_matrix": cm.tolist(),
            "per_class_report": report_dict,
        }

    def get_feature_importances(self) -> Dict[str, float]:
        """Returns Gini / Gain feature importances mapped to feature names."""
        if self.feature_names is None:
            return {}
        importances = self.model.feature_importances_
        return dict(zip(self.feature_names, [float(x) for x in importances]))

    def save(self, filepath: str) -> None:
        """Persists trained model and metadata."""
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: str) -> "SupervisedThreatClassifier":
        """Loads trained model from file."""
        return joblib.load(filepath)
