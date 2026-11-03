"""Unsupervised Anomaly Detection Module for UniGuard AI.

Uses Isolation Forest to detect zero-day or out-of-distribution traffic patterns
that deviate from normal unidirectional baseline behavior.
"""

from typing import Dict, Any, List, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.utils.parallel import Parallel, delayed
from sklearn import get_config, config_context
import joblib


class IsolationForestAnomalyDetector:
    """Unsupervised anomaly detector for unidirectional flow patterns."""

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1,
        )
        self.is_fitted: bool = False

    def fit(self, X_train: np.ndarray) -> "IsolationForestAnomalyDetector":
        """Fits the isolation forest on benign or representative traffic baseline."""
        self.model.fit(X_train)
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predicts anomaly status: -1 for anomaly, 1 for inlier/normal."""
        with config_context(**get_config()):
            if hasattr(self.model, "n_jobs") and getattr(X, "shape", [0])[0] == 1 and getattr(self.model, "n_jobs", 1) != 1:
                orig_jobs = self.model.n_jobs
                self.model.n_jobs = 1
                try:
                    return self.model.predict(X)
                finally:
                    self.model.n_jobs = orig_jobs
            return self.model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Returns normalized anomaly score in [0.0, 1.0].
        
        Raw score is typically between -0.5 and 0.5 where lower = more anomalous.
        We invert and normalize so that 1.0 = maximum anomaly, 0.0 = completely normal.
        """
        with config_context(**get_config()):
            if hasattr(self.model, "n_jobs") and getattr(X, "shape", [0])[0] == 1 and getattr(self.model, "n_jobs", 1) != 1:
                orig_jobs = self.model.n_jobs
                self.model.n_jobs = 1
                try:
                    raw_scores = self.model.score_samples(X)
                finally:
                    self.model.n_jobs = orig_jobs
            else:
                raw_scores = self.model.score_samples(X)  # opposite of anomaly score
        # Normal range is ~ -0.2 to -0.8 in sklearn
        # Map: score in [-0.8, -0.2] -> [1.0, 0.0]
        norm_scores = np.clip((-raw_scores - 0.3) / 0.5, 0.0, 1.0)
        return norm_scores

    def evaluate_sample(self, x: np.ndarray) -> Dict[str, Any]:
        """Evaluates a single flow vector."""
        if x.ndim == 1:
            x = x.reshape(1, -1)
        is_inlier = int(self.model.predict(x)[0]) == 1
        anomaly_score = float(self.score_samples(x)[0])
        return {
            "is_anomaly": not is_inlier,
            "anomaly_score": round(anomaly_score, 4),
            "severity": "HIGH" if anomaly_score >= 0.7 else ("MEDIUM" if anomaly_score >= 0.4 else "LOW"),
        }

    def save(self, filepath: str) -> None:
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: str) -> "IsolationForestAnomalyDetector":
        return joblib.load(filepath)
