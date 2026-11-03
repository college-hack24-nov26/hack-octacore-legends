"""Unsupervised Flow Directionality and Asymmetry Engine.

Learns traffic structure without manual labels using Isolation Forest and
behavioral clustering (K-Means / archetype mapping).
Strictly separates traffic directionality from security threat classification.
"""

from __future__ import annotations

import os
import json
import joblib
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import RobustScaler

from uniguard.directionality.asymmetry_engine import AsymmetryEngine, DIRECTIONALITY_FEATURE_NAMES
from uniguard.directionality.heuristics import HeuristicBaselineComparator


class FlowObservationState(Enum):
    """Lifecycle state of flow observation window (Task 8)."""
    UNKNOWN = "UNKNOWN"           # 1-2 packets, insufficient evidence
    OBSERVING = "OBSERVING"       # Accumulating directional evidence
    CANDIDATE = "CANDIDATE"       # Minimum packet/duration thresholds reached
    CLASSIFIED = "CLASSIFIED"     # Directionality engine committed to state


class DirectionalityState(Enum):
    """Behavioral directionality classification (Task 10 - NOT security threat)."""
    BIDIRECTIONAL = "BIDIRECTIONAL"                     # Symmetric or normal conversational
    ASYMMETRIC = "ASYMMETRIC"                           # Moderate asymmetry, reverse traffic present
    STRONGLY_ASYMMETRIC = "STRONGLY_ASYMMETRIC"         # Heavy asymmetry, sparse reverse traffic
    UNIDIRECTIONAL_OBSERVED = "UNIDIRECTIONAL_OBSERVED" # Pure or near pure one-way traffic
    UNKNOWN = "UNKNOWN"                                 # Insufficient observation


class EngineOperationalMode(Enum):
    """Operational mode for environment baseline learning (Task 14)."""
    LEARNING = "LEARNING"       # Accumulates baseline traffic in memory to fit models
    MONITORING = "MONITORING"   # Active inference using fitted baseline models
    ADAPTIVE = "ADAPTIVE"       # Active inference + rolling online background updates


class DirectionalityResult:
    """Standardized output of the directionality engine."""

    def __init__(
        self,
        state: DirectionalityState,
        score: float,
        confidence: float,
        observation_state: FlowObservationState,
        features: Dict[str, float],
        is_excluded_from_unidirectional_security: bool,
        explanation_bullets: List[str],
        baseline_5_20: Dict[str, Any],
    ) -> None:
        self.state = state
        self.score = float(np.clip(score, 0.0, 1.0))
        self.confidence = float(np.clip(confidence, 0.0, 1.0))
        self.observation_state = observation_state
        self.features = features
        self.is_excluded_from_unidirectional_security = is_excluded_from_unidirectional_security
        self.explanation_bullets = explanation_bullets
        self.baseline_5_20 = baseline_5_20

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "score": round(self.score, 4),
            "confidence": round(self.confidence, 4),
            "observation_state": self.observation_state.value,
            "is_excluded": self.is_excluded_from_unidirectional_security,
            "explanation": self.explanation_bullets,
            "baseline_5_20": self.baseline_5_20,
            "features": {k: round(v, 4) for k, v in self.features.items()},
        }


class UnsupervisedDirectionalityEngine:
    """Core unsupervised engine analyzing conversation directionality."""

    def __init__(
        self,
        min_packets: int = 3,
        min_duration_sec: float = 0.05,
        mode: EngineOperationalMode = EngineOperationalMode.MONITORING,
        models_dir: str = "models_saved",
    ) -> None:
        self.min_packets = min_packets
        self.min_duration_sec = min_duration_sec
        self.mode = mode
        self.models_dir = models_dir

        self.scaler: Optional[RobustScaler] = None
        self.isolation_forest: Optional[IsolationForest] = None
        self.kmeans_clusterer: Optional[KMeans] = None

        self.is_fitted: bool = False
        self.learning_buffer: List[np.ndarray] = []
        self.max_learning_samples: int = 5000

        self._try_load_models()

    def _try_load_models(self) -> None:
        """Attempts to load pre-trained directionality models if present."""
        scaler_path = os.path.join(self.models_dir, "directionality_scaler.joblib")
        if_path = os.path.join(self.models_dir, "directionality_isolation_forest.joblib")
        kmeans_path = os.path.join(self.models_dir, "directionality_kmeans.joblib")

        if os.path.exists(scaler_path) and os.path.exists(if_path):
            try:
                self.scaler = joblib.load(scaler_path)
                self.isolation_forest = joblib.load(if_path)
                if os.path.exists(kmeans_path):
                    self.kmeans_clusterer = joblib.load(kmeans_path)
                self.is_fitted = True
            except Exception:
                self.is_fitted = False

    def save_models(self) -> None:
        """Saves fitted baseline models to disk."""
        os.makedirs(self.models_dir, exist_ok=True)
        if self.scaler is not None:
            joblib.dump(self.scaler, os.path.join(self.models_dir, "directionality_scaler.joblib"))
        if self.isolation_forest is not None:
            joblib.dump(self.isolation_forest, os.path.join(self.models_dir, "directionality_isolation_forest.joblib"))
        if self.kmeans_clusterer is not None:
            joblib.dump(self.kmeans_clusterer, os.path.join(self.models_dir, "directionality_kmeans.joblib"))

    def evaluate_flow(
        self,
        features: Dict[str, float],
        is_flow_closed: bool = False,
    ) -> DirectionalityResult:
        """Evaluates directionality state, score, confidence, and exclusion gate for a flow.

        Args:
            features: Directionality feature dictionary from AsymmetryEngine.
            is_flow_closed: True if flow has concluded via timeout or FIN/RST.
        """
        fwd_pkts = int(features.get("forward_packet_count", 0))
        rev_pkts = int(features.get("reverse_packet_count", 0))
        total_pkts = fwd_pkts + rev_pkts
        duration = features.get("duration", 0.0)

        # 5/20 baseline evaluation (Task 13)
        baseline_comparison = HeuristicBaselineComparator.compare_with_unsupervised(
            forward_packets=fwd_pkts,
            reverse_packets=rev_pkts,
            unsupervised_state="UNKNOWN",
            unsupervised_score=0.0,
        )

        # -------------------------------------------------------------
        # Step 1: Minimum Observation Lifecycle (Task 8)
        # -------------------------------------------------------------
        if not is_flow_closed and (total_pkts < self.min_packets and duration < self.min_duration_sec):
            return DirectionalityResult(
                state=DirectionalityState.UNKNOWN,
                score=0.0,
                confidence=0.1,
                observation_state=FlowObservationState.UNKNOWN,
                features=features,
                is_excluded_from_unidirectional_security=True, # Do not alert on premature 1-2 packets
                explanation_bullets=["Insufficient observation: Flow is still in initial accumulation state."],
                baseline_5_20=baseline_comparison["baseline_5_20"],
            )

        obs_state = FlowObservationState.CLASSIFIED if (total_pkts >= 10 or is_flow_closed) else FlowObservationState.CANDIDATE

        # -------------------------------------------------------------
        # Step 2: Learning Buffer Accumulation (Task 14)
        # -------------------------------------------------------------
        vec = AsymmetryEngine.to_vector(features).reshape(1, -1)
        if self.mode == EngineOperationalMode.LEARNING:
            if len(self.learning_buffer) < self.max_learning_samples:
                self.learning_buffer.append(vec.flatten())
            if len(self.learning_buffer) >= 200 and not self.is_fitted:
                self.fit_baseline(np.array(self.learning_buffer))

        # -------------------------------------------------------------
        # Step 3: Statistical Directionality Formulation
        # -------------------------------------------------------------
        ap = features.get("packet_asymmetry", 0.0)
        ab = features.get("byte_asymmetry", 0.0)
        rev_presence = features.get("reverse_presence", 0.0)
        rev_ack_ratio = features.get("reverse_ack_ratio", 0.0)
        burst_transitions = features.get("burst_transition_rate", 0.0)
        tcp_handshake = features.get("tcp_handshake_presence", 0.0)

        # Directionality continuous score (0.0 = balanced, 1.0 = purely unidirectional)
        # Weighted combination of packet asymmetry, lack of reverse presence, and lack of burst transitions
        raw_score = (
            0.45 * ap
            + 0.25 * (1.0 - rev_presence)
            + 0.15 * (1.0 - min(1.0, burst_transitions * 2.5))
            + 0.15 * (1.0 - min(1.0, rev_ack_ratio))
        )

        # Handling normal download problem (Task 12):
        # In a normal download: byte asymmetry Ab is high (~0.95), and packet asymmetry Ap may be ~0.80
        # BUT reverse ACK ratio is high, reverse presence is 1.0, and TCP handshake occurred!
        # This reduces the score significantly back towards balanced / conversational!
        if rev_presence > 0.0 and (rev_ack_ratio > 0.20 or burst_transitions > 0.05):
            raw_score *= 0.35 # Strong attenuation for conversational downloads/streaming!

        directionality_score = float(np.clip(raw_score, 0.0, 1.0))

        # -------------------------------------------------------------
        # Step 4: Unsupervised Outlier / Cluster Adjustment (Task 9)
        # -------------------------------------------------------------
        anomaly_factor = 0.0
        if self.is_fitted and self.scaler is not None and self.isolation_forest is not None:
            try:
                scaled_v = self.scaler.transform(vec)
                # Isolation Forest decision_function: lower means more anomalous (outlier directionality)
                raw_decision = float(self.isolation_forest.decision_function(scaled_v)[0])
                # Normalize decision to [0, 1] anomaly factor
                anomaly_factor = float(np.clip(0.5 - (raw_decision * 1.5), 0.0, 1.0))
            except Exception:
                anomaly_factor = 0.0

        # Adjust score slightly based on unsupervised outlier detection
        if anomaly_factor > 0.65 and rev_presence == 0.0:
            directionality_score = min(1.0, directionality_score * 1.2)

        # -------------------------------------------------------------
        # Step 5: Confidence Calculation (Task 15)
        # -------------------------------------------------------------
        # Confidence increases with packet count, duration, and closure
        vol_conf = min(1.0, total_pkts / 25.0)
        dur_conf = min(1.0, duration / 2.0)
        closed_conf = 0.2 if is_flow_closed else 0.0
        confidence = min(1.0, (vol_conf * 0.5) + (dur_conf * 0.3) + closed_conf)

        # -------------------------------------------------------------
        # Step 6: Assign Directionality State & Exclusion Gate (Task 10 & 11)
        # -------------------------------------------------------------
        explanation = []

        if rev_pkts == 0:
            state = DirectionalityState.UNIDIRECTIONAL_OBSERVED
            explanation.append("Zero reverse packets observed across the entire flow duration.")
            explanation.append(f"Forward direction transmitted {fwd_pkts:,} packets ({features.get('forward_byte_count', 0):,.0f} bytes).")
            is_excluded = False # Route to security pipeline
        elif directionality_score >= 0.75:
            state = DirectionalityState.STRONGLY_ASYMMETRIC
            explanation.append(f"Severe packet and burst imbalance (Ap={ap:.2f}, Transitions={burst_transitions:.3f}).")
            explanation.append(f"Forward packets: {fwd_pkts:,}, Reverse packets: {rev_pkts:,}.")
            is_excluded = False # Route to security pipeline
        elif directionality_score >= 0.45:
            state = DirectionalityState.ASYMMETRIC
            explanation.append(f"Moderate directional asymmetry (Ap={ap:.2f}, Reverse ACKs present: {rev_ack_ratio:.2f}).")
            is_excluded = False # Route to security pipeline
        else:
            state = DirectionalityState.BIDIRECTIONAL
            explanation.append("Balanced bidirectional communication or normal request-response exchange.")
            explanation.append(f"Reverse ACK coverage: {rev_ack_ratio:.2f}, Burst transitions: {burst_transitions:.2f}.")
            is_excluded = True # Exclude from unidirectional security analysis!

        # Update baseline comparison with final unsupervised state
        final_baseline = HeuristicBaselineComparator.compare_with_unsupervised(
            forward_packets=fwd_pkts,
            reverse_packets=rev_pkts,
            unsupervised_state=state.value,
            unsupervised_score=directionality_score,
        )

        return DirectionalityResult(
            state=state,
            score=directionality_score,
            confidence=confidence,
            observation_state=obs_state,
            features=features,
            is_excluded_from_unidirectional_security=is_excluded,
            explanation_bullets=explanation,
            baseline_5_20=final_baseline,
        )

    def fit_baseline(self, X_feature_vectors: np.ndarray) -> None:
        """Trains unsupervised Isolation Forest and K-Means models on normal baseline traffic."""
        if len(X_feature_vectors) < 20:
            return

        self.scaler = RobustScaler()
        X_scaled = self.scaler.fit_transform(X_feature_vectors)

        # Train Isolation Forest on directional features
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        self.isolation_forest.fit(X_scaled)

        # Train K-Means (4 archetypes: Balanced, Normal Asym, High Asym, One-way)
        self.kmeans_clusterer = KMeans(n_clusters=4, random_state=42, n_init=5)
        self.kmeans_clusterer.fit(X_scaled)

        self.is_fitted = True
        self.save_models()
