"""Model Training and Calibration Script for UniGuard AI.

Trains and persists:
1. FlowDataPreprocessor (RobustScaler + LabelEncoder)
2. Supervised Threat Classifier (Random Forest)
3. Supervised Threat Classifier (XGBoost)
4. Unsupervised Anomaly Detector (Isolation Forest)
5. SHAP Explainer Cache
"""

import os
import sys
import json
import numpy as np
import pandas as pd

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sklearn.model_selection import train_test_split
from uniguard.features.schema import UNIDIRECTIONAL_FEATURES
from uniguard.preprocessing.pipeline import FlowDataPreprocessor
from uniguard.models.supervised import SupervisedThreatClassifier
from uniguard.models.anomaly import IsolationForestAnomalyDetector
from scripts.run_unidirectional_experiment import generate_benchmark_dataset


def train_and_persist_all_models(models_dir: str = "models_saved") -> None:
    os.makedirs(models_dir, exist_ok=True)

    print("=" * 80)
    print(" UNIGUARD AI: TRAINING DUAL-ENGINE AI SUITE")
    print(" (Supervised RF + Supervised XGB + Unsupervised Isolation Forest)")
    print("=" * 80)

    # 1. Generate clean training corpus
    print("[*] Generating training flow corpus...")
    df = generate_benchmark_dataset(n_samples=6000, random_seed=123)
    train_df, val_df = train_test_split(df, test_size=0.25, random_state=42, stratify=df["label"])

    X_train_raw = train_df[UNIDIRECTIONAL_FEATURES]
    y_train_raw = train_df["label"]
    X_val_raw = val_df[UNIDIRECTIONAL_FEATURES]
    y_val_raw = val_df["label"]

    # 2. Fit and persist Preprocessor
    print("[*] Fitting FlowDataPreprocessor (RobustScaler)...")
    preprocessor = FlowDataPreprocessor()
    X_train_scaled, y_train_enc = preprocessor.fit_transform(X_train_raw, y_train_raw)
    X_val_scaled = preprocessor.transform_features(X_val_raw)
    y_val_enc = preprocessor.label_encoder.transform(y_val_raw)

    preprocessor_path = os.path.join(models_dir, "preprocessor.joblib")
    preprocessor.save(preprocessor_path)
    print(f"[OK] Saved Preprocessor to: {preprocessor_path}")

    # 3. Train Random Forest Classifier
    print("[*] Training Supervised Random Forest Classifier...")
    rf_classifier = SupervisedThreatClassifier(
        model_type="random_forest",
        n_estimators=120,
        max_depth=16,
        random_state=42,
    )
    rf_classifier.train(X_train_scaled, y_train_enc, feature_names=list(UNIDIRECTIONAL_FEATURES))
    rf_metrics = rf_classifier.evaluate(X_val_scaled, y_val_enc)
    rf_path = os.path.join(models_dir, "uniguard_rf_model.joblib")
    rf_classifier.save(rf_path)
    print(f"[OK] Random Forest F1: {rf_metrics['weighted_f1']*100:.2f}% | Latency: {rf_metrics['inference_latency_ms_per_flow']*1000:.1f} us")
    print(f"[OK] Saved Random Forest model to: {rf_path}")

    # 4. Train XGBoost Classifier
    print("[*] Training Supervised XGBoost Classifier...")
    xgb_classifier = SupervisedThreatClassifier(
        model_type="xgboost",
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
    )
    xgb_classifier.train(X_train_scaled, y_train_enc, feature_names=list(UNIDIRECTIONAL_FEATURES))
    xgb_metrics = xgb_classifier.evaluate(X_val_scaled, y_val_enc)
    xgb_path = os.path.join(models_dir, "uniguard_xgb_model.joblib")
    xgb_classifier.save(xgb_path)
    print(f"[OK] XGBoost F1: {xgb_metrics['weighted_f1']*100:.2f}% | Latency: {xgb_metrics['inference_latency_ms_per_flow']*1000:.1f} us")
    print(f"[OK] Saved XGBoost model to: {xgb_path}")

    # 5. Train Isolation Forest Anomaly Detector on Benign Baseline
    print("[*] Training Isolation Forest Anomaly Detector on Benign baseline...")
    benign_mask = train_df["label"] == "BENIGN"
    X_train_benign = preprocessor.transform_features(train_df[benign_mask][UNIDIRECTIONAL_FEATURES])

    anomaly_detector = IsolationForestAnomalyDetector(
        contamination=0.04,
        n_estimators=100,
        random_state=42,
    )
    anomaly_detector.fit(X_train_benign)
    anomaly_path = os.path.join(models_dir, "uniguard_isolation_forest.joblib")
    anomaly_detector.save(anomaly_path)
    print(f"[OK] Saved Isolation Forest model to: {anomaly_path}")

    # Save class label mapping metadata
    label_classes = list(preprocessor.label_encoder.classes_)
    metadata = {
        "classes": label_classes,
        "features": list(UNIDIRECTIONAL_FEATURES),
        "rf_f1": rf_metrics["weighted_f1"],
        "xgb_f1": xgb_metrics["weighted_f1"],
    }
    with open(os.path.join(models_dir, "model_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    print("=" * 80)
    print(" ALL MODELS TRAINED, VALIDATED, AND PERSISTED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    train_and_persist_all_models()
