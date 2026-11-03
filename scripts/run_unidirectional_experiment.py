"""The Flagship Unidirectional Benchmark Experiment for UniGuard AI.

Smart India Hackathon (SIH) 2026 - Major Scientific Differentiator.

Scientifically evaluates and compares:
1. Scenario A: Traditional Bidirectional Model (trained on forward + backward features)
2. Scenario A Failure Mode: Traditional Model deployed on a Unidirectional Tap (backward features missing/zeroed)
3. Scenario B: UniGuard AI Strict Unidirectional Model (trained exclusively on 24 forward behavioral features)

Computes Precision, Recall, F1, FPR, FNR, and Latency to demonstrate why UniGuard AI
is essential for data diodes and asymmetric network monitoring.
"""

import os
import sys
import json
import time
from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sklearn.model_selection import train_test_split
from uniguard.features.schema import UNIDIRECTIONAL_FEATURES, PROHIBITED_BIDIRECTIONAL_FEATURES
from uniguard.models.supervised import SupervisedThreatClassifier
from uniguard.preprocessing.pipeline import FlowDataPreprocessor


def generate_benchmark_dataset(n_samples: int = 5000, random_seed: int = 42) -> pd.DataFrame:
    """Generates a statistically realistic cybersecurity benchmark flow dataset.
    
    Contains multi-class distribution:
    - BENIGN (Web HTTPS, DNS queries, SSH)
    - PORT_SCAN (Rapid probes across ports, 1 packet, no reverse data)
    - SYN_FLOOD (Extreme packet rates, pure SYN flags)
    - UDP_FLOOD (High rate UDP packets, zero flags)
    - DATA_EXFILTRATION (Bursty large packets egressing)
    """
    np.random.seed(random_seed)
    records = []

    classes = ["BENIGN", "DATA_EXFILTRATION", "SLOWLORIS", "PORT_SCAN", "SYN_FLOOD"]
    samples_per_class = n_samples // len(classes)

    for label in classes:
        for _ in range(samples_per_class):
            if label == "BENIGN":
                proto = 6
                # 50% client browsing requests, 50% inbound server bulk downloads
                if np.random.rand() > 0.5:
                    # Inbound server download (Server -> Client)
                    src_port = np.random.choice([80, 443, 8080, 8443])
                    dst_port = np.random.randint(1024, 65535)
                    pkt_count = np.random.randint(100, 5000)
                    duration = np.random.uniform(2.0, 30.0)
                    pkt_len_mean = np.random.uniform(1200, 1460) # MTU saturation
                    pkt_len_std = np.random.uniform(50, 150)
                    pkt_len_min = 64.0
                    pkt_len_max = 1500.0
                    tcp_psh = float(np.random.randint(10, 50))
                else:
                    # Outbound client web browsing (Client -> Server)
                    dst_port = np.random.choice([80, 443, 8080, 8443])
                    src_port = np.random.randint(1024, 65535)
                    pkt_count = np.random.randint(50, 200)
                    duration = np.random.uniform(1.0, 8.0)
                    pkt_len_mean = np.random.uniform(80, 250) # Client ACKs/GETs
                    pkt_len_std = np.random.uniform(10, 50)
                    pkt_len_min = 40.0
                    pkt_len_max = 600.0
                    tcp_psh = float(np.random.randint(2, 6))

                iat_mean = duration / pkt_count
                iat_std = iat_mean * 0.4
                iat_min = 0.0001
                iat_max = iat_mean * 2.0
                tcp_syn = 1.0
                tcp_ack = float(pkt_count - 1)
                entropy = 1.8
                burstiness = 0.4

                bwd_pkts = float(pkt_count * 0.5)
                bwd_bytes = bwd_pkts * 100.0
                fwd_bwd_ratio = pkt_count / max(1.0, bwd_pkts)
                syn_ack_rtt = np.random.uniform(0.015, 0.040)
                init_win_backward = 65535.0

            elif label == "DATA_EXFILTRATION":
                # Attacker exfiltrating data disguised as HTTPS
                proto = 6
                dst_port = 443
                src_port = np.random.randint(1024, 65535)
                pkt_count = np.random.randint(50, 150)
                duration = np.random.uniform(2.0, 8.0)
                # Notice: Exfiltration sends large payload forward!
                pkt_len_mean = np.random.uniform(1200, 1460)
                pkt_len_std = np.random.uniform(50, 150)
                pkt_len_min = 40.0
                pkt_len_max = 1500.0
                iat_mean = duration / pkt_count
                iat_std = iat_mean * np.random.uniform(0.8, 1.8) # High jitter
                iat_min = 0.0001
                iat_max = iat_mean * 3.5
                tcp_syn = 1.0
                tcp_ack = float(pkt_count - 1)
                tcp_psh = float(pkt_count // 3)
                entropy = 3.8
                burstiness = iat_std / (iat_mean + 1e-6)

                # Target server only sends tiny TCP ACKs back
                bwd_pkts = float(pkt_count * 0.3)
                bwd_bytes = bwd_pkts * 54.0
                fwd_bwd_ratio = pkt_count / max(1.0, bwd_pkts)
                syn_ack_rtt = np.random.uniform(0.020, 0.050)
                init_win_backward = 14600.0

            elif label == "SLOWLORIS":
                # Subtle HTTP Denial of Service: slow transmission mimicking benign HTTP
                proto = 6
                dst_port = 80
                src_port = np.random.randint(1024, 65535)
                pkt_count = np.random.randint(12, 35)
                duration = np.random.uniform(15.0, 45.0)  # Very long duration
                pkt_len_mean = np.random.uniform(50, 120) # Small partial headers
                pkt_len_std = np.random.uniform(2, 15)
                pkt_len_min = 40.0
                pkt_len_max = 200.0
                iat_mean = duration / max(1, pkt_count)   # High IAT (slow drip)
                iat_std = iat_mean * 0.15
                iat_min = iat_mean * 0.8
                iat_max = iat_mean * 1.2
                tcp_syn = 1.0
                tcp_ack = float(pkt_count - 1)
                tcp_psh = float(pkt_count - 1)
                entropy = 0.6
                burstiness = 0.15

                # Server stalls; bwd packets are near zero in Slowloris
                bwd_pkts = float(np.random.choice([0, 1, 2]))
                bwd_bytes = bwd_pkts * 54.0
                fwd_bwd_ratio = pkt_count / max(1.0, bwd_pkts)
                syn_ack_rtt = np.random.uniform(0.200, 0.800) # Severely delayed
                init_win_backward = 14600.0

            elif label == "PORT_SCAN":
                proto = 6
                dst_port = np.random.randint(1, 1024)
                src_port = np.random.randint(1024, 65535)
                pkt_count = 1
                duration = 0.0001
                pkt_len_mean = 44.0
                pkt_len_std = 0.0
                pkt_len_min = 44.0
                pkt_len_max = 44.0
                iat_mean = 0.0
                iat_std = 0.0
                iat_min = 0.0
                iat_max = 0.0
                tcp_syn = 1.0
                tcp_ack = 0.0
                tcp_psh = 0.0
                entropy = 0.0
                burstiness = 0.0

                # Bidirectional artifacts (Target closes or drops, no bwd traffic)
                bwd_pkts = 0.0
                bwd_bytes = 0.0
                fwd_bwd_ratio = 10.0
                syn_ack_rtt = 0.0
                init_win_backward = 0.0

            elif label == "SYN_FLOOD":
                proto = 6
                dst_port = np.random.choice([80, 443, 8080])
                src_port = np.random.randint(1024, 65535)
                pkt_count = np.random.randint(50, 500)
                duration = np.random.uniform(0.05, 0.5)
                pkt_len_mean = 54.0
                pkt_len_std = 2.0
                pkt_len_min = 54.0
                pkt_len_max = 60.0
                iat_mean = duration / pkt_count
                iat_std = iat_mean * 0.1
                iat_min = iat_mean * 0.5
                iat_max = iat_mean * 1.5
                tcp_syn = float(pkt_count)
                tcp_ack = 0.0
                tcp_psh = 0.0
                entropy = 0.05
                burstiness = 0.1

                bwd_pkts = 0.0
                bwd_bytes = 0.0
                fwd_bwd_ratio = 100.0
                syn_ack_rtt = 0.0
                init_win_backward = 0.0

            elif label == "UDP_FLOOD":
                proto = 17
                dst_port = np.random.choice([53, 123, 1900])
                src_port = np.random.randint(1024, 65535)
                pkt_count = np.random.randint(80, 600)
                duration = np.random.uniform(0.1, 0.8)
                pkt_len_mean = np.random.uniform(500, 1200)
                pkt_len_std = np.random.uniform(10, 50)
                pkt_len_min = 400.0
                pkt_len_max = 1400.0
                iat_mean = duration / pkt_count
                iat_std = iat_mean * 0.05
                iat_min = iat_mean * 0.8
                iat_max = iat_mean * 1.2
                tcp_syn = 0.0
                tcp_ack = 0.0
                tcp_psh = 0.0
                entropy = 1.2
                burstiness = 0.05

                bwd_pkts = 0.0
                bwd_bytes = 0.0
                fwd_bwd_ratio = 500.0
                syn_ack_rtt = 0.0
                init_win_backward = 0.0

            elif label == "DATA_EXFILTRATION":
                proto = 6
                dst_port = np.random.choice([443, 8443, 9001])
                src_port = np.random.randint(1024, 65535)
                pkt_count = np.random.randint(100, 1000)
                duration = np.random.uniform(1.0, 5.0)
                pkt_len_mean = 1420.0
                pkt_len_std = 15.0
                pkt_len_min = 1350.0
                pkt_len_max = 1500.0
                iat_mean = duration / pkt_count
                iat_std = iat_mean * np.random.uniform(0.8, 1.5)
                iat_min = 0.0001
                iat_max = iat_mean * 4.0
                tcp_syn = 1.0
                tcp_ack = float(pkt_count - 1)
                tcp_psh = float(pkt_count // 2)
                entropy = 0.8
                burstiness = iat_std / (iat_mean + 1e-6)

                bwd_pkts = float(np.random.randint(5, 20)) # Asymmetric, small ACKs
                bwd_bytes = bwd_pkts * 54.0
                fwd_bwd_ratio = pkt_count / max(1.0, bwd_pkts)
                syn_ack_rtt = np.random.uniform(0.02, 0.05)
                init_win_backward = 29200.0

            byte_count = pkt_count * pkt_len_mean
            pkt_rate = pkt_count / max(1e-5, duration)
            byte_rate = byte_count / max(1e-5, duration)

            record = {
                # 24 Unidirectional Features
                "proto": proto,
                "dst_port": dst_port,
                "src_port": src_port,
                "pkt_count": pkt_count,
                "byte_count": byte_count,
                "duration": duration,
                "pkt_rate": pkt_rate,
                "byte_rate": byte_rate,
                "pkt_len_mean": pkt_len_mean,
                "pkt_len_std": pkt_len_std,
                "pkt_len_min": pkt_len_min,
                "pkt_len_max": pkt_len_max,
                "iat_mean": iat_mean,
                "iat_std": iat_std,
                "iat_min": iat_min,
                "iat_max": iat_max,
                "tcp_syn_cnt": tcp_syn,
                "tcp_psh_cnt": tcp_psh,
                "tcp_ack_cnt": tcp_ack,
                "tcp_fin_cnt": 0.0,
                "tcp_rst_cnt": 0.0,
                "tcp_urg_cnt": 0.0,
                "entropy_pkt_len": entropy,
                "burstiness": burstiness,
                # 5 Prohibited Bidirectional Features (for Scenario A comparison)
                "bwd_pkt_count": bwd_pkts,
                "bwd_byte_count": bwd_bytes,
                "fwd_bwd_ratio": fwd_bwd_ratio,
                "syn_ack_latency_rtt": syn_ack_rtt,
                "init_win_bytes_backward": init_win_backward,
                # Target
                "label": label,
            }
            records.append(record)

    df = pd.DataFrame(records)
    return df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)


def run_unidirectional_experiment() -> Dict[str, Any]:
    print("=" * 85)
    print(" UNIGUARD AI: SCIENTIFIC UNIDIRECTIONAL BENCHMARK EXPERIMENT")
    print(" Smart India Hackathon (SIH) 2026 - Major Research Contribution")
    print("=" * 85)

    df = generate_benchmark_dataset(n_samples=5000)
    print(f"[*] Benchmark dataset generated: {len(df)} flows across 5 classes.")

    train_df, test_df = train_test_split(df, test_size=0.30, random_state=42, stratify=df["label"])

    bwd_features = ["bwd_pkt_count", "bwd_byte_count", "fwd_bwd_ratio", "syn_ack_latency_rtt", "init_win_bytes_backward"]
    bidirectional_feature_set = list(UNIDIRECTIONAL_FEATURES) + bwd_features
    unidirectional_feature_set = list(UNIDIRECTIONAL_FEATURES)

    y_train = train_df["label"].values
    y_test = test_df["label"].values

    # -------------------------------------------------------------
    # EXPERIMENT 1: Scenario A - Traditional Bidirectional Model
    # -------------------------------------------------------------
    print("\n[1] Training Scenario A: Standard Bidirectional Model (29 features)...")
    X_train_bidi = train_df[bidirectional_feature_set].values
    X_test_bidi = test_df[bidirectional_feature_set].values

    model_bidi = SupervisedThreatClassifier(model_type="random_forest", n_estimators=100)
    model_bidi.train(X_train_bidi, y_train, feature_names=bidirectional_feature_set)
    eval_bidi = model_bidi.evaluate(X_test_bidi, y_test)
    
    top_bidi_feats = sorted(model_bidi.get_feature_importances().items(), key=lambda x: x[1], reverse=True)[:5]
    print(f"    Scenario A Top-5 Anchored Features: {top_bidi_feats}")

    # -------------------------------------------------------------
    # EXPERIMENT 2: Scenario A Real-World Failure Mode on 1-Way Link
    # -------------------------------------------------------------
    print("[2] Evaluating Scenario A Failure Mode: Bidirectional Model deployed on Unidirectional Tap...")
    # On a unidirectional link, reverse features are absent (set to 0.0)
    X_test_bidi_blinded = test_df[bidirectional_feature_set].copy()
    for col in bwd_features:
        X_test_bidi_blinded[col] = 0.0
    eval_bidi_failure = model_bidi.evaluate(X_test_bidi_blinded.values, y_test)

    # -------------------------------------------------------------
    # EXPERIMENT 3: Scenario B - UniGuard AI Strict Unidirectional Model
    # -------------------------------------------------------------
    print("[3] Training Scenario B: UniGuard AI Strict Unidirectional Model (24 forward features only)...")
    X_train_uni = train_df[unidirectional_feature_set].values
    X_test_uni = test_df[unidirectional_feature_set].values

    model_uni = SupervisedThreatClassifier(model_type="random_forest", n_estimators=100)
    model_uni.train(X_train_uni, y_train, feature_names=unidirectional_feature_set)
    eval_uni = model_uni.evaluate(X_test_uni, y_test)

    # -------------------------------------------------------------
    # EXPERIMENT 4: XGBoost Unidirectional Model
    # -------------------------------------------------------------
    print("[4] Training Scenario B with XGBoost Classifier...")
    # Map labels to integers for XGBoost
    label_map = {lbl: idx for idx, lbl in enumerate(np.unique(y_train))}
    y_train_num = np.array([label_map[l] for l in y_train])
    y_test_num = np.array([label_map[l] for l in y_test])

    model_xgb = SupervisedThreatClassifier(model_type="xgboost", n_estimators=100)
    model_xgb.train(X_train_uni, y_train_num, feature_names=unidirectional_feature_set)
    eval_xgb = model_xgb.evaluate(X_test_uni, y_test_num)

    # -------------------------------------------------------------
    # Tabulate Comparative Results
    # -------------------------------------------------------------
    print("\n" + "=" * 85)
    print(" SCIENTIFIC EVALUATION BENCHMARK MATRIX")
    print("=" * 85)
    header = f"{'EVALUATION SCENARIO':<35} | {'PRECISION':<9} | {'RECALL':<8} | {'F1-SCORE':<8} | {'FPR':<7} | {'FNR':<7} | {'LATENCY':<10}"
    print(header)
    print("-" * 85)

    def print_row(name: str, ev: Dict[str, Any]):
        row = f"{name:<35} | {ev['weighted_precision'] * 100:>8.2f}% | {ev['weighted_recall'] * 100:>7.2f}% | {ev['weighted_f1'] * 100:>7.2f}% | {ev['mean_fpr'] * 100:>6.2f}% | {ev['mean_fnr'] * 100:>6.2f}% | {ev['inference_latency_ms_per_flow'] * 1000:>6.1f} us"
        print(row)

    print_row("A. Bidirectional Model (Ideal Bidi)", eval_bidi)
    print_row("A. Bidi Model on 1-Way Link (FAIL)", eval_bidi_failure)
    print_row("B. UniGuard AI (Random Forest)", eval_uni)
    print_row("B. UniGuard AI (XGBoost)", eval_xgb)
    print("=" * 85)

    # Save models and results
    os.makedirs("models_saved", exist_ok=True)
    os.makedirs("data", exist_ok=True)

    model_uni.save("models_saved/uniguard_rf_model.joblib")
    with open("models_saved/label_classes.json", "w") as f:
        json.dump(list(np.unique(y_train)), f)

    report = {
        "experiment_timestamp": time.time(),
        "dataset_samples": len(df),
        "classes": list(np.unique(y_train)),
        "scenarios": {
            "bidirectional_ideal": eval_bidi,
            "bidirectional_deployed_on_unidirectional_fail": eval_bidi_failure,
            "uniguard_rf_unidirectional": eval_uni,
            "uniguard_xgb_unidirectional": eval_xgb,
        },
    }

    report_path = "data/unidirectional_experiment_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[OK] Trained UniGuard AI model saved to: 'models_saved/uniguard_rf_model.joblib'")
    print(f"[OK] Full scientific report saved to: '{report_path}'\n")

    return report


if __name__ == "__main__":
    run_unidirectional_experiment()
