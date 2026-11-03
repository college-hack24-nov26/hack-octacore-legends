"""Scientific Comparative Evaluation of Three Directionality Classification Methods.

Smart India Hackathon (SIH) 2026 - Task 22 Benchmark.

Compares:
1. Method 1: Raw Packet-Count Heuristic (5/20 Rule)
2. Method 2: Statistical Asymmetry (Packet Asymmetry Ap + Byte Asymmetry Ab + Ratio R)
3. Method 3: Unsupervised Directionality Engine (Statistical + Dependency + Unsupervised Isolation Forest / Clustering)

Evaluates False Positive Rate (FPR) on normal downloads/streaming,
False Negative Rate (FNR) on unidirectional attacks, Precision, Recall,
and Per-Flow Processing Latency.
"""

from __future__ import annotations

import os
import sys
import json
import time
from typing import Dict, Any, List
import numpy as np
import pandas as pd

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.generate_directionality_dataset import generate_research_evaluation_dataset
from uniguard.directionality.heuristics import HeuristicBaselineComparator
from uniguard.directionality.unsupervised_model import (
    UnsupervisedDirectionalityEngine,
    EngineOperationalMode,
    DirectionalityState,
)
from uniguard.directionality.asymmetry_engine import AsymmetryEngine


def run_three_method_benchmark(n_samples: int = 5000) -> Dict[str, Any]:
    print("=" * 90)
    print(" UNIGUARD AI: SCIENTIFIC DIRECTIONALITY BENCHMARK EVALUATION (TASK 22)")
    print(" Smart India Hackathon (SIH) 2026 - Major Research Contribution")
    print("=" * 90)

    df = generate_research_evaluation_dataset(n_samples=n_samples, random_seed=42)
    print(f"[*] Generated benchmark dataset: {len(df)} flows.")
    print(f"    - Normal flows (Browsing, Downloads, YouTube, Uploads, DNS): {sum(df['category'] == 'NORMAL'):,}")
    print(f"    - Attack flows (SYN Flood, Port Scan, UDP Flood, Exfil, Slowloris): {sum(df['category'] == 'MALICIOUS'):,}\n")

    # True binary labels for one-way security candidacy:
    # 0 = Normal / Bidirectional Conversational (Should NOT enter unidirectional threat detector)
    # 1 = Truly Asymmetric / Unidirectional Observed (Should enter unidirectional threat detector)
    y_true_asymmetric = (df["category"] == "MALICIOUS").astype(int).values

    # -----------------------------------------------------------------
    # METHOD 1: Raw 5/20 Packet-Count Rule
    # -----------------------------------------------------------------
    print("[1] Evaluating Method 1: Raw 5/20 Heuristic Rule (>=20 fwd, <=5 rev)...")
    m1_preds = []
    t0 = time.perf_counter()
    for _, row in df.iterrows():
        fwd_pkts = int(row["forward_packet_count"])
        rev_pkts = int(row["reverse_packet_count"])
        is_asym = (fwd_pkts >= 20 and rev_pkts <= 5)
        m1_preds.append(1 if is_asym else 0)
    m1_latency_us = ((time.perf_counter() - t0) / len(df)) * 1_000_000
    m1_preds = np.array(m1_preds)

    # -----------------------------------------------------------------
    # METHOD 2: Statistical Asymmetry (Ap + Ab + Ratio)
    # -----------------------------------------------------------------
    print("[2] Evaluating Method 2: Statistical Asymmetry (Packet + Byte Asymmetry + Ratio)...")
    m2_preds = []
    t0 = time.perf_counter()
    for _, row in df.iterrows():
        ap = float(row["packet_asymmetry"])
        ab = float(row["byte_asymmetry"])
        score = 0.60 * ap + 0.40 * ab
        # Statistical threshold for asymmetry without reverse dependency analysis
        m2_preds.append(1 if score >= 0.70 else 0)
    m2_latency_us = ((time.perf_counter() - t0) / len(df)) * 1_000_000
    m2_preds = np.array(m2_preds)

    # -----------------------------------------------------------------
    # METHOD 3: Unsupervised Engine (Statistical + Dependency + IF/KMeans)
    # -----------------------------------------------------------------
    print("[3] Evaluating Method 3: Unsupervised Directionality Engine...")
    engine = UnsupervisedDirectionalityEngine(min_packets=3, min_duration_sec=0.05)

    # Fit baseline on a subset of normal flows to simulate environment baseline learning
    normal_subset = df[df["category"] == "NORMAL"]
    X_normal = []
    for _, row in normal_subset.head(500).iterrows():
        f_dict = {col: float(row[col]) for col in df.columns if col in [
            "forward_packet_count", "reverse_packet_count", "forward_byte_count", "reverse_byte_count",
            "packet_asymmetry", "byte_asymmetry", "directional_ratio", "forward_packet_rate",
            "reverse_packet_rate", "forward_byte_rate", "reverse_byte_rate", "duration",
            "reverse_presence", "burst_transition_rate", "temporal_dependency_lag",
            "tcp_handshake_presence", "reverse_ack_ratio"
        ]}
        X_normal.append(AsymmetryEngine.to_vector(f_dict))
    engine.fit_baseline(np.array(X_normal))

    m3_preds = []
    t0 = time.perf_counter()
    for _, row in df.iterrows():
        f_dict = {col: float(row[col]) for col in df.columns if col in [
            "forward_packet_count", "reverse_packet_count", "forward_byte_count", "reverse_byte_count",
            "packet_asymmetry", "byte_asymmetry", "directional_ratio", "forward_packet_rate",
            "reverse_packet_rate", "forward_byte_rate", "reverse_byte_rate", "duration",
            "reverse_presence", "burst_transition_rate", "temporal_dependency_lag",
            "tcp_handshake_presence", "reverse_ack_ratio"
        ]}
        res = engine.evaluate_flow(f_dict, is_flow_closed=True)
        # 1 if routed to unidirectional security analysis, 0 if excluded
        m3_preds.append(0 if res.is_excluded_from_unidirectional_security else 1)
    m3_latency_us = ((time.perf_counter() - t0) / len(df)) * 1_000_000
    m3_preds = np.array(m3_preds)

    # -----------------------------------------------------------------
    # Compute Metrics Function
    # -----------------------------------------------------------------
    def compute_metrics(y_true, y_pred, latency_us):
        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))

        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * (precision * recall) / max(1e-6, precision + recall)
        fpr = fp / max(1, fp + tn) # False positive rate on normal traffic!
        fnr = fn / max(1, fn + tp) # False negative rate on malicious one-way traffic!

        return {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "latency_us": round(latency_us, 2),
        }

    m1_eval = compute_metrics(y_true_asymmetric, m1_preds, m1_latency_us)
    m2_eval = compute_metrics(y_true_asymmetric, m2_preds, m2_latency_us)
    m3_eval = compute_metrics(y_true_asymmetric, m3_preds, m3_latency_us)

    # Breakdown on Normal Downloads specifically (The Core False Positive Problem)
    downloads_mask = df["scenario"].isin(["LARGE_FILE_DOWNLOAD", "YOUTUBE_VIDEO_STREAMING", "CLOUD_DATA_UPLOAD"])
    m1_dl_fp = int(np.sum(m1_preds[downloads_mask] == 1))
    m2_dl_fp = int(np.sum(m2_preds[downloads_mask] == 1))
    m3_dl_fp = int(np.sum(m3_preds[downloads_mask] == 1))
    dl_total = int(np.sum(downloads_mask))

    # -----------------------------------------------------------------
    # Print Benchmark Matrix
    # -----------------------------------------------------------------
    print("\n" + "=" * 90)
    print(" SCIENTIFIC EVALUATION BENCHMARK MATRIX (TASK 22)")
    print("=" * 90)
    header = f"{'METHOD':<35} | {'PRECISION':<9} | {'RECALL':<8} | {'F1-SCORE':<8} | {'FPR':<7} | {'FNR':<7} | {'DOWNLOAD FP':<12} | {'LATENCY':<10}"
    print(header)
    print("-" * 90)

    def print_row(name: str, ev: Dict[str, Any], dl_fp: int, dl_tot: int):
        dl_str = f"{dl_fp}/{dl_tot} ({(dl_fp/dl_tot)*100:.1f}%)"
        row = (
            f"{name:<35} | "
            f"{ev['precision']*100:>8.2f}% | "
            f"{ev['recall']*100:>7.2f}% | "
            f"{ev['f1_score']*100:>7.2f}% | "
            f"{ev['fpr']*100:>6.2f}% | "
            f"{ev['fnr']*100:>6.2f}% | "
            f"{dl_str:>12} | "
            f"{ev['latency_us']:>7.1f} us"
        )
        print(row)

    print_row("1. Raw Packet Heuristic (5/20)", m1_eval, m1_dl_fp, dl_total)
    print_row("2. Statistical Asymmetry (Ap+Ab)", m2_eval, m2_dl_fp, dl_total)
    print_row("3. Unsupervised Engine (UniGuard)", m3_eval, m3_dl_fp, dl_total)
    print("=" * 90)

    # Save scientific report
    os.makedirs("data", exist_ok=True)
    report = {
        "timestamp": time.time(),
        "total_flows": len(df),
        "downloads_total": dl_total,
        "method_1_5_20_heuristic": {
            **m1_eval,
            "downloads_false_positives": m1_dl_fp,
            "downloads_fpr": round(m1_dl_fp / dl_total, 4),
        },
        "method_2_statistical_asymmetry": {
            **m2_eval,
            "downloads_false_positives": m2_dl_fp,
            "downloads_fpr": round(m2_dl_fp / dl_total, 4),
        },
        "method_3_unsupervised_directionality_engine": {
            **m3_eval,
            "downloads_false_positives": m3_dl_fp,
            "downloads_fpr": round(m3_dl_fp / dl_total, 4),
        },
    }

    report_path = "data/directionality_benchmark_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[OK] Scientific Directionality Benchmark report saved to: '{report_path}'\n")
    return report


if __name__ == "__main__":
    run_three_method_benchmark()
