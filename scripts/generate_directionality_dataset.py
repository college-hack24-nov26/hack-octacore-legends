"""Controlled Research Dataset Generator for Directionality & Asymmetry Evaluation.

Smart India Hackathon (SIH) 2026 - Task 21.

Generates realistic multi-scenario network traffic records spanning:
1. Normal Traffic:
   - Web Browsing (HTTP/HTTPS client requests with small server responses)
   - Large File Downloads (MTU-saturated inbound packets with paced client ACKs)
   - YouTube / Video Streaming (continuous MTU video chunks with periodic client TCP ACKs)
   - Cloud Uploads (client MTU saturation with server ACKs)
   - DNS Queries (UDP 53 request-response pairs)
   - QUIC / UDP 443 streaming
2. Network Variations:
   - IPv4 and IPv6 conversations
   - VPN / Virtual Adapter interfaces
   - Internal LAN communications
3. Security-Oriented Anomalies:
   - Reconnaissance Port Scan (single-packet SYN probes with zero reverse responses)
   - Distributed SYN Flood (high-rate empty SYN packets with zero ACKs)
   - High-Volume UDP Flood (rapid spoofed UDP bursts)
   - Stealthy Slowloris (slow-drip partial HTTP headers)
   - Covert Data Exfiltration (unbalanced outbound data transfer over custom/HTTPS ports)
"""

from __future__ import annotations

import os
import random
from typing import List, Dict, Any, Tuple
import numpy as np
import pandas as pd


def generate_research_evaluation_dataset(
    n_samples: int = 6000,
    random_seed: int = 42,
) -> pd.DataFrame:
    """Generates a diverse research dataset covering normal, network-variant, and malicious directional flows."""
    np.random.seed(random_seed)
    random.seed(random_seed)

    scenarios = [
        # Normal Traffic (Expected Directionality: BIDIRECTIONAL or NORMAL ASYMMETRIC)
        ("WEB_BROWSING_HTTPS", 0.20),
        ("LARGE_FILE_DOWNLOAD", 0.15),
        ("YOUTUBE_VIDEO_STREAMING", 0.15),
        ("CLOUD_DATA_UPLOAD", 0.08),
        ("DNS_QUERY_RESPONSE", 0.07),
        ("QUIC_UDP_STREAMING", 0.05),
        # Security Traffic (Expected Directionality: STRONGLY ASYMMETRIC or UNIDIRECTIONAL OBSERVED)
        ("PORT_SCAN_PROBE", 0.08),
        ("SYN_FLOOD_ATTACK", 0.08),
        ("UDP_FLOOD_ATTACK", 0.06),
        ("DATA_EXFILTRATION", 0.05),
        ("SLOWLORIS_DOS", 0.03),
    ]

    records: List[Dict[str, Any]] = []

    for scenario_name, scenario_fraction in scenarios:
        count = int(round(n_samples * scenario_fraction))
        for _ in range(count):
            is_ipv6 = np.random.rand() < 0.15
            if is_ipv6:
                src_ip = f"2001:db8::{np.random.randint(1, 9999):x}"
                dst_ip = f"2607:f8b0:4005::{np.random.randint(1, 9999):x}"
            else:
                src_ip = f"192.168.1.{np.random.randint(10, 250)}"
                dst_ip = f"{np.random.randint(11, 210)}.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}"

            if scenario_name == "WEB_BROWSING_HTTPS":
                proto = 6
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.choice([443, 80, 8080])
                duration = np.random.uniform(0.5, 5.0)
                fwd_pkts = np.random.randint(8, 40)
                # Web browsing has reciprocal response packets
                rev_pkts = int(fwd_pkts * np.random.uniform(0.6, 1.4))
                fwd_bytes = fwd_pkts * np.random.uniform(100, 400)
                rev_bytes = rev_pkts * np.random.uniform(600, 1400)
                burst_transitions = max(1, int(min(fwd_pkts, rev_pkts) * np.random.uniform(0.4, 0.8)))
                rev_ack_ratio = np.random.uniform(0.7, 1.0)
                tcp_syn = 1
                rev_syn = 1
                category = "NORMAL"
                true_directionality = "BIDIRECTIONAL"

            elif scenario_name == "LARGE_FILE_DOWNLOAD":
                # High forward byte volume (Server -> Client) with client returning TCP ACKs
                proto = 6
                src_port = np.random.choice([443, 80, 8443])
                dst_port = np.random.randint(1024, 65535)
                duration = np.random.uniform(2.0, 30.0)
                fwd_pkts = np.random.randint(200, 5000)
                # Client returns 1 ACK for every ~2-3 MTU packets
                rev_pkts = max(5, int(fwd_pkts * np.random.uniform(0.25, 0.50)))
                fwd_bytes = fwd_pkts * np.random.uniform(1400, 1460) # MTU saturation
                rev_bytes = rev_pkts * 54.0                          # Pure TCP ACKs
                burst_transitions = int(rev_pkts * np.random.uniform(0.5, 0.9))
                rev_ack_ratio = 1.0
                tcp_syn = 1
                rev_syn = 1
                category = "NORMAL"
                true_directionality = "BIDIRECTIONAL" # Conversational download, excluded from one-way security threat

            elif scenario_name == "YOUTUBE_VIDEO_STREAMING":
                # Video streaming chunks: bursts of 1460-byte packets followed by client window ACKs
                proto = 6
                src_port = 443
                dst_port = np.random.randint(1024, 65535)
                duration = np.random.uniform(5.0, 45.0)
                fwd_pkts = np.random.randint(300, 6000)
                rev_pkts = max(10, int(fwd_pkts * np.random.uniform(0.20, 0.40)))
                fwd_bytes = fwd_pkts * 1440.0
                rev_bytes = rev_pkts * 60.0
                burst_transitions = int(rev_pkts * np.random.uniform(0.6, 0.9))
                rev_ack_ratio = 1.0
                tcp_syn = 1
                rev_syn = 1
                category = "NORMAL"
                true_directionality = "BIDIRECTIONAL"

            elif scenario_name == "CLOUD_DATA_UPLOAD":
                # Client uploading payload to cloud storage (Client -> Server MTU saturation)
                proto = 6
                src_port = np.random.randint(1024, 65535)
                dst_port = 443
                duration = np.random.uniform(2.0, 20.0)
                fwd_pkts = np.random.randint(150, 3000)
                rev_pkts = max(5, int(fwd_pkts * np.random.uniform(0.25, 0.45)))
                fwd_bytes = fwd_pkts * 1420.0
                rev_bytes = rev_pkts * 54.0
                burst_transitions = int(rev_pkts * 0.7)
                rev_ack_ratio = 1.0
                tcp_syn = 1
                rev_syn = 1
                category = "NORMAL"
                true_directionality = "BIDIRECTIONAL"

            elif scenario_name == "DNS_QUERY_RESPONSE":
                proto = 17 # UDP
                src_port = np.random.randint(1024, 65535)
                dst_port = 53
                duration = np.random.uniform(0.01, 0.2)
                fwd_pkts = np.random.randint(1, 3)
                rev_pkts = fwd_pkts
                fwd_bytes = fwd_pkts * np.random.uniform(60, 100)
                rev_bytes = rev_pkts * np.random.uniform(120, 400)
                burst_transitions = 1
                rev_ack_ratio = 0.0
                tcp_syn = 0
                rev_syn = 0
                category = "NORMAL"
                true_directionality = "BIDIRECTIONAL"

            elif scenario_name == "QUIC_UDP_STREAMING":
                proto = 17 # UDP 443
                src_port = np.random.randint(1024, 65535)
                dst_port = 443
                duration = np.random.uniform(1.0, 10.0)
                fwd_pkts = np.random.randint(50, 800)
                rev_pkts = int(fwd_pkts * np.random.uniform(0.3, 0.7))
                fwd_bytes = fwd_pkts * np.random.uniform(800, 1200)
                rev_bytes = rev_pkts * np.random.uniform(200, 600)
                burst_transitions = int(rev_pkts * 0.5)
                rev_ack_ratio = 0.0
                tcp_syn = 0
                rev_syn = 0
                category = "NORMAL"
                true_directionality = "BIDIRECTIONAL"

            elif scenario_name == "PORT_SCAN_PROBE":
                # Single isolated SYN probe with ZERO reverse response
                proto = 6
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.randint(1, 1024)
                duration = 0.0001
                fwd_pkts = 1
                rev_pkts = 0
                fwd_bytes = 60.0
                rev_bytes = 0.0
                burst_transitions = 0
                rev_ack_ratio = 0.0
                tcp_syn = 1
                rev_syn = 0
                category = "MALICIOUS"
                true_directionality = "UNIDIRECTIONAL_OBSERVED"

            elif scenario_name == "SYN_FLOOD_ATTACK":
                # Rapid SYN packets, zero reverse responses
                proto = 6
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.choice([80, 443, 8080])
                duration = np.random.uniform(0.05, 0.5)
                fwd_pkts = np.random.randint(50, 600)
                rev_pkts = 0
                fwd_bytes = fwd_pkts * 54.0
                rev_bytes = 0.0
                burst_transitions = 0
                rev_ack_ratio = 0.0
                tcp_syn = fwd_pkts
                rev_syn = 0
                category = "MALICIOUS"
                true_directionality = "UNIDIRECTIONAL_OBSERVED"

            elif scenario_name == "UDP_FLOOD_ATTACK":
                proto = 17
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.choice([53, 123, 1900, 37008])
                duration = np.random.uniform(0.1, 0.8)
                fwd_pkts = np.random.randint(100, 800)
                rev_pkts = 0
                fwd_bytes = fwd_pkts * np.random.uniform(400, 1200)
                rev_bytes = 0.0
                burst_transitions = 0
                rev_ack_ratio = 0.0
                tcp_syn = 0
                rev_syn = 0
                category = "MALICIOUS"
                true_directionality = "UNIDIRECTIONAL_OBSERVED"

            elif scenario_name == "DATA_EXFILTRATION":
                # Attacker pumping outbound data with minimal or no reverse traffic
                proto = 6
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.choice([443, 8443, 9001, 22])
                duration = np.random.uniform(1.0, 8.0)
                fwd_pkts = np.random.randint(80, 800)
                # Maybe 1 or 2 ACK packets back, or 0
                rev_pkts = np.random.choice([0, 1, 2])
                fwd_bytes = fwd_pkts * 1420.0
                rev_bytes = rev_pkts * 54.0
                burst_transitions = rev_pkts
                rev_ack_ratio = rev_pkts / float(fwd_pkts)
                tcp_syn = 1
                rev_syn = 0 if rev_pkts == 0 else 1
                category = "MALICIOUS"
                true_directionality = "STRONGLY_ASYMMETRIC"

            elif scenario_name == "SLOWLORIS_DOS":
                proto = 6
                src_port = np.random.randint(1024, 65535)
                dst_port = 80
                duration = np.random.uniform(10.0, 40.0)
                fwd_pkts = np.random.randint(15, 45)
                rev_pkts = np.random.choice([0, 1])
                fwd_bytes = fwd_pkts * 64.0
                rev_bytes = rev_pkts * 54.0
                burst_transitions = rev_pkts
                rev_ack_ratio = rev_pkts / float(fwd_pkts)
                tcp_syn = 1
                rev_syn = 0
                category = "MALICIOUS"
                true_directionality = "STRONGLY_ASYMMETRIC"

            # Compute normalized statistical features
            eps = 1e-6
            ap = abs(fwd_pkts - rev_pkts) / (fwd_pkts + rev_pkts + eps)
            ab = abs(fwd_bytes - rev_bytes) / (fwd_bytes + rev_bytes + eps)
            dir_ratio = float(np.log10((fwd_pkts + 1.0) / (rev_pkts + 1.0)))

            eff_dur = max(eps, duration)
            fwd_rate = fwd_pkts / eff_dur
            rev_rate = rev_pkts / eff_dur
            fwd_byte_rate = fwd_bytes / eff_dur
            rev_byte_rate = rev_bytes / eff_dur

            record = {
                "scenario": scenario_name,
                "category": category,
                "true_directionality": true_directionality,
                "proto": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "duration": duration,
                "forward_packet_count": fwd_pkts,
                "reverse_packet_count": rev_pkts,
                "forward_byte_count": fwd_bytes,
                "reverse_byte_count": rev_bytes,
                "packet_asymmetry": float(np.clip(ap, 0.0, 1.0)),
                "byte_asymmetry": float(np.clip(ab, 0.0, 1.0)),
                "directional_ratio": dir_ratio,
                "forward_packet_rate": fwd_rate,
                "reverse_packet_rate": rev_rate,
                "forward_byte_rate": fwd_byte_rate,
                "reverse_byte_rate": rev_byte_rate,
                "reverse_presence": 1.0 if rev_pkts > 0 else 0.0,
                "burst_transition_rate": float(burst_transitions) / max(1.0, fwd_pkts + rev_pkts),
                "temporal_dependency_lag": 0.02 if rev_pkts > 0 else 0.0,
                "tcp_handshake_presence": 1.0 if (tcp_syn > 0 and rev_syn > 0) else 0.0,
                "reverse_ack_ratio": float(rev_ack_ratio),
            }
            records.append(record)

    df = pd.DataFrame(records)
    return df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)


if __name__ == "__main__":
    df = generate_research_evaluation_dataset(n_samples=5000)
    out_dir = "data"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "research_directionality_dataset.csv")
    df.to_csv(out_path, index=False)
    print(f"[*] Generated research evaluation dataset: {len(df)} records saved to {out_path}")
    print(f"[*] Category breakdown:\n{df['category'].value_counts()}")
    print(f"[*] True directionality breakdown:\n{df['true_directionality'].value_counts()}")
