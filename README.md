# UniGuard AI: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Smart India Hackathon (SIH) 2026**  
**Category:** Cybersecurity / Network Monitoring / Intrusion Detection  

---

## 1. Problem Statement Overview
In enterprise data diodes, asymmetric BGP routing paths, optical taps, and isolated enclaves, network security sensors often have visibility into traffic traveling in **only one direction** (ingress or egress). Traditional intrusion detection systems (Snort, Suricata, Zeek) rely heavily on bidirectional TCP handshake matching (`SYN` -> `SYN-ACK` -> `ACK`), round-trip response metrics, and forward/backward traffic ratios. When deployed on unidirectional links, traditional systems suffer from TCP state table exhaustion, missing response payloads, and high false-alarm rates.

**UniGuard AI** is a specialized cybersecurity detection framework designed to reconstruct flow-level behavioral signatures exclusively from one-way IP traffic, applying supervised threat classification, unsupervised anomaly detection, explainable AI (SHAP), and multi-factor risk scoring.

---

## 2. System Architecture

```
                       Raw Packets (PCAP / Live Interface)
                                       │
                                       ▼
                         PcapIngestor / LiveSniffer
                                       │
                                       ▼
                       FlowTracker (5-Tuple Hash Table)
                      [Inactivity & Active Timeout Eviction]
                                       │
                                       ▼
                   FeatureExtractor (Strict 24-Feature Vector)
                 [Zero Reverse Features / Mathematically Verified]
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
      Supervised Threat Classifier           Unsupervised Anomaly Detector
        (Random Forest / XGBoost)                 (Isolation Forest)
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
                          Explainability Engine (SHAP)
                                       │
                                       ▼
                           Multi-Factor Risk Scorer
                                       │
                                       ▼
                         Database (SQLite Event Store)
                                       │
                                       ▼
                          Desktop UI (PySide6 Dashboard)
```

---

## 3. Strict 24-Feature Unidirectional Schema
UniGuard AI strictly forbids bidirectional features (e.g., `bwd_packets`, `fwd_bwd_ratio`, `syn_ack_rtt`). All 24 canonical features are computed from one direction:
1. `proto` - Transport protocol number (6=TCP, 17=UDP, 1=ICMP)
2. `dst_port` - Target service port
3. `src_port` - Ephemeral/source port
4. `pkt_count` - Total packets in flow observation window
5. `byte_count` - Total bytes in flow observation window
6. `duration` - Flow observation time ($t_N - t_1$)
7. `pkt_rate` - Packets per second
8. `byte_rate` - Bytes per second
9. `pkt_len_mean` - Mean packet size
10. `pkt_len_std` - Standard deviation of packet sizes
11. `pkt_len_min` - Minimum packet size observed
12. `pkt_len_max` - Maximum packet size observed
13. `iat_mean` - Mean inter-arrival time
14. `iat_std` - Standard deviation of inter-arrival times
15. `iat_min` - Minimum inter-arrival time
16. `iat_max` - Maximum inter-arrival time
17. `tcp_syn_cnt` - SYN flag count
18. `tcp_psh_cnt` - PSH flag count
19. `tcp_ack_cnt` - Sender ACK flag count
20. `tcp_fin_cnt` - FIN flag count
21. `tcp_rst_cnt` - RST flag count
22. `tcp_urg_cnt` - URG flag count
23. `entropy_pkt_len` - Shannon entropy of packet lengths
24. `burstiness` - Coefficient of variation of inter-arrival times ($\sigma_{IAT} / \mu_{IAT}$)

---

## 4. Repository Structure

```
UniGuardAI/
├── config/                  # Configuration profiles (YAML)
│   └── default_config.yaml
├── data/                    # Datasets and synthetic PCAPs
│   └── samples/
│       └── sample_unidirectional.pcap
├── scripts/                 # Utility scripts and testbed runners
│   ├── generate_sample_pcap.py
│   └── run_pcap_analysis.py
├── tests/                   # Automated unit test suite
│   ├── test_flow_engine.py
│   ├── test_features.py
│   └── test_risk_scorer.py
├── uniguard/                # Core Python framework
│   ├── capture/             # PCAP reader and live socket capture
│   ├── flow_engine/         # Flow tracker and timeout eviction
│   ├── features/            # Feature extractor and schema
│   ├── preprocessing/       # Scalers and encoders
│   ├── models/              # ML and Anomaly detection models
│   ├── detection/           # Threat detection orchestrator
│   ├── risk/                # Multi-factor risk scoring engine
│   ├── explainability/      # SHAP feature importance explainers
│   ├── database/            # Event logging and SQLite storage
│   └── desktop_ui/          # PySide6 SOC monitoring application
├── requirements.txt         # Project dependencies
├── .gitignore               # Git exclusion rules
└── README.md                # Project documentation
```

---

## 5. Quickstart & Verification

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Automated Test Suite
```bash
python -m unittest discover tests
```

### 3. Generate Synthetic PCAP
```bash
python scripts/generate_sample_pcap.py
```

### 4. Run Offline PCAP Analysis Pipeline
```bash
python scripts/run_pcap_analysis.py
```
