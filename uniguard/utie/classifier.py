"""Directionality Classification Engine for UniGuard AI UTIE.

Evaluates available network telemetry and sensor placement context to classify
flows into one of 5 distinct operational directionality states:
1. UNIDIRECTIONAL_OBSERVED
2. BIDIRECTIONAL_OBSERVED
3. ASYMMETRIC_OBSERVED
4. INSUFFICIENT_DATA
5. UNKNOWN

Provides an explicit Directionality Confidence Score and granular evidence rationale,
strictly separated from machine learning threat classification confidence.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
import numpy as np

from uniguard.utie.sensor_visibility import (
    SensorVisibilityAssessment,
    VisibilityType,
    ObservationPoint,
)


class DirectionalityClass(Enum):
    """The 5 primary UTIE observation categories."""
    UNIDIRECTIONAL_OBSERVED = "UNIDIRECTIONAL_OBSERVED"
    BIDIRECTIONAL_OBSERVED = "BIDIRECTIONAL_OBSERVED"
    ASYMMETRIC_OBSERVED = "ASYMMETRIC_OBSERVED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    UNKNOWN = "UNKNOWN"


@dataclass
class DirectionalityClassificationResult:
    """Detailed outcome of UTIE directionality and evidence evaluation."""
    classification: DirectionalityClass
    confidence_score: float             # Calibrated evidence score 0.0 - 1.0 (NOT ML threat confidence)
    evidence_bullets: List[str]
    fwd_packets: int
    rev_packets: Optional[int]          # None if reverse observation was unmonitored / unavailable
    fwd_bytes: int
    rev_bytes: Optional[int]
    symmetry_ratio: Optional[float]     # Fwd / Rev packet ratio (None if rev=0 or rev unmonitored)
    is_insufficient_data: bool
    observation_window_sec: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification": self.classification.value,
            "confidence_score": round(self.confidence_score, 4),
            "evidence_bullets": self.evidence_bullets,
            "fwd_packets": self.fwd_packets,
            "rev_packets": self.rev_packets,
            "fwd_bytes": self.fwd_bytes,
            "rev_bytes": self.rev_bytes,
            "symmetry_ratio": round(self.symmetry_ratio, 2) if self.symmetry_ratio is not None else None,
            "is_insufficient_data": self.is_insufficient_data,
            "observation_window_sec": round(self.observation_window_sec, 4),
        }


class DirectionalityClassifier:
    """Classifies flow directionality patterns while adhering to SIH 2026 guidelines."""

    def __init__(
        self,
        min_packets_threshold: int = 3,
        min_duration_threshold: float = 0.05,
    ) -> None:
        self.min_packets = min_packets_threshold
        self.min_duration = min_duration_threshold

    def classify(
        self,
        fwd_packets: int,
        rev_packets: Optional[int],
        fwd_bytes: int,
        rev_bytes: Optional[int],
        duration: float,
        proto: int,
        visibility_assessment: SensorVisibilityAssessment,
        tcp_syn_cnt: int = 0,
        tcp_ack_cnt: int = 0,
        tcp_fin_cnt: int = 0,
        tcp_rst_cnt: int = 0,
    ) -> DirectionalityClassificationResult:
        """Classifies the flow into one of the 5 target states with evidence."""
        rev_count = rev_packets if rev_packets is not None else 0
        total_packets = fwd_packets + rev_count
        evidence: List[str] = []

        # -------------------------------------------------------------
        # Rule 1: Guard against incomplete / single-packet flows
        # "A single packet or incomplete flow must not automatically be treated as proof of unidirectional communication"
        # -------------------------------------------------------------
        if total_packets < self.min_packets or (duration < self.min_duration and total_packets <= 2):
            evidence.append(
                f"Flow size ({total_packets} packets, {duration:.3f}s duration) is below the statistical observation threshold (min {self.min_packets} pkts, {self.min_duration}s)."
            )
            evidence.append("Single packets or ephemeral transient bursts cannot substantiate physical unidirectionality.")
            confidence = max(0.15, min(0.40, total_packets * 0.12))
            return DirectionalityClassificationResult(
                classification=DirectionalityClass.INSUFFICIENT_DATA,
                confidence_score=confidence,
                evidence_bullets=evidence,
                fwd_packets=fwd_packets,
                rev_packets=rev_packets,
                fwd_bytes=fwd_bytes,
                rev_bytes=rev_bytes,
                symmetry_ratio=None,
                is_insufficient_data=True,
                observation_window_sec=duration,
            )

        # -------------------------------------------------------------
        # Rule 2: Physical Hardware Data Diode Topology
        # -------------------------------------------------------------
        if visibility_assessment.visibility_type == VisibilityType.MONITORED_ONE_WAY_HARDWARE:
            evidence.append("Sensor is physically positioned on a hardware data diode interface.")
            evidence.append(f"All {fwd_packets} packets are guaranteed unidirectional by physical optical/electronic design.")
            evidence.append(f"Flow volume: {fwd_bytes} bytes across {duration:.3f} seconds.")
            return DirectionalityClassificationResult(
                classification=DirectionalityClass.UNIDIRECTIONAL_OBSERVED,
                confidence_score=0.99,
                evidence_bullets=evidence,
                fwd_packets=fwd_packets,
                rev_packets=0,
                fwd_bytes=fwd_bytes,
                rev_bytes=0,
                symmetry_ratio=None,
                is_insufficient_data=False,
                observation_window_sec=duration,
            )

        # -------------------------------------------------------------
        # Rule 3: Bilateral Packets Captured (Reverse Packets > 0)
        # -------------------------------------------------------------
        if rev_packets is not None and rev_packets > 0:
            sym_ratio = float(fwd_packets) / float(rev_packets)
            rev_b = rev_bytes if rev_bytes is not None else 0

            # Evaluate symmetry balance: balanced between 0.2 and 5.0
            if 0.2 <= sym_ratio <= 5.0:
                evidence.append(f"Active 2-way conversation confirmed: {fwd_packets} forward packets, {rev_packets} return packets.")
                evidence.append(f"Traffic symmetry ratio is balanced ({sym_ratio:.2f}:1).")
                if proto == 6 and (tcp_syn_cnt > 0 or tcp_ack_cnt > 0):
                    evidence.append("Normal bidirectional TCP handshake and session exchanges observed.")

                base_conf = 0.85 + min(0.14, (total_packets / 100.0) * 0.10)
                conf = float(np.clip(base_conf - visibility_assessment.confidence_penalty, 0.1, 1.0))
                return DirectionalityClassificationResult(
                    classification=DirectionalityClass.BIDIRECTIONAL_OBSERVED,
                    confidence_score=conf,
                    evidence_bullets=evidence,
                    fwd_packets=fwd_packets,
                    rev_packets=rev_packets,
                    fwd_bytes=fwd_bytes,
                    rev_bytes=rev_bytes,
                    symmetry_ratio=sym_ratio,
                    is_insufficient_data=False,
                    observation_window_sec=duration,
                )
            else:
                evidence.append(f"Bilateral traffic observed, but with heavy directional asymmetry (ratio {sym_ratio:.2f}:1).")
                evidence.append(f"Forward direction carries {fwd_packets} pkts ({fwd_bytes} bytes) vs reverse {rev_packets} pkts ({rev_b} bytes).")
                if sym_ratio > 5.0:
                    evidence.append("Pronounced forward dominance: reverse packets are minimal (e.g. sparse ACKs or keepalives).")
                else:
                    evidence.append("Pronounced reverse dominance: forward flow is primarily client requests triggering large return downloads.")

                base_conf = 0.80 + min(0.15, (total_packets / 80.0) * 0.10)
                conf = float(np.clip(base_conf - visibility_assessment.confidence_penalty, 0.1, 1.0))
                return DirectionalityClassificationResult(
                    classification=DirectionalityClass.ASYMMETRIC_OBSERVED,
                    confidence_score=conf,
                    evidence_bullets=evidence,
                    fwd_packets=fwd_packets,
                    rev_packets=rev_packets,
                    fwd_bytes=fwd_bytes,
                    rev_bytes=rev_bytes,
                    symmetry_ratio=sym_ratio,
                    is_insufficient_data=False,
                    observation_window_sec=duration,
                )

        # -------------------------------------------------------------
        # Rule 4: Zero Reverse Packets Observed
        # -------------------------------------------------------------
        evidence.append(f"Sensor recorded {fwd_packets} packets in forward direction with 0 return packets over {duration:.3f}s.")

        if proto == 6:  # TCP
            if tcp_syn_cnt > 0 and tcp_ack_cnt == 0:
                evidence.append("TCP connection request (SYN) was sent, but no SYN-ACK or RST response was ever returned.")
            elif tcp_ack_cnt > 0 and tcp_syn_cnt == 0:
                evidence.append("TCP payload/ACK packets transmitted without return data or acknowledgment.")
        elif proto == 17:  # UDP
            evidence.append("UDP datagrams emitted with no return datagrams observed on wire.")
        elif proto == 1:   # ICMP
            evidence.append("ICMP queries with no replies captured.")

        # Compute empirical evidence confidence based on sample size and observation window duration
        # More packets + longer observation window = higher confidence of genuine unidirectionality
        depth_factor = min(0.40, (fwd_packets / 20.0) * 0.40)
        time_factor = min(0.35, (duration / 5.0) * 0.35)
        base_confidence = 0.25 + depth_factor + time_factor
        calibrated_confidence = float(np.clip(base_confidence - visibility_assessment.confidence_penalty, 0.15, 0.98))

        if visibility_assessment.visibility_type == VisibilityType.POTENTIAL_ASYMMETRIC_ROUTING:
            evidence.append("Note: Asymmetric transit link configured; return traffic may traverse a separate WAN route.")

        return DirectionalityClassificationResult(
            classification=DirectionalityClass.UNIDIRECTIONAL_OBSERVED,
            confidence_score=calibrated_confidence,
            evidence_bullets=evidence,
            fwd_packets=fwd_packets,
            rev_packets=0,
            fwd_bytes=fwd_bytes,
            rev_bytes=0,
            symmetry_ratio=None,
            is_insufficient_data=False,
            observation_window_sec=duration,
        )

