"""Sensor Visibility Awareness for UniGuard AI Unidirectional Traffic Intelligence Engine (UTIE).

Distinguishes true physical unidirectionality from monitoring placement artefacts,
asymmetric routing, optical data diodes, and packet capture limitations.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


class ObservationPoint(Enum):
    """Network monitoring observation point topology (Configurable by operator)."""
    PROMISCUOUS_TAP = "PROMISCUOUS_TAP"        # Bilateral SPAN/TAP expected to see both directions
    DATA_DIODE_EGRESS = "DATA_DIODE_EGRESS"    # Hardware optical/electronic one-way outbound diode
    DATA_DIODE_INGRESS = "DATA_DIODE_INGRESS"  # Hardware optical/electronic one-way inbound diode
    ASYMMETRIC_SPAN = "ASYMMETRIC_SPAN"        # Egress and Ingress travel via different routing paths
    GATEWAY_INLINE = "GATEWAY_INLINE"          # Inline firewall or border router interface
    UNKNOWN = "UNKNOWN"                        # Default; no topology assumption is made


class VisibilityType(Enum):
    """Evaluated sensor visibility characterization for a given flow."""
    MONITORED_ONE_WAY_HARDWARE = "MONITORED_ONE_WAY_HARDWARE"
    BILATERAL_OBSERVED_BOTH_WAYS = "BILATERAL_OBSERVED_BOTH_WAYS"
    BILATERAL_CAPABLE_OBSERVED_ONE_WAY = "BILATERAL_CAPABLE_OBSERVED_ONE_WAY"
    POTENTIAL_ASYMMETRIC_ROUTING = "POTENTIAL_ASYMMETRIC_ROUTING"
    INSUFFICIENT_OBSERVATION_WINDOW = "INSUFFICIENT_OBSERVATION_WINDOW"
    CAPTURE_LIMITATION_ARTEFACT = "CAPTURE_LIMITATION_ARTEFACT"


@dataclass
class SensorVisibilityContext:
    """Configurable operator settings for sensor topology and monitoring constraints."""
    observation_point: ObservationPoint = ObservationPoint.UNKNOWN
    sampling_rate: float = 1.0                  # 1.0 = 100% full capture, < 1.0 = sampled
    is_diode_enforced: bool = False             # True if hardware diode guarantees no reverse traffic
    known_asymmetric_cidrs: List[str] = field(default_factory=list)
    buffer_drops_detected: bool = False
    interface_name: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observation_point": self.observation_point.value,
            "sampling_rate": self.sampling_rate,
            "is_diode_enforced": self.is_diode_enforced,
            "known_asymmetric_cidrs": self.known_asymmetric_cidrs,
            "buffer_drops_detected": self.buffer_drops_detected,
            "interface_name": self.interface_name,
        }


@dataclass
class SensorVisibilityAssessment:
    """Standardized output of sensor visibility analysis for a specific flow."""
    visibility_type: VisibilityType
    is_reverse_direction_missing: bool
    reverse_missing_reason: str
    completeness_status: str                   # "COMPLETE", "PARTIAL", "INSUFFICIENT_DATA"
    confidence_penalty: float                  # Penalty deduction applied if sensor limitation obscures data
    sensor_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "visibility_type": self.visibility_type.value,
            "is_reverse_missing": self.is_reverse_direction_missing,
            "reverse_missing_reason": self.reverse_missing_reason,
            "completeness_status": self.completeness_status,
            "confidence_penalty": round(self.confidence_penalty, 3),
            "sensor_notes": self.sensor_notes,
        }


class SensorVisibilityEvaluator:
    """Evaluates sensor visibility context against observed flow telemetry."""

    def __init__(self, context: Optional[SensorVisibilityContext] = None) -> None:
        self.context = context or SensorVisibilityContext()

    def evaluate(
        self,
        forward_packets: int,
        reverse_packets: Optional[int],
        flow_duration: float,
        proto: int,
        has_syn: bool,
        has_ack: bool,
    ) -> SensorVisibilityAssessment:
        """Determines why reverse-direction traffic is present or missing.

        Never assumes unidirectional traffic automatically equals malicious activity;
        distinguishes topology and sensor limitations from malicious one-way floods.
        """
        rev_count = reverse_packets if reverse_packets is not None else 0
        total_packets = forward_packets + rev_count
        notes: List[str] = []

        # 1. Check for Insufficient Data
        if total_packets < 3 or (flow_duration < 0.05 and total_packets <= 2):
            notes.append(f"Insufficient observation window: only {total_packets} packet(s) over {flow_duration:.3f}s.")
            notes.append("Cannot reliably determine true communication symmetry from short bursts.")
            return SensorVisibilityAssessment(
                visibility_type=VisibilityType.INSUFFICIENT_OBSERVATION_WINDOW,
                is_reverse_direction_missing=(rev_count == 0),
                reverse_missing_reason="Insufficient observation duration / packet threshold not met",
                completeness_status="INSUFFICIENT_DATA",
                confidence_penalty=0.40,
                sensor_notes=notes,
            )

        # 2. Check for Hardware Data Diode Topology
        if self.context.is_diode_enforced or self.context.observation_point in (
            ObservationPoint.DATA_DIODE_EGRESS,
            ObservationPoint.DATA_DIODE_INGRESS,
        ):
            notes.append(f"Monitoring point is physical hardware data diode ({self.context.observation_point.value}).")
            notes.append("Reverse-path packets are physically isolated by design; missing return path is expected.")
            return SensorVisibilityAssessment(
                visibility_type=VisibilityType.MONITORED_ONE_WAY_HARDWARE,
                is_reverse_direction_missing=True,
                reverse_missing_reason="Physical one-way hardware data diode isolation (reverse path physically disconnected)",
                completeness_status="COMPLETE",
                confidence_penalty=0.0,
                sensor_notes=notes,
            )

        # 3. Check for Bilateral Visibility (Both directions observed on wire)
        if rev_count > 0:
            ratio = float(forward_packets) / float(rev_count) if rev_count > 0 else 999.0
            if 0.1 <= ratio <= 10.0:
                notes.append(f"Bilateral communication observed: Fwd={forward_packets}, Rev={rev_count} (ratio: {ratio:.2f}).")
                notes.append("Sensor has full visibility of both conversation directions.")
                return SensorVisibilityAssessment(
                    visibility_type=VisibilityType.BILATERAL_OBSERVED_BOTH_WAYS,
                    is_reverse_direction_missing=False,
                    reverse_missing_reason="Reverse direction active and visible",
                    completeness_status="COMPLETE",
                    confidence_penalty=0.0,
                    sensor_notes=notes,
                )
            else:
                notes.append(f"Asymmetric bilateral traffic observed: Fwd={forward_packets}, Rev={rev_count} (ratio: {ratio:.2f}).")
                notes.append("Both directions captured, but volume asymmetry is statistically significant.")
                return SensorVisibilityAssessment(
                    visibility_type=VisibilityType.BILATERAL_OBSERVED_BOTH_WAYS,
                    is_reverse_direction_missing=False,
                    reverse_missing_reason="Reverse direction present but heavily asymmetric",
                    completeness_status="COMPLETE",
                    confidence_penalty=0.05,
                    sensor_notes=notes,
                )

        # 4. Check for Asymmetric Routing / Transit SPAN
        if self.context.observation_point == ObservationPoint.ASYMMETRIC_SPAN:
            notes.append("Sensor is configured on an asymmetric transit link.")
            notes.append("Return packets likely travel via an alternative gateway or BGP routing path.")
            return SensorVisibilityAssessment(
                visibility_type=VisibilityType.POTENTIAL_ASYMMETRIC_ROUTING,
                is_reverse_direction_missing=True,
                reverse_missing_reason="Known asymmetric routing topology: return path bypasses this sensor",
                completeness_status="PARTIAL",
                confidence_penalty=0.20,
                sensor_notes=notes,
            )

        # 5. Check for Capture Limitation / Drops
        if self.context.buffer_drops_detected or self.context.sampling_rate < 0.99:
            notes.append(f"Packet capture constraints active (sampling={self.context.sampling_rate:.2f}, buffer drops={self.context.buffer_drops_detected}).")
            notes.append("Return packets may have been dropped before ring buffer ingestion.")
            return SensorVisibilityAssessment(
                visibility_type=VisibilityType.CAPTURE_LIMITATION_ARTEFACT,
                is_reverse_direction_missing=True,
                reverse_missing_reason="Capture limitation or packet drop suspected",
                completeness_status="PARTIAL",
                confidence_penalty=0.25,
                sensor_notes=notes,
            )

        # 6. Default: Bilateral capable sensor, but zero reverse packets were observed
        notes.append(f"Sensor is bilateral-capable ({self.context.observation_point.value}), but 0 return packets were captured across {forward_packets} forward packets.")
        if proto == 6:  # TCP
            if has_syn and not has_ack:
                notes.append("TCP SYN observed without return SYN-ACK/ACK. Possible unanswered probe, scan, or unresponsive target.")
            elif has_ack:
                notes.append("TCP data/ACK stream without return acknowledgments. Possible data exfiltration, blind push, or asymmetric return.")
        elif proto == 17:  # UDP
            notes.append("UDP unidirectional flow. Normal for syslog, streaming, SNMP traps, or UDP flood attack.")
        elif proto == 1:   # ICMP
            notes.append("ICMP unidirectional echo without reply.")

        return SensorVisibilityAssessment(
            visibility_type=VisibilityType.BILATERAL_CAPABLE_OBSERVED_ONE_WAY,
            is_reverse_direction_missing=True,
            reverse_missing_reason="No reverse packets observed on wire during entire flow lifetime",
            completeness_status="COMPLETE",
            confidence_penalty=0.0,
            sensor_notes=notes,
        )
