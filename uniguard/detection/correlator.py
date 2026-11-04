"""Security Incident Correlator and Alert Aggregator for UniGuard AI.

Aggregates individual SecurityEvent objects across temporal windows and network 5-tuples
into actionable high-level SecurityIncident objects to eliminate alert fatigue,
accurately distinguish SYN Flood from Port Scan attacks, and provide SOC-ready triage summaries.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict

from uniguard.detection.engine import SecurityEvent


PROTO_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
}


def format_protocol(proto: int) -> str:
    """Returns human-readable protocol string (e.g., 'TCP', 'UDP', 'ICMP')."""
    return PROTO_MAP.get(int(proto), f"P{proto}")


@dataclass
class SecurityIncident:
    """High-level security incident aggregating multiple related flow events."""
    incident_id: str
    incident_type: str
    src_ip: str
    dst_ip: str
    target_ports: List[int]
    protocol: str
    event_count: int
    packet_count: int
    byte_count: int
    start_time: float
    end_time: float
    duration: float
    severity: str
    risk_score: int
    confidence_pct: float
    summary: str
    tactics: List[str]
    recommendations: List[str]
    event_ids: List[str]
    events: List[SecurityEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes incident to dictionary without cyclic raw event references."""
        data = asdict(self)
        data.pop("events", None)
        data["event_count"] = self.event_count
        data["ports_probed"] = len(self.target_ports)
        data["start_time_iso"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.start_time))
        data["end_time_iso"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.end_time))
        return data


class SecurityIncidentCorrelator:
    """Correlates individual flow-level security events into comprehensive security incidents."""

    def __init__(self, time_window_sec: float = 60.0) -> None:
        self.time_window_sec = time_window_sec
        self._incident_counter: int = 0
        self._active_groups: Dict[Tuple[str, str], List[SecurityEvent]] = {}

    def correlate_events(self, events: List[SecurityEvent]) -> List[SecurityIncident]:
        """Correlates a batch of SecurityEvents into aggregated SecurityIncidents.

        Preserves all underlying events while eliminating redundant alerts and correctly
        distinguishing SYN Flood (single port, high volume) from Port Scan (multiple ports).
        """
        # Filter out informational benign events that were not flagged as threats
        threat_events = [e for e in events if e.threat_type != "BENIGN" and e.risk_score >= 35]
        if not threat_events:
            return []

        # Group by (src_ip, dst_ip)
        host_groups: Dict[Tuple[str, str], List[SecurityEvent]] = {}
        for ev in threat_events:
            group_key = (ev.src_ip, ev.dst_ip)
            if group_key not in host_groups:
                host_groups[group_key] = []
            host_groups[group_key].append(ev)

        incidents: List[SecurityIncident] = []

        for (src_ip, dst_ip), group in host_groups.items():
            incidents.extend(self._correlate_host_group(src_ip, dst_ip, group))

        # Sort incidents by severity / risk descending
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
        incidents.sort(key=lambda inc: (severity_rank.get(inc.severity, 0), inc.risk_score), reverse=True)

        return incidents

    def _correlate_host_group(
        self, src_ip: str, dst_ip: str, group: List[SecurityEvent]
    ) -> List[SecurityIncident]:
        """Correlates events between a specific source and destination host pair."""
        incidents: List[SecurityIncident] = []
        group.sort(key=lambda e: e.timestamp)

        # Distinguish distinct destination ports
        ports = sorted(list(set(e.dst_port for e in group)))
        protos = sorted(list(set(e.proto for e in group)))
        primary_proto = format_protocol(protos[0]) if protos else "TCP"

        start_time = group[0].timestamp
        end_time = group[-1].timestamp
        duration = max(0.001, end_time - start_time)

        total_packets = sum(int(e.flow_metrics.get("packet_count", 1)) for e in group)
        total_bytes = sum(int(e.flow_metrics.get("byte_count", 0)) for e in group)
        max_risk = max(e.risk_score for e in group)
        avg_conf = sum(e.confidence_pct for e in group) / len(group)
        event_ids = [e.event_id for e in group]

        # Case 1: Multiple requests targeting the EXACT SAME destination port -> SYN FLOOD / DoS
        if len(ports) == 1 and len(group) >= 3:
            target_port = ports[0]
            self._incident_counter += 1
            inc_id = f"INC-{int(time.time())}-{self._incident_counter:03d}"

            # Update underlying events to correctly reflect SYN_FLOOD rather than misclassified PORT_SCAN
            for ev in group:
                if ev.threat_type == "PORT_SCAN":
                    ev.threat_type = "SYN_FLOOD"
                    ev.severity = "CRITICAL" if len(group) >= 50 else "HIGH"
                    ev.risk_score = max(ev.risk_score, 85)

            calculated_rate = total_packets / duration if duration > 0.05 else float(total_packets * 10)
            severity = "CRITICAL" if (len(group) >= 50 or total_packets >= 100) else "HIGH"
            inc_risk = min(100, max(max_risk, 88 if severity == "CRITICAL" else 78))

            summary = (
                f"Host {src_ip} launched a high-rate unidirectional SYN Flood against {dst_ip}:{target_port} "
                f"({len(group)} flows, {total_packets} packets in {duration:.3f}s, ~{calculated_rate:,.1f} pkts/s)."
            )

            tactics = [
                "T1498 - Network Denial of Service (Direct Volumetric SYN Flood)",
                "T1499.002 - Endpoint Denial of Service: Service Exhaustion (Port 80/HTTP)",
                "Ephemeral Source Port Rotation to bypass per-socket rate limiting",
            ]

            recommendations = [
                f"Deploy SYN proxy / SYN cookies on perimeter firewall targeting {dst_ip}:{target_port}.",
                f"Apply egress/ingress rate-limiting rule on upstream router for source host {src_ip}.",
                f"Inspect web/service logs on {dst_ip} for half-open connection table saturation.",
            ]

            incident = SecurityIncident(
                incident_id=inc_id,
                incident_type="SYN_FLOOD",
                src_ip=src_ip,
                dst_ip=dst_ip,
                target_ports=ports,
                protocol=primary_proto,
                event_count=len(group),
                packet_count=total_packets,
                byte_count=total_bytes,
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                severity=severity,
                risk_score=inc_risk,
                confidence_pct=round(avg_conf, 1),
                summary=summary,
                tactics=tactics,
                recommendations=recommendations,
                event_ids=event_ids,
                events=group,
            )
            incidents.append(incident)

        # Case 2: Probing multiple distinct destination ports -> PORT SCAN
        elif len(ports) >= 3:
            self._incident_counter += 1
            inc_id = f"INC-{int(time.time())}-{self._incident_counter:03d}"
            severity = "HIGH" if len(ports) >= 10 else "MEDIUM"
            inc_risk = min(100, max(max_risk, 80 if severity == "HIGH" else 65))

            ports_str = ", ".join(str(p) for p in ports[:8])
            if len(ports) > 8:
                ports_str += f", ... (+{len(ports)-8} more)"

            summary = (
                f"Host {src_ip} conducted a reconnaissance Port Scan against {dst_ip} "
                f"probing {len(ports)} distinct ports ({ports_str}) across {len(group)} connection attempts."
            )

            tactics = [
                "T1046 - Network Service Discovery (Port Scanning)",
                "T1595.001 - Active Scanning: Scanning IP Blocks",
            ]

            recommendations = [
                f"Block scanner host {src_ip} on perimeter intrusion prevention systems (IPS).",
                f"Audit exposed services on {dst_ip} and close unnecessary listener ports.",
                "Review firewall logs to determine if scanner identified open responsive services.",
            ]

            incident = SecurityIncident(
                incident_id=inc_id,
                incident_type="PORT_SCAN",
                src_ip=src_ip,
                dst_ip=dst_ip,
                target_ports=ports,
                protocol=primary_proto,
                event_count=len(group),
                packet_count=total_packets,
                byte_count=total_bytes,
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                severity=severity,
                risk_score=inc_risk,
                confidence_pct=round(avg_conf, 1),
                summary=summary,
                tactics=tactics,
                recommendations=recommendations,
                event_ids=event_ids,
                events=group,
            )
            incidents.append(incident)

        # Case 3: Other threats or small probe events (e.g., DATA_EXFILTRATION, SLOWLORIS)
        else:
            threat_types = list(set(e.threat_type for e in group))
            primary_threat = threat_types[0] if threat_types else "SUSPICIOUS"

            self._incident_counter += 1
            inc_id = f"INC-{int(time.time())}-{self._incident_counter:03d}"
            severity = group[0].severity

            summary = (
                f"Host {src_ip} initiated {len(group)} suspicious flow(s) ({primary_threat}) "
                f"targeting {dst_ip}:{ports[0] if ports else 'any'} [{primary_proto}]."
            )

            tactics = [f"Tactical signature: {primary_threat}"]
            recommendations = [
                f"Inspect network traffic payload and host logs for {src_ip}.",
                f"Verify authorization of activity to destination {dst_ip}.",
            ]

            incident = SecurityIncident(
                incident_id=inc_id,
                incident_type=primary_threat,
                src_ip=src_ip,
                dst_ip=dst_ip,
                target_ports=ports,
                protocol=primary_proto,
                event_count=len(group),
                packet_count=total_packets,
                byte_count=total_bytes,
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                severity=severity,
                risk_score=max_risk,
                confidence_pct=round(avg_conf, 1),
                summary=summary,
                tactics=tactics,
                recommendations=recommendations,
                event_ids=event_ids,
                events=group,
            )
            incidents.append(incident)

        return incidents

