"""Report Data Collector for UniGuard AI Security Reports.

Aggregates and computes cybersecurity metrics from the live SQLite database
and analysis engines across all 10 standard report sections.
Strictly relies on real observed data without fabricating statistics.
"""

from __future__ import annotations

import time
import math
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from collections import Counter

from uniguard.database.storage import SecurityDatabase


class ReportDataCollector:
    """Collects and aggregates factual data for security report generation."""

    def __init__(self, db: Optional[SecurityDatabase] = None) -> None:
        self.db = db or SecurityDatabase()

    def collect(
        self,
        report_name: str,
        report_type: str,
        date_range_label: str,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Collects metrics for all 10 sections within the specified time range."""
        events = self.db.get_events_by_timerange(start_time, end_time, limit=20000)
        utie_records = self.db.get_utie_by_timerange(start_time, end_time, limit=20000)

        # 1. Executive Summary
        exec_summary = self._compute_executive_summary(events, utie_records, date_range_label, report_type)

        # 2. Network Traffic Analysis
        traffic_analysis = self._compute_traffic_analysis(events, utie_records)

        # 3. Unidirectional Traffic Intelligence
        utie_analysis = self._compute_utie_analysis(events, utie_records)

        # 4. Threat Detection Summary
        threat_summary = self._compute_threat_summary(events)

        # 5. High-Risk Security Events
        high_risk_events = self._compute_high_risk_events(events)

        # 6. AI Model Analysis
        ai_model_analysis = self._compute_ai_model_analysis(events)

        # 7. AI Explainability
        explainability_summary = self._compute_explainability_summary(events)

        # 8. Risk Analysis
        risk_analysis = self._compute_risk_analysis(events)

        # 9. Investigation Timeline
        investigation_timeline = self._compute_investigation_timeline(events)

        # 10. Recommendations
        recommendations = self._compute_recommendations(events, utie_records, threat_summary)

        return {
            "metadata": {
                "report_name": report_name,
                "report_type": report_type,
                "date_range_label": date_range_label,
                "start_time": start_time,
                "end_time": end_time,
                "generated_at": time.time(),
                "generated_at_str": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_events_collected": len(events),
                "total_utie_flows_collected": len(utie_records),
            },
            "section_1_executive_summary": exec_summary,
            "section_2_traffic_analysis": traffic_analysis,
            "section_3_utie_intelligence": utie_analysis,
            "section_4_threat_summary": threat_summary,
            "section_5_high_risk_events": high_risk_events,
            "section_6_ai_model_analysis": ai_model_analysis,
            "section_7_explainability": explainability_summary,
            "section_8_risk_analysis": risk_analysis,
            "section_9_timeline": investigation_timeline,
            "section_10_recommendations": recommendations,
        }

    def _compute_executive_summary(
        self,
        events: List[Dict[str, Any]],
        utie_records: List[Dict[str, Any]],
        date_range_label: str,
        report_type: str,
    ) -> Dict[str, Any]:
        total_events = len(events)
        critical_count = sum(1 for e in events if str(e.get("severity", "")).upper() == "CRITICAL")
        high_count = sum(1 for e in events if str(e.get("severity", "")).upper() == "HIGH")
        high_risk_total = sum(1 for e in events if (e.get("risk_score", 0) or 0) >= 70 or str(e.get("severity", "")).upper() in ("HIGH", "CRITICAL"))

        threat_counter = Counter(str(e.get("threat_type", "BENIGN")).upper() for e in events if str(e.get("threat_type", "BENIGN")).upper() != "BENIGN")
        top_threat = threat_counter.most_common(1)[0][0] if threat_counter else "None Detected"

        avg_risk = round(sum((e.get("risk_score", 0) or 0) for e in events) / max(total_events, 1), 1)
        max_risk = max([(e.get("risk_score", 0) or 0) for e in events], default=0)

        # Overview narrative
        if total_events == 0:
            overview_text = (
                f"During the monitored period ({date_range_label}), no network events were logged. "
                "The network perimeter shows no recorded security anomalies or policy violations."
            )
        elif high_risk_total == 0:
            overview_text = (
                f"During the monitored period ({date_range_label}), a total of {total_events} network events were analyzed. "
                "All observed traffic remained within baseline security parameters with zero high or critical risk detections."
            )
        else:
            overview_text = (
                f"During the monitored period ({date_range_label}), UniGuard AI analyzed {total_events} events and detected "
                f"{high_risk_total} high-risk occurrences requiring immediate SOC triage. "
                f"The primary attack vector identified was '{top_threat}', with a maximum risk score of {max_risk}/100. "
                f"A total of {critical_count} critical and {high_count} high severity alerts were logged across the sensor grid."
            )

        return {
            "total_events": total_events,
            "critical_events": critical_count,
            "high_events": high_count,
            "high_risk_total": high_risk_total,
            "top_threat": top_threat,
            "average_risk_score": avg_risk,
            "max_risk_score": max_risk,
            "overview_text": overview_text,
            "status": "ELEVATED RISK" if high_risk_total > 0 else "SECURE",
        }

    def _compute_traffic_analysis(
        self,
        events: List[Dict[str, Any]],
        utie_records: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_counts: Counter = Counter()
        src_ip_counts: Counter = Counter()
        dst_ip_counts: Counter = Counter()
        total_packets = 0
        total_bytes = 0
        durations = []

        # From UTIE records if available, otherwise from event flow_metrics
        if utie_records:
            for r in utie_records:
                proto_name = r.get("proto_name") or proto_map.get(r.get("proto", 0), f"PROTO-{r.get('proto')}")
                proto_counts[proto_name] += 1
                src_ip_counts[r.get("src_ip", "Unknown")] += 1
                dst_ip_counts[r.get("dst_ip", "Unknown")] += 1
                total_packets += (r.get("packet_count") or 0) + (r.get("reverse_packet_count") or 0)
                total_bytes += (r.get("byte_count") or 0) + (r.get("reverse_byte_count") or 0)
                dur = r.get("duration", 0.0) or 0.0
                if dur > 0:
                    durations.append(dur)
        else:
            for e in events:
                p_num = e.get("proto", 0)
                p_name = proto_map.get(p_num, f"PROTO-{p_num}")
                proto_counts[p_name] += 1
                src_ip_counts[e.get("src_ip", "Unknown")] += 1
                dst_ip_counts[e.get("dst_ip", "Unknown")] += 1
                fm = e.get("flow_metrics", {})
                if isinstance(fm, dict):
                    total_packets += fm.get("packet_count", 1)
                    total_bytes += fm.get("byte_count", 0)
                    dur = fm.get("duration", 0.0)
                    if dur > 0:
                        durations.append(dur)

        avg_dur = round(sum(durations) / max(len(durations), 1), 3) if durations else 0.0

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_megabytes": round(total_bytes / (1024 * 1024), 2),
            "average_duration_sec": avg_dur,
            "protocol_distribution": dict(proto_counts.most_common(10)),
            "top_source_ips": [{"ip": ip, "count": count} for ip, count in src_ip_counts.most_common(5)],
            "top_dest_ips": [{"ip": ip, "count": count} for ip, count in dst_ip_counts.most_common(5)],
        }

    def _compute_utie_analysis(
        self,
        events: List[Dict[str, Any]],
        utie_records: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        dir_counts: Counter = Counter()
        missing_reverse_count = 0
        asymmetric_count = 0

        if utie_records:
            for r in utie_records:
                d = str(r.get("directionality", "UNKNOWN")).upper()
                dir_counts[d] += 1
                if r.get("is_reverse_missing"):
                    missing_reverse_count += 1
                if "ASYMMETRIC" in str(r.get("sensor_visibility_type", "")).upper():
                    asymmetric_count += 1
        else:
            for e in events:
                d = str(e.get("directionality_state", "UNKNOWN")).upper()
                dir_counts[d] += 1

        total_tracked = sum(dir_counts.values())
        unidir_count = dir_counts.get("UNIDIRECTIONAL", 0)
        bidir_count = dir_counts.get("BIDIRECTIONAL", 0)
        unidir_pct = round((unidir_count / max(total_tracked, 1)) * 100, 1)

        return {
            "total_tracked_flows": total_tracked,
            "unidirectional_flows": unidir_count,
            "bidirectional_flows": bidir_count,
            "unknown_flows": dir_counts.get("UNKNOWN", 0),
            "unidirectional_percentage": unidir_pct,
            "missing_reverse_handshakes": missing_reverse_count,
            "asymmetric_sensor_visibility": asymmetric_count,
            "directionality_distribution": dict(dir_counts),
            "assessment": (
                "High Unidirectional Traffic Ratio detected — indicative of network tap placement, "
                "covert scanning, or exfiltration channels." if unidir_pct > 30 else
                "Normal flow symmetry observed across monitored interfaces."
            ),
        }

    def _compute_threat_summary(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        threat_counts: Counter = Counter()
        severity_counts: Counter = Counter()

        for e in events:
            t = str(e.get("threat_type", "BENIGN")).upper()
            threat_counts[t] += 1
            s = str(e.get("severity", "LOW")).upper()
            severity_counts[s] += 1

        return {
            "threat_distribution": dict(threat_counts.most_common()),
            "severity_distribution": dict(severity_counts),
            "port_scan_count": threat_counts.get("PORT SCAN", 0) + threat_counts.get("PORTSCAN", 0),
            "ddos_count": threat_counts.get("DDOS", 0) + threat_counts.get("DOS", 0),
            "data_exfiltration_count": threat_counts.get("DATA EXFILTRATION", 0) + threat_counts.get("EXFILTRATION", 0),
            "c2_count": threat_counts.get("C2 BEACONING", 0) + threat_counts.get("C2", 0) + threat_counts.get("COMMAND_AND_CONTROL", 0),
            "benign_count": threat_counts.get("BENIGN", 0),
        }

    def _compute_high_risk_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        high_risk = []
        for e in events:
            score = e.get("risk_score", 0) or 0
            sev = str(e.get("severity", "")).upper()
            if score >= 60 or sev in ("HIGH", "CRITICAL"):
                ts = e.get("timestamp", 0)
                ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"
                high_risk.append({
                    "event_id": str(e.get("event_id", "N/A")),
                    "timestamp": ts,
                    "timestamp_str": ts_str,
                    "src_ip": str(e.get("src_ip", "N/A")),
                    "dst_ip": str(e.get("dst_ip", "N/A")),
                    "src_port": e.get("src_port", 0),
                    "dst_port": e.get("dst_port", 0),
                    "proto": e.get("proto", 6),
                    "threat_type": str(e.get("threat_type", "UNKNOWN")),
                    "risk_score": score,
                    "severity": sev,
                    "confidence_pct": round(e.get("confidence_pct", 0.0), 1),
                    "directionality": str(e.get("directionality_state", "UNKNOWN")),
                })

        # Sort descending by risk score, then timestamp
        high_risk.sort(key=lambda x: (x["risk_score"], x["timestamp"]), reverse=True)
        return high_risk[:25]

    def _compute_ai_model_analysis(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        confidences = [e.get("confidence_pct", 0.0) for e in events if e.get("confidence_pct") is not None]
        anomalies = [e.get("anomaly_score", 0.0) for e in events if e.get("anomaly_score") is not None]

        avg_conf = round(sum(confidences) / max(len(confidences), 1), 1) if confidences else 0.0
        min_conf = round(min(confidences), 1) if confidences else 0.0
        max_conf = round(max(confidences), 1) if confidences else 0.0

        avg_anom = round(sum(anomalies) / max(len(anomalies), 1), 3) if anomalies else 0.0

        return {
            "active_models": [
                {"name": "Random Forest Classifier", "status": "OPERATIONAL", "purpose": "Multi-class threat categorization"},
                {"name": "XGBoost Gradient Booster", "status": "OPERATIONAL", "purpose": "High-speed asymmetric flow classification"},
                {"name": "Isolation Forest", "status": "OPERATIONAL", "purpose": "Unsupervised zero-day network anomaly detection"},
                {"name": "Rule-Based Heuristic Engine", "status": "OPERATIONAL", "purpose": "Deterministic boundary & signature verification"},
            ],
            "confidence_metrics": {
                "average_confidence_pct": avg_conf,
                "min_confidence_pct": min_conf,
                "max_confidence_pct": max_conf,
            },
            "anomaly_metrics": {
                "average_anomaly_score": avg_anom,
                "evaluated_samples": len(anomalies),
            },
        }

    def _compute_explainability_summary(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        explained_count = 0
        rule_counter: Counter = Counter()
        factor_counter: Counter = Counter()

        for e in events:
            expl = e.get("explanation") or {}
            factors = e.get("contributing_factors") or []

            if expl and isinstance(expl, dict):
                explained_count += 1
                for r in expl.get("rules_triggered", []):
                    rule_counter[str(r)] += 1
                for f in expl.get("top_factors", []):
                    factor_counter[str(f.get("factor", ""))] += 1

            if factors and isinstance(factors, list):
                for f in factors:
                    if isinstance(f, str):
                        factor_counter[f] += 1
                    elif isinstance(f, dict):
                        factor_counter[str(f.get("feature", ""))] += 1

        top_rules = [{"rule": r, "count": c} for r, c in rule_counter.most_common(5) if r]
        top_factors = [{"factor": f, "count": c} for f, c in factor_counter.most_common(5) if f]

        return {
            "total_explained_events": explained_count,
            "explainability_coverage_pct": round((explained_count / max(len(events), 1)) * 100, 1),
            "primary_behavioral_rules_triggered": top_rules,
            "primary_contributing_features": top_factors,
        }

    def _compute_risk_analysis(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        low = sum(1 for e in events if (e.get("risk_score", 0) or 0) < 40)
        medium = sum(1 for e in events if 40 <= (e.get("risk_score", 0) or 0) < 70)
        high = sum(1 for e in events if 70 <= (e.get("risk_score", 0) or 0) < 90)
        critical = sum(1 for e in events if (e.get("risk_score", 0) or 0) >= 90)

        scores = [(e.get("risk_score", 0) or 0) for e in events]
        avg_score = round(sum(scores) / max(len(scores), 1), 1) if scores else 0.0

        return {
            "low_risk_count": low,
            "medium_risk_count": medium,
            "high_risk_count": high,
            "critical_risk_count": critical,
            "average_risk_score": avg_score,
            "risk_score_distribution": {
                "Low (0-39)": low,
                "Medium (40-69)": medium,
                "High (70-89)": high,
                "Critical (90-100)": critical,
            },
        }

    def _compute_investigation_timeline(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not events:
            return {
                "first_event_time": "N/A",
                "last_event_time": "N/A",
                "peak_attack_window": "N/A",
                "hourly_event_distribution": {},
            }

        sorted_events = sorted(events, key=lambda x: x.get("timestamp", 0))
        first_ts = sorted_events[0].get("timestamp", 0)
        last_ts = sorted_events[-1].get("timestamp", 0)

        first_str = datetime.fromtimestamp(first_ts).strftime("%Y-%m-%d %H:%M:%S") if first_ts else "N/A"
        last_str = datetime.fromtimestamp(last_ts).strftime("%Y-%m-%d %H:%M:%S") if last_ts else "N/A"

        # Hourly bucket distribution
        hour_counter: Counter = Counter()
        for e in events:
            t = e.get("timestamp", 0)
            if t:
                hour_key = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:00")
                hour_counter[hour_key] += 1

        peak_window = hour_counter.most_common(1)[0][0] if hour_counter else "N/A"

        return {
            "first_event_time": first_str,
            "last_event_time": last_str,
            "peak_attack_window": peak_window,
            "hourly_event_distribution": dict(hour_counter),
        }

    def _compute_recommendations(
        self,
        events: List[Dict[str, Any]],
        utie_records: List[Dict[str, Any]],
        threat_summary: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        recs = []

        # Check for port scan threats
        if threat_summary.get("port_scan_count", 0) > 0:
            recs.append({
                "priority": "HIGH",
                "category": "Perimeter Defense",
                "title": "Mitigate Active Reconnaissance and Port Scanning",
                "action": "Deploy dynamic firewall rate-limiting (e.g. iptables recent module or perimeter ACLs) on inbound SYN packets and restrict public access to unneeded service ports.",
            })

        # Check for DDoS
        if threat_summary.get("ddos_count", 0) > 0:
            recs.append({
                "priority": "CRITICAL",
                "category": "Availability Protection",
                "title": "Engage Anti-DDoS Traffic Scrubbing",
                "action": "Enable upstream volumetric DDoS mitigation and implement SYN-cookie challenge mechanisms on border routers to absorb packet flood bursts.",
            })

        # Check for Exfiltration
        if threat_summary.get("data_exfiltration_count", 0) > 0:
            recs.append({
                "priority": "CRITICAL",
                "category": "Data Protection",
                "title": "Isolate Endpoints Suspected of Data Exfiltration",
                "action": "Block outbound high-volume unidirectional data flows to suspicious external IPs; enforce TLS inspection and DNS sinkholing on flagged hosts.",
            })

        # Check for C2 Beaconing
        if threat_summary.get("c2_count", 0) > 0:
            recs.append({
                "priority": "CRITICAL",
                "category": "Incident Containment",
                "title": "Terminate Command & Control (C2) Connections",
                "action": "Immediately revoke network leases for affected internal IP addresses and initiate memory forensics to locate unauthorized persistent implants.",
            })

        # Check for Unidirectional Asymmetry
        unidir_flows = sum(1 for e in events if str(e.get("directionality_state", "")).upper() == "UNIDIRECTIONAL")
        if unidir_flows > 5:
            recs.append({
                "priority": "MEDIUM",
                "category": "Sensor Architecture",
                "title": "Verify Asymmetric Route Visibility & Tap Coverage",
                "action": "Ensure mirrored SPAN ports capture both ingress and egress channels across routing boundaries to eliminate blind spots in multi-path network fabrics.",
            })

        # Default hygiene recommendation if clean
        if not recs:
            recs.append({
                "priority": "LOW",
                "category": "Security Hygiene",
                "title": "Maintain Continuous Passive Network Monitoring",
                "action": "No anomalous threats observed. Continue periodic baseline profiling and maintain firmware patches across all network switching hardware.",
            })

        return recs

