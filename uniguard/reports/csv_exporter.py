"""CSV Export Utility for UniGuard AI Security Reports.

Produces structured, UTF-8 CSV exports containing executive metrics,
threat summaries, and high-risk security event records.
"""

from __future__ import annotations

import csv
import os
from typing import Dict, Any, List


class CsvReportExporter:
    """Exports cybersecurity reports to structured, UTF-8 CSV files."""

    def export(self, report_data: Dict[str, Any], output_path: str) -> str:
        """Writes report metadata, threat breakdown, and event records to CSV."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        meta = report_data.get("metadata", {})
        exec_sum = report_data.get("section_1_executive_summary", {})
        threat_sum = report_data.get("section_4_threat_summary", {})
        high_risk_events = report_data.get("section_5_high_risk_events", [])
        utie_data = report_data.get("section_3_utie_intelligence", {})

        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)

            # Metadata Section
            writer.writerow(["# UNIGUARD AI SECURITY AUDIT REPORT"])
            writer.writerow(["Report Name", meta.get("report_name", "Security Report")])
            writer.writerow(["Report Type", meta.get("report_type", "EXECUTIVE")])
            writer.writerow(["Date Range", meta.get("date_range_label", "ALL")])
            writer.writerow(["Generated At", meta.get("generated_at_str", "")])
            writer.writerow([])

            # Executive Summary Section
            writer.writerow(["# SECTION 1: EXECUTIVE SUMMARY"])
            writer.writerow(["Metric", "Value"])
            writer.writerow(["Total Events Analyzed", exec_sum.get("total_events", 0)])
            writer.writerow(["High-Risk Events", exec_sum.get("high_risk_total", 0)])
            writer.writerow(["Critical Severity Events", exec_sum.get("critical_events", 0)])
            writer.writerow(["High Severity Events", exec_sum.get("high_events", 0)])
            writer.writerow(["Primary Threat Identified", exec_sum.get("top_threat", "None")])
            writer.writerow(["Average Risk Score", exec_sum.get("average_risk_score", 0.0)])
            writer.writerow(["Maximum Risk Score", exec_sum.get("max_risk_score", 0)])
            writer.writerow(["Unidirectional Traffic Ratio (%)", utie_data.get("unidirectional_percentage", 0.0)])
            writer.writerow([])

            # Threat Distribution Section
            writer.writerow(["# SECTION 2: THREAT CLASSIFICATION BREAKDOWN"])
            writer.writerow(["Threat Category", "Detection Count"])
            for t_cat, count in threat_sum.get("threat_distribution", {}).items():
                writer.writerow([t_cat, count])
            writer.writerow([])

            # High-Risk Security Events Table
            writer.writerow(["# SECTION 3: HIGH-RISK SECURITY EVENTS"])
            headers = [
                "Event ID",
                "Timestamp",
                "Source IP",
                "Destination IP",
                "Source Port",
                "Destination Port",
                "Protocol",
                "Threat Type",
                "Risk Score",
                "Severity",
                "Confidence (%)",
                "Directionality",
            ]
            writer.writerow(headers)

            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            for e in high_risk_events:
                p_val = e.get("proto", 6)
                p_str = proto_map.get(p_val, str(p_val))
                writer.writerow([
                    e.get("event_id", ""),
                    e.get("timestamp_str", ""),
                    e.get("src_ip", ""),
                    e.get("dst_ip", ""),
                    e.get("src_port", ""),
                    e.get("dst_port", ""),
                    p_str,
                    e.get("threat_type", ""),
                    e.get("risk_score", 0),
                    e.get("severity", ""),
                    e.get("confidence_pct", 0.0),
                    e.get("directionality", "UNKNOWN"),
                ])

        return output_path

