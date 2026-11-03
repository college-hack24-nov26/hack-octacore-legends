"""Report Builder for UniGuard AI Security Reports.

Orchestrates data collection, analytics compilation, multi-format export
(PDF, CSV, JSON), and database history persistence.
"""

from __future__ import annotations

import os
import uuid
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple

from uniguard.database.storage import SecurityDatabase
from uniguard.reports.report_data_collector import ReportDataCollector
from uniguard.reports.pdf_generator import PdfReportGenerator
from uniguard.reports.csv_exporter import CsvReportExporter
from uniguard.reports.json_exporter import JsonReportExporter


DEFAULT_REPORTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "reports_output")
)


class SecurityReportBuilder:
    """Coordinates end-to-end report generation across formats and engines."""

    def __init__(
        self,
        db: Optional[SecurityDatabase] = None,
        output_dir: Optional[str] = None,
    ) -> None:
        self.db = db or SecurityDatabase()
        self.output_dir = output_dir or DEFAULT_REPORTS_DIR
        os.makedirs(self.output_dir, exist_ok=True)

        self.collector = ReportDataCollector(self.db)
        self.pdf_generator = PdfReportGenerator()
        self.csv_exporter = CsvReportExporter()
        self.json_exporter = JsonReportExporter()

    def calculate_timerange(
        self,
        range_code: str,
        custom_start: Optional[float] = None,
        custom_end: Optional[float] = None,
    ) -> Tuple[Optional[float], Optional[float], str]:
        """Resolves date range code to start and end epoch timestamps."""
        now = time.time()
        range_code = (range_code or "LAST_24_HOURS").upper().strip()

        if range_code in ("TODAY", "CURRENT_DAY"):
            dt_now = datetime.now()
            start_dt = datetime(dt_now.year, dt_now.month, dt_now.day)
            return start_dt.timestamp(), now, "Today (Since Midnight)"
        elif range_code in ("LAST_24_HOURS", "24H", "24_HOURS"):
            return now - 86400, now, "Last 24 Hours"
        elif range_code in ("LAST_7_DAYS", "7D", "7_DAYS"):
            return now - (7 * 86400), now, "Last 7 Days"
        elif range_code in ("LAST_30_DAYS", "30D", "30_DAYS"):
            return now - (30 * 86400), now, "Last 30 Days"
        elif range_code in ("CUSTOM", "CUSTOM_RANGE"):
            start = custom_start if custom_start is not None else (now - 86400)
            end = custom_end if custom_end is not None else now
            s_str = datetime.fromtimestamp(start).strftime("%Y-%m-%d %H:%M")
            e_str = datetime.fromtimestamp(end).strftime("%Y-%m-%d %H:%M")
            return start, end, f"Custom ({s_str} - {e_str})"
        elif range_code in ("ALL", "ALL_TIME", "ALL_EVENTS"):
            return None, None, "All Monitored Time"
        else:
            return now - 86400, now, "Last 24 Hours"

    def build_report(
        self,
        report_name: str = "UniGuard AI Security Report",
        report_type: str = "EXECUTIVE",
        date_range_code: str = "LAST_24_HOURS",
        export_format: str = "PDF",
        custom_start: Optional[float] = None,
        custom_end: Optional[float] = None,
        progress_callback: Optional[callable] = None,
    ) -> Dict[str, Any]:
        """Executes full report generation pipeline with progress callbacks."""
        report_id = f"RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

        if progress_callback:
            progress_callback(10, "Resolving time boundaries and criteria...")

        start_time, end_time, range_label = self.calculate_timerange(
            date_range_code, custom_start, custom_end
        )

        if progress_callback:
            progress_callback(30, "Collecting network events and flow intelligence from database...")

        report_data = self.collector.collect(
            report_name=report_name,
            report_type=report_type,
            date_range_label=range_label,
            start_time=start_time,
            end_time=end_time,
        )

        exec_summary = report_data.get("section_1_executive_summary", {})
        total_events = exec_summary.get("total_events", 0)
        high_risk_events = exec_summary.get("high_risk_total", 0)
        overview_text = exec_summary.get("overview_text", "")

        format_clean = export_format.upper().strip()
        safe_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in report_name)
        timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{safe_name}_{timestamp_slug}"

        generated_files: Dict[str, str] = {}
        primary_file_path = ""

        # Export according to requested formats
        if format_clean in ("PDF", "ALL"):
            if progress_callback:
                progress_callback(60, "Generating visual charts and compiling PDF document...")
            pdf_path = os.path.join(self.output_dir, f"{base_filename}.pdf")
            self.pdf_generator.generate(report_data, pdf_path)
            generated_files["PDF"] = pdf_path
            if not primary_file_path:
                primary_file_path = pdf_path

        if format_clean in ("CSV", "ALL"):
            if progress_callback:
                progress_callback(80, "Exporting structured CSV data files...")
            csv_path = os.path.join(self.output_dir, f"{base_filename}.csv")
            self.csv_exporter.export(report_data, csv_path)
            generated_files["CSV"] = csv_path
            if not primary_file_path:
                primary_file_path = csv_path

        if format_clean in ("JSON", "ALL"):
            if progress_callback:
                progress_callback(90, "Serializing schema-compliant JSON report...")
            json_path = os.path.join(self.output_dir, f"{base_filename}.json")
            self.json_exporter.export(report_data, json_path)
            generated_files["JSON"] = json_path
            if not primary_file_path:
                primary_file_path = json_path

        # Save metadata to database history
        if progress_callback:
            progress_callback(95, "Recording report metadata in SQLite repository...")

        report_meta_record = {
            "report_id": report_id,
            "report_name": report_name,
            "report_type": report_type,
            "date_range": range_label,
            "start_time": start_time,
            "end_time": end_time,
            "export_format": format_clean,
            "file_path": primary_file_path,
            "timestamp": time.time(),
            "status": "COMPLETED",
            "total_events": total_events,
            "high_risk_events": high_risk_events,
            "summary_text": overview_text,
        }
        self.db.insert_report(report_meta_record)

        if progress_callback:
            progress_callback(100, "Security report generation complete.")

        return {
            "report_id": report_id,
            "report_name": report_name,
            "report_type": report_type,
            "format": format_clean,
            "primary_file_path": primary_file_path,
            "files": generated_files,
            "report_data": report_data,
            "metadata_record": report_meta_record,
        }

