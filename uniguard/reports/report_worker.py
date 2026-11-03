"""Background Worker Thread for Non-Blocking Security Report Generation.

Ensures that the PySide6 desktop GUI remains 100% responsive while
complex PDF documents and analytical charts are rendered.
"""

from __future__ import annotations

import traceback
from typing import Dict, Any, Optional

from PySide6.QtCore import QThread, Signal

from uniguard.reports.report_builder import SecurityReportBuilder


class ReportWorkerThread(QThread):
    """Executes report compilation inside a separate background thread."""

    progress_updated = Signal(int, str)
    report_finished = Signal(dict)
    report_failed = Signal(str)

    def __init__(
        self,
        report_name: str,
        report_type: str,
        date_range_code: str,
        export_format: str,
        custom_start: Optional[float] = None,
        custom_end: Optional[float] = None,
        builder: Optional[SecurityReportBuilder] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.report_name = report_name
        self.report_type = report_type
        self.date_range_code = date_range_code
        self.export_format = export_format
        self.custom_start = custom_start
        self.custom_end = custom_end
        self.builder = builder or SecurityReportBuilder()
        self._is_cancelled = False

    def cancel(self) -> None:
        """Flags the worker to stop processing if possible."""
        self._is_cancelled = True

    def run(self) -> None:
        """Executes the report build process and emits lifecycle signals."""
        try:
            def on_progress(pct: int, msg: str):
                if not self._is_cancelled:
                    self.progress_updated.emit(pct, msg)

            on_progress(5, "Initializing report generation worker...")

            result = self.builder.build_report(
                report_name=self.report_name,
                report_type=self.report_type,
                date_range_code=self.date_range_code,
                export_format=self.export_format,
                custom_start=self.custom_start,
                custom_end=self.custom_end,
                progress_callback=on_progress,
            )

            if not self._is_cancelled:
                self.report_finished.emit(result)
        except Exception as ex:
            err_msg = f"{str(ex)}\n{traceback.format_exc()}"
            self.report_failed.emit(err_msg)

