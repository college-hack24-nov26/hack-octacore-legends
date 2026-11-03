"""Report History Manager for UniGuard AI Security Reports.

Handles queries, deletions, and operating system file/folder launches.
"""

from __future__ import annotations

import os
import sys
import subprocess
from typing import Dict, Any, List, Optional

from uniguard.database.storage import SecurityDatabase


class ReportHistoryManager:
    """Manages report audit trails and file system interactions."""

    def __init__(self, db: Optional[SecurityDatabase] = None) -> None:
        self.db = db or SecurityDatabase()

    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves history of generated reports."""
        return self.db.get_report_history(limit=limit)

    def get_kpi_summary(self) -> Dict[str, Any]:
        """Calculates report overview KPIs."""
        return self.db.get_reports_kpi_summary()

    def delete_report(self, report_id: str, delete_file: bool = False) -> bool:
        """Deletes a report entry from the database, optionally deleting the file on disk."""
        if delete_file:
            report = self.db.get_report_by_id(report_id)
            if report and report.get("file_path"):
                path = report["file_path"]
                if os.path.isfile(path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass
        return self.db.delete_report(report_id)

    @staticmethod
    def open_file(file_path: str) -> bool:
        """Opens a document in the default system viewer cross-platform."""
        if not file_path or not os.path.exists(file_path):
            return False
        try:
            if sys.platform == "win32":
                os.startfile(os.path.normpath(file_path))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", file_path])
            else:
                subprocess.Popen(["xdg-open", file_path])
            return True
        except Exception:
            return False

    @staticmethod
    def open_folder(file_path: str) -> bool:
        """Opens the directory containing the file and selects it if possible."""
        if not file_path:
            return False
        directory = os.path.dirname(os.path.abspath(file_path))
        if not os.path.exists(directory):
            return False
        try:
            if sys.platform == "win32":
                norm_file = os.path.normpath(file_path)
                if os.path.exists(norm_file):
                    subprocess.Popen(f'explorer /select,"{norm_file}"')
                else:
                    os.startfile(directory)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", file_path])
            else:
                subprocess.Popen(["xdg-open", directory])
            return True
        except Exception:
            return False

