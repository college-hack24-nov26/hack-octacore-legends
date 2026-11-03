"""JSON Export Utility for UniGuard AI Security Reports.

Produces structured, schema-compliant JSON representations of cybersecurity reports.
"""

from __future__ import annotations

import json
import os
from typing import Dict, Any


class JsonReportExporter:
    """Exports cybersecurity reports to structured JSON files."""

    def export(self, report_data: Dict[str, Any], output_path: str) -> str:
        """Serializes report dictionary into an indented, UTF-8 JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        return output_path

