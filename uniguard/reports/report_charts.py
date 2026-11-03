"""Chart Generation Utilities for UniGuard AI Security Reports.

Generates professional, high-resolution figures using Matplotlib's Agg backend.
Charts are embedded directly into PDF reports and interactive desktop previews.
"""

from __future__ import annotations

import os
import tempfile
from typing import Dict, Any, Optional

os.environ.setdefault("MPLCONFIGDIR", tempfile.gettempdir())

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


class ReportChartGenerator:
    """Generates visual analytics charts for cybersecurity reports."""

    def __init__(self, output_dir: Optional[str] = None) -> None:
        self.output_dir = output_dir or os.path.join(tempfile.gettempdir(), "uniguard_report_charts")
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_all_charts(self, report_data: Dict[str, Any]) -> Dict[str, str]:
        """Generates all 4 standard analytical charts and returns their file paths."""
        paths = {}
        paths["threat_distribution"] = self.generate_threat_chart(report_data)
        paths["severity_distribution"] = self.generate_severity_chart(report_data)
        paths["risk_distribution"] = self.generate_risk_chart(report_data)
        paths["directionality_distribution"] = self.generate_directionality_chart(report_data)
        return paths

    def _setup_figure_style(self, fig, ax, title: str):
        """Applies a clean, modern aesthetic suitable for both screen and PDF print."""
        fig.patch.set_facecolor("#ffffff")
        ax.set_facecolor("#f8fafc")
        ax.set_title(title, fontsize=12, fontweight="bold", pad=12, color="#0f172a")
        ax.tick_params(colors="#334155", labelsize=9)
        for spine in ax.spines.values():
            spine.set_color("#cbd5e1")
            spine.set_linewidth(0.8)

    def generate_threat_chart(self, report_data: Dict[str, Any]) -> str:
        """Generates a horizontal bar chart of detected threat classifications."""
        out_path = os.path.join(self.output_dir, "threat_distribution.png")
        threat_dist = report_data.get("section_4_threat_summary", {}).get("threat_distribution", {})

        fig, ax = plt.subplots(figsize=(6, 3.2), dpi=150)
        self._setup_figure_style(fig, ax, "Threat Classification Distribution")

        if not threat_dist:
            ax.text(0.5, 0.5, "No Threat Events Detected", ha="center", va="center", color="#64748b", fontsize=11)
            ax.set_axis_off()
        else:
            threats = list(threat_dist.keys())[:7]
            counts = [threat_dist[t] for t in threats]
            threats.reverse()
            counts.reverse()

            bars = ax.barh(threats, counts, color="#0284c7", edgecolor="#0369a1", height=0.55)
            ax.grid(axis="x", linestyle="--", alpha=0.5, color="#cbd5e1")
            for bar in bars:
                w = bar.get_width()
                ax.text(w + max(max(counts) * 0.02, 0.5), bar.get_y() + bar.get_height() / 2, f"{int(w)}",
                        va="center", ha="left", fontsize=9, color="#0f172a", fontweight="bold")
            ax.set_xlim(0, max(counts) * 1.18 if counts else 10)

        fig.tight_layout()
        fig.savefig(out_path, dpi=150, facecolor=fig.get_facecolor(), bbox_inches="tight")
        plt.close(fig)
        return out_path

    def generate_severity_chart(self, report_data: Dict[str, Any]) -> str:
        """Generates a donut chart displaying event severity proportions."""
        out_path = os.path.join(self.output_dir, "severity_distribution.png")
        sev_dist = report_data.get("section_4_threat_summary", {}).get("severity_distribution", {})

        fig, ax = plt.subplots(figsize=(5, 3.2), dpi=150)
        self._setup_figure_style(fig, ax, "Security Events by Severity")

        labels = []
        sizes = []
        colors = []
        color_map = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#10b981",
            "INFORMATIONAL": "#3b82f6",
        }

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sev_dist.get(sev, 0)
            if count > 0:
                labels.append(sev)
                sizes.append(count)
                colors.append(color_map.get(sev, "#94a3b8"))

        if not sizes:
            ax.text(0.5, 0.5, "No Severity Data Available", ha="center", va="center", color="#64748b", fontsize=11)
            ax.set_axis_off()
        else:
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                autopct="%1.0f%%",
                pctdistance=0.75,
                colors=colors,
                startangle=140,
                textprops={"fontsize": 9, "color": "#0f172a"},
                wedgeprops={"width": 0.45, "edgecolor": "#ffffff", "linewidth": 1.5},
            )
            for at in autotexts:
                at.set_color("#ffffff")
                at.set_fontweight("bold")
                at.set_fontsize(8)

        fig.tight_layout()
        fig.savefig(out_path, dpi=150, facecolor=fig.get_facecolor(), bbox_inches="tight")
        plt.close(fig)
        return out_path

    def generate_risk_chart(self, report_data: Dict[str, Any]) -> str:
        """Generates a bar chart breakdown of risk scores by tier."""
        out_path = os.path.join(self.output_dir, "risk_distribution.png")
        risk_dist = report_data.get("section_8_risk_analysis", {}).get("risk_score_distribution", {})

        fig, ax = plt.subplots(figsize=(5.5, 3.2), dpi=150)
        self._setup_figure_style(fig, ax, "Risk Score Tier Breakdown")

        tiers = ["Low (0-39)", "Medium (40-69)", "High (70-89)", "Critical (90-100)"]
        counts = [risk_dist.get(t, 0) for t in tiers]
        colors = ["#10b981", "#eab308", "#f97316", "#ef4444"]

        if sum(counts) == 0:
            ax.text(0.5, 0.5, "No Risk Data Logged", ha="center", va="center", color="#64748b", fontsize=11)
            ax.set_axis_off()
        else:
            bars = ax.bar(tiers, counts, color=colors, edgecolor="#475569", width=0.55)
            ax.grid(axis="y", linestyle="--", alpha=0.5, color="#cbd5e1")
            for bar in bars:
                h = bar.get_height()
                ax.text(bar.get_x() + bar.get_width() / 2, h + max(max(counts) * 0.02, 0.5), f"{int(h)}",
                        ha="center", va="bottom", fontsize=9, color="#0f172a", fontweight="bold")
            ax.set_ylim(0, max(counts) * 1.2 if counts else 10)
            ax.tick_params(axis="x", labelsize=8)

        fig.tight_layout()
        fig.savefig(out_path, dpi=150, facecolor=fig.get_facecolor(), bbox_inches="tight")
        plt.close(fig)
        return out_path

    def generate_directionality_chart(self, report_data: Dict[str, Any]) -> str:
        """Generates a pie/donut chart representing Unidirectional vs Bidirectional traffic."""
        out_path = os.path.join(self.output_dir, "directionality_distribution.png")
        dir_dist = report_data.get("section_3_utie_intelligence", {}).get("directionality_distribution", {})

        fig, ax = plt.subplots(figsize=(5, 3.2), dpi=150)
        self._setup_figure_style(fig, ax, "Traffic Directionality Profile")

        labels = []
        sizes = []
        colors = []
        color_map = {
            "UNIDIRECTIONAL": "#0284c7",
            "BIDIRECTIONAL": "#10b981",
            "UNKNOWN": "#64748b",
        }

        for d in ["UNIDIRECTIONAL", "BIDIRECTIONAL", "UNKNOWN"]:
            count = dir_dist.get(d, 0)
            if count > 0:
                labels.append(d.capitalize())
                sizes.append(count)
                colors.append(color_map.get(d, "#94a3b8"))

        if not sizes:
            ax.text(0.5, 0.5, "No Flow Directionality Data", ha="center", va="center", color="#64748b", fontsize=11)
            ax.set_axis_off()
        else:
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                autopct="%1.0f%%",
                pctdistance=0.75,
                colors=colors,
                startangle=90,
                textprops={"fontsize": 9, "color": "#0f172a"},
                wedgeprops={"width": 0.45, "edgecolor": "#ffffff", "linewidth": 1.5},
            )
            for at in autotexts:
                at.set_color("#ffffff")
                at.set_fontweight("bold")
                at.set_fontsize(8)

        fig.tight_layout()
        fig.savefig(out_path, dpi=150, facecolor=fig.get_facecolor(), bbox_inches="tight")
        plt.close(fig)
        return out_path
