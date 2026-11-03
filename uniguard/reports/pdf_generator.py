"""PDF Report Generator for UniGuard AI Security Reports.

Produces multi-page, publication-grade cybersecurity reports using
ReportLab Platypus, custom NumberedCanvas page counters, embedded analytics
charts, and structured forensic tables.
"""

from __future__ import annotations

import os
from typing import Dict, Any, List, Optional

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    Image,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from uniguard.reports.report_charts import ReportChartGenerator


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas that computes total page count for running headers/footers."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        self.saveState()
        self.setFont("Helvetica-Bold", 7)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(36, 756, "UNIGUARD AI — THREAT INTELLIGENCE & AUDIT REPORT")
            self.drawRightString(576, 756, "CONFIDENTIAL / SOC LEVEL 2")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(36, 750, 576, 750)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(36, 42, 576, 42)
        self.setFont("Helvetica", 7.5)
        self.drawString(36, 30, "CONFIDENTIAL — STRICTLY FOR AUTHORIZED SECURITY OPERATIONS USE ONLY")
        self.drawRightString(576, 30, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class PdfReportGenerator:
    """Compiles complete 10-section cybersecurity reports into PDF format."""

    def __init__(self, chart_gen: Optional[ReportChartGenerator] = None) -> None:
        self.chart_gen = chart_gen or ReportChartGenerator()

    def generate(self, report_data: Dict[str, Any], output_path: str) -> str:
        """Constructs and builds the complete PDF document."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=50,
            bottomMargin=50,
        )

        charts = self.chart_gen.generate_all_charts(report_data)
        styles = self._create_styles()
        story: List[Any] = []

        # 0. Document Banner & Header
        self._build_header_banner(story, report_data, styles)

        # 1. Executive Summary
        self._build_section_1_executive(story, report_data, styles)

        # 2. Network Traffic Analysis
        self._build_section_2_traffic(story, report_data, styles)

        # 3. Unidirectional Traffic Intelligence
        self._build_section_3_utie(story, report_data, styles, charts)

        # 4. Threat Detection Summary
        self._build_section_4_threats(story, report_data, styles, charts)

        # 5. High-Risk Security Events
        self._build_section_5_high_risk(story, report_data, styles)

        # 6. AI Model Analysis
        self._build_section_6_ai_models(story, report_data, styles)

        # 7. AI Threat Explainability
        self._build_section_7_explainability(story, report_data, styles)

        # 8. Risk Analysis & Scoring
        self._build_section_8_risk(story, report_data, styles, charts)

        # 9. Investigation Timeline
        self._build_section_9_timeline(story, report_data, styles)

        # 10. Recommendations & Action Plan
        self._build_section_10_recommendations(story, report_data, styles)

        # Build document
        doc.build(story, canvasmaker=NumberedCanvas)
        return output_path

    def _create_styles(self) -> Dict[str, ParagraphStyle]:
        base = getSampleStyleSheet()
        custom = {
            "DocTitle": ParagraphStyle(
                "DocTitle",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=18,
                leading=22,
                textColor=colors.HexColor("#0f172a"),
            ),
            "DocSubTitle": ParagraphStyle(
                "DocSubTitle",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=9,
                leading=13,
                textColor=colors.HexColor("#475569"),
            ),
            "SecTitle": ParagraphStyle(
                "SecTitle",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=11,
                leading=15,
                textColor=colors.HexColor("#0284c7"),
                spaceBefore=12,
                spaceAfter=4,
            ),
            "Body": ParagraphStyle(
                "Body",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=8.5,
                leading=12,
                textColor=colors.HexColor("#1e293b"),
            ),
            "TableHead": ParagraphStyle(
                "TableHead",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=9,
                textColor=colors.white,
                alignment=1,
            ),
            "TableCell": ParagraphStyle(
                "TableCell",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor("#1e293b"),
            ),
            "TableCellBold": ParagraphStyle(
                "TableCellBold",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor("#0f172a"),
            ),
            "TableCellCenter": ParagraphStyle(
                "TableCellCenter",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor("#1e293b"),
                alignment=1,
            ),
            "BadgeCritical": ParagraphStyle(
                "BadgeCritical",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=7,
                leading=8,
                textColor=colors.HexColor("#b91c1c"),
                alignment=1,
            ),
            "BadgeHigh": ParagraphStyle(
                "BadgeHigh",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=7,
                leading=8,
                textColor=colors.HexColor("#c2410c"),
                alignment=1,
            ),
        }
        return custom

    def _build_header_banner(self, story: List[Any], report_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> None:
        meta = report_data.get("metadata", {})
        left_text = (
            f"<b><font size='14' color='#0f172a'>UniGuard AI</font></b><br/>"
            f"<font size='8' color='#64748b'>Autonomous Cyber Threat Detection & Unidirectional Traffic Intelligence</font>"
        )
        right_text = (
            f"<b><font size='8' color='#0f172a'>REPORT: </font></b><font size='8' color='#0284c7'>{meta.get('report_name')}</font><br/>"
            f"<b><font size='7.5' color='#475569'>TYPE: </font></b><font size='7.5'>{meta.get('report_type')}</font> | "
            f"<b><font size='7.5' color='#475569'>RANGE: </font></b><font size='7.5'>{meta.get('date_range_label')}</font><br/>"
            f"<b><font size='7.5' color='#475569'>GENERATED: </font></b><font size='7.5'>{meta.get('generated_at_str')}</font>"
        )

        banner_table = Table(
            [[Paragraph(left_text, styles["Body"]), Paragraph(right_text, styles["Body"])]],
            colWidths=[310, 230],
        )
        banner_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(banner_table)
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceBefore=4, spaceAfter=8))

    def _build_section_1_executive(self, story: List[Any], report_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> None:
        sec1 = report_data.get("section_1_executive_summary", {})
        story.append(Paragraph("1. EXECUTIVE SUMMARY", styles["SecTitle"]))

        # KPI metric grid
        kpi_data = [
            [
                Paragraph("<b>TOTAL ANALYZED EVENTS</b>", styles["TableCellCenter"]),
                Paragraph("<b>HIGH-RISK DETECTIONS</b>", styles["TableCellCenter"]),
                Paragraph("<b>PRIMARY THREAT VECTOR</b>", styles["TableCellCenter"]),
                Paragraph("<b>OVERALL RISK POSTURE</b>", styles["TableCellCenter"]),
            ],
            [
                Paragraph(f"<font size='13' color='#0f172a'><b>{sec1.get('total_events', 0)}</b></font>", styles["TableCellCenter"]),
                Paragraph(f"<font size='13' color='#ef4444'><b>{sec1.get('high_risk_total', 0)}</b></font>", styles["TableCellCenter"]),
                Paragraph(f"<font size='10' color='#0284c7'><b>{sec1.get('top_threat', 'None')}</b></font>", styles["TableCellCenter"]),
                Paragraph(f"<font size='10' color='{'#dc2626' if sec1.get('high_risk_total', 0) > 0 else '#16a34a'}'><b>{sec1.get('status', 'SECURE')}</b></font>", styles["TableCellCenter"]),
            ],
        ]
        kpi_table = Table(kpi_data, colWidths=[135, 135, 140, 130])
        kpi_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#ffffff")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 4))

        overview_para = Paragraph(f"<b>Operational Assessment:</b> {sec1.get('overview_text', '')}", styles["Body"])
        story.append(overview_para)
        story.append(Spacer(1, 6))

    def _build_section_2_traffic(self, story: List[Any], report_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> None:
        sec2 = report_data.get("section_2_traffic_analysis", {})
        story.append(Paragraph("2. NETWORK TRAFFIC ANALYSIS", styles["SecTitle"]))

        traffic_summary = [
            [
                Paragraph("<b>Total Packets</b>", styles["TableCellBold"]),
                Paragraph(str(sec2.get("total_packets", 0)), styles["TableCell"]),
                Paragraph("<b>Total Data Volume</b>", styles["TableCellBold"]),
                Paragraph(f"{sec2.get('total_megabytes', 0.0)} MB ({sec2.get('total_bytes', 0):,} bytes)", styles["TableCell"]),
            ],
            [
                Paragraph("<b>Average Flow Duration</b>", styles["TableCellBold"]),
                Paragraph(f"{sec2.get('average_duration_sec', 0.0)} s", styles["TableCell"]),
                Paragraph("<b>Monitored Protocols</b>", styles["TableCellBold"]),
                Paragraph(", ".join([f"{k} ({v})" for k, v in sec2.get("protocol_distribution", {}).items()][:4]) or "None", styles["TableCell"]),
            ],
        ]
        t_table = Table(traffic_summary, colWidths=[120, 150, 120, 150])
        t_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t_table)
        story.append(Spacer(1, 6))

    def _build_section_3_utie(
        self,
        story: List[Any],
        report_data: Dict[str, Any],
        styles: Dict[str, ParagraphStyle],
        charts: Dict[str, str],
    ) -> None:
        sec3 = report_data.get("section_3_utie_intelligence", {})
        story.append(Paragraph("3. UNIDIRECTIONAL TRAFFIC INTELLIGENCE (UTIE)", styles["SecTitle"]))

        utie_table_data = [
            [
                Paragraph("<b>Unidirectional Flows</b>", styles["TableCellBold"]),
                Paragraph(f"{sec3.get('unidirectional_flows', 0)} ({sec3.get('unidirectional_percentage', 0.0)}%)", styles["TableCell"]),
                Paragraph("<b>Bidirectional Flows</b>", styles["TableCellBold"]),
                Paragraph(str(sec3.get("bidirectional_flows", 0)), styles["TableCell"]),
            ],
            [
                Paragraph("<b>Missing Reverse Handshakes</b>", styles["TableCellBold"]),
                Paragraph(str(sec3.get("missing_reverse_handshakes", 0)), styles["TableCell"]),
                Paragraph("<b>Asymmetric Visibility Cases</b>", styles["TableCellBold"]),
                Paragraph(str(sec3.get("asymmetric_sensor_visibility", 0)), styles["TableCell"]),
            ],
        ]
        u_table = Table(utie_table_data, colWidths=[140, 130, 140, 130])
        u_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(u_table)
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"<b>Sensor Assessment:</b> {sec3.get('assessment', '')}", styles["Body"]))
        story.append(Spacer(1, 6))

    def _build_section_4_threats(
        self,
        story: List[Any],
        report_data: Dict[str, Any],
        styles: Dict[str, ParagraphStyle],
        charts: Dict[str, str],
    ) -> None:
        sec4 = report_data.get("section_4_threat_summary", {})
        story.append(Paragraph("4. THREAT DETECTION & SEVERITY SUMMARY", styles["SecTitle"]))

        # Visual analytics layout: 2 charts side by side
        chart_threat = charts.get("threat_distribution")
        chart_sev = charts.get("severity_distribution")

        chart_cells = []
        if chart_threat and os.path.exists(chart_threat):
            chart_cells.append(Image(chart_threat, width=265, height=140))
        else:
            chart_cells.append(Paragraph("Chart Unavailable", styles["TableCellCenter"]))

        if chart_sev and os.path.exists(chart_sev):
            chart_cells.append(Image(chart_sev, width=265, height=140))
        else:
            chart_cells.append(Paragraph("Chart Unavailable", styles["TableCellCenter"]))

        chart_table = Table([chart_cells], colWidths=[270, 270])
        chart_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(chart_table)
        story.append(Spacer(1, 8))

    def _build_section_5_high_risk(self, story: List[Any], report_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> None:
        high_risk = report_data.get("section_5_high_risk_events", [])
        story.append(Paragraph("5. HIGH-RISK SECURITY EVENTS (PRIORITY TRIAGE)", styles["SecTitle"]))

        headers = [
            Paragraph("<b>Event ID</b>", styles["TableHead"]),
            Paragraph("<b>Timestamp</b>", styles["TableHead"]),
            Paragraph("<b>Source Endpoint</b>", styles["TableHead"]),
            Paragraph("<b>Dest Endpoint</b>", styles["TableHead"]),
            Paragraph("<b>Threat Classification</b>", styles["TableHead"]),
            Paragraph("<b>Risk</b>", styles["TableHead"]),
            Paragraph("<b>Severity</b>", styles["TableHead"]),
        ]
        table_rows = [headers]

        if not high_risk:
            no_row = [Paragraph("<i>No High-Risk Events Encountered in Monitored Range</i>", styles["TableCellCenter"])] + [Paragraph("", styles["TableCellCenter"])] * 6
            table_rows.append(no_row)
        else:
            for e in high_risk[:12]:  # Show top 12 in PDF
                sev = str(e.get("severity", "")).upper()
                badge_style = styles["BadgeCritical"] if sev == "CRITICAL" else styles["BadgeHigh"] if sev == "HIGH" else styles["TableCellCenter"]
                src_str = f"{e.get('src_ip')}:{e.get('src_port')}"
                dst_str = f"{e.get('dst_ip')}:{e.get('dst_port')}"

                table_rows.append([
                    Paragraph(e.get("event_id", "")[:12], styles["TableCell"]),
                    Paragraph(e.get("timestamp_str", "").split(" ")[-1], styles["TableCellCenter"]),
                    Paragraph(src_str, styles["TableCell"]),
                    Paragraph(dst_str, styles["TableCell"]),
                    Paragraph(f"<b>{e.get('threat_type', '')}</b>", styles["TableCell"]),
                    Paragraph(f"<b>{e.get('risk_score', 0)}</b>", styles["TableCellCenter"]),
                    Paragraph(f"<b>{sev}</b>", badge_style),
                ])

        hr_table = Table(table_rows, colWidths=[70, 60, 105, 105, 110, 35, 55])
        hr_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(hr_table)
        story.append(Spacer(1, 8))

    def _build_section_6_ai_models(self, story: List[Any], report_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> None:
        sec6 = report_data.get("section_6_ai_model_analysis", {})
        story.append(Paragraph("6. ARTIFICIAL INTELLIGENCE & DETECTION ENGINE STATUS", styles["SecTitle"]))

        models = sec6.get("active_models", [])
        m_rows = [
            [
                Paragraph("<b>Ensemble Component</b>", styles["TableHead"]),
                Paragraph("<b>Model Architecture</b>", styles["TableHead"]),
                Paragraph("<b>Operational Status</b>", styles["TableHead"]),
            ]
        ]
        for m in models:
            m_rows.append([
                Paragraph(f"<b>{m.get('name')}</b>", styles["TableCellBold"]),
                Paragraph(m.get("purpose", ""), styles["TableCell"]),
                Paragraph(f"<font color='#16a34a'><b>{m.get('status')}</b></font>", styles["TableCellCenter"]),
            ])

        m_table = Table(m_rows, colWidths=[160, 260, 120])
        m_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(m_table)
        story.append(Spacer(1, 6))

    def _build_section_7_explainability(self, story: List[Any], report_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> None:
        sec7 = report_data.get("section_7_explainability", {})
        story.append(Paragraph("7. AI THREAT EXPLANATION ENGINE (WHY WAS THIS DETECTED?)", styles["SecTitle"]))

        expl_text = (
            f"<b>Explainability Coverage:</b> {sec7.get('explainability_coverage_pct', 0.0)}% "
            f"({sec7.get('total_explained_events', 0)} events analyzed via forensic explainability rules).<br/>"
        )
        rules = sec7.get("primary_behavioral_rules_triggered", [])
        if rules:
            expl_text += "<b>Top Triggered Forensic Rules:</b> " + ", ".join([f"{r.get('rule')} (x{r.get('count')})" for r in rules[:3]]) + "<br/>"

        factors = sec7.get("primary_contributing_features", [])
        if factors:
            expl_text += "<b>Key Contributing Features:</b> " + ", ".join([f"{f.get('factor')} (x{f.get('count')})" for f in factors[:3]])

        story.append(Paragraph(expl_text, styles["Body"]))
        story.append(Spacer(1, 6))

    def _build_section_8_risk(
        self,
        story: List[Any],
        report_data: Dict[str, Any],
        styles: Dict[str, ParagraphStyle],
        charts: Dict[str, str],
    ) -> None:
        sec8 = report_data.get("section_8_risk_analysis", {})
        story.append(Paragraph("8. RISK SCORE DISTRIBUTION & IMPACT PROFILE", styles["SecTitle"]))

        chart_risk = charts.get("risk_distribution")
        chart_dir = charts.get("directionality_distribution")

        chart_cells = []
        if chart_risk and os.path.exists(chart_risk):
            chart_cells.append(Image(chart_risk, width=265, height=135))
        else:
            chart_cells.append(Paragraph("Risk Chart Unavailable", styles["TableCellCenter"]))

        if chart_dir and os.path.exists(chart_dir):
            chart_cells.append(Image(chart_dir, width=265, height=135))
        else:
            chart_cells.append(Paragraph("Directionality Chart Unavailable", styles["TableCellCenter"]))

        r_table = Table([chart_cells], colWidths=[270, 270])
        r_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(r_table)
        story.append(Spacer(1, 6))

    def _build_section_9_timeline(self, story: List[Any], report_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> None:
        sec9 = report_data.get("section_9_timeline", {})
        story.append(Paragraph("9. INCIDENT & INVESTIGATION TIMELINE", styles["SecTitle"]))

        t_data = [
            [
                Paragraph("<b>First Observed Event</b>", styles["TableCellBold"]),
                Paragraph(sec9.get("first_event_time", "N/A"), styles["TableCell"]),
                Paragraph("<b>Last Observed Event</b>", styles["TableCellBold"]),
                Paragraph(sec9.get("last_event_time", "N/A"), styles["TableCell"]),
            ],
            [
                Paragraph("<b>Peak Activity Period</b>", styles["TableCellBold"]),
                Paragraph(sec9.get("peak_attack_window", "N/A"), styles["TableCell"]),
                Paragraph("<b>Chronological Status</b>", styles["TableCellBold"]),
                Paragraph("Contained / Monitored", styles["TableCell"]),
            ],
        ]
        tl_table = Table(t_data, colWidths=[130, 140, 130, 140])
        tl_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(tl_table)
        story.append(Spacer(1, 6))

    def _build_section_10_recommendations(self, story: List[Any], report_data: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> None:
        recs = report_data.get("section_10_recommendations", [])
        story.append(Paragraph("10. PRIORITIZED DEFENSIVE RECOMMENDATIONS", styles["SecTitle"]))

        rec_rows = [
            [
                Paragraph("<b>Priority</b>", styles["TableHead"]),
                Paragraph("<b>Category</b>", styles["TableHead"]),
                Paragraph("<b>Remediation Action Item</b>", styles["TableHead"]),
            ]
        ]

        priority_colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#10b981",
        }

        for r in recs:
            prio = r.get("priority", "LOW").upper()
            p_color = priority_colors.get(prio, "#64748b")
            rec_rows.append([
                Paragraph(f"<font color='{p_color}'><b>{prio}</b></font>", styles["TableCellCenter"]),
                Paragraph(f"<b>{r.get('category')}</b>", styles["TableCell"]),
                Paragraph(f"<b>{r.get('title')}:</b> {r.get('action')}", styles["TableCell"]),
            ])

        rec_table = Table(rec_rows, colWidths=[65, 120, 355])
        rec_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(rec_table)

