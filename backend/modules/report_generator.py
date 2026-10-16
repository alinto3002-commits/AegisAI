import io
import json
from typing import Dict, Any

from backend.models.schemas import ReviewReport

class CodeReviewReportGenerator:
    """
    Module 6: Code Review Report Generation & Export Module.
    Generates structured exportable reports in JSON, Markdown, and formatted PDF formats.
    """

    @staticmethod
    def to_json(report: ReviewReport) -> str:
        """Serializes review report to structured JSON."""
        return report.model_dump_json(indent=2)

    @staticmethod
    def to_markdown(report: ReviewReport) -> str:
        """Generates comprehensive GitHub/GitLab Pull Request Markdown report."""
        md = [
            f"# 🛡️ AI Code Review & Security Analysis Report",
            f"",
            f"**Report ID:** `{report.id}`  ",
            f"**Target File:** `{report.filename}`  ",
            f"**Language:** `{report.language.capitalize()}`  ",
            f"**Lines of Code:** `{report.lines_of_code}` | **Cyclomatic Complexity:** `{report.cyclomatic_complexity}`  ",
            f"**Timestamp:** `{report.timestamp}`  ",
            f"",
            f"---",
            f"",
            f"## 🏆 Executive Verdict & Health Score",
            f"- **Gate Decision:** `{report.verdict}`",
            f"- **Security & Quality Health Score:** **`{report.health_score} / 100`** ({report.risk_level} Risk)",
            f"",
            f"### Severity Summary",
            f"| Critical | High | Medium | Low | Info |",
            f"| :---: | :---: | :---: | :---: | :---: |",
            f"| **{report.severity_counts.get('CRITICAL', 0)}** | **{report.severity_counts.get('HIGH', 0)}** | **{report.severity_counts.get('MEDIUM', 0)}** | **{report.severity_counts.get('LOW', 0)}** | **{report.severity_counts.get('INFO', 0)}** |",
            f"",
            f"---",
            f"",
            f"## 🔍 Detailed Findings & Remediation Roadmap",
        ]

        if not report.findings:
            md.append("✅ *No security vulnerabilities or quality issues were identified.*")
        else:
            for idx, f in enumerate(report.findings, start=1):
                md.append(f"### {idx}. [{f.severity.value}] {f.title}")
                md.append(f"- **Agent:** {f.agent_type.value}")
                md.append(f"- **Category:** {f.category}")
                if f.owasp_category:
                    md.append(f"- **OWASP Category:** `{f.owasp_category}`")
                if f.cwe_id:
                    md.append(f"- **CWE:** `{f.cwe_id}`")
                md.append(f"- **Location:** Lines `{f.line_start} - {f.line_end}`")
                md.append(f"")
                md.append(f"**Description:**  \n{f.description}")
                md.append(f"")
                if f.evidence:
                    md.append(f"**Evidence:**\n```{report.language}\n{f.evidence}\n```")
                    md.append(f"")
                if f.remediation:
                    md.append(f"#### 🛠️ Remediation Guidance")
                    md.append(f"{f.remediation.explanation}")
                    md.append(f"")
                    md.append(f"**Proposed Code Diff:**\n```diff\n{f.remediation.diff}\n```")
                    md.append(f"")
                    md.append(f"**Secure Implementation Example:**\n```{report.language}\n{f.remediation.corrected_snippet}\n```")
                    md.append(f"")
                    if f.remediation.references:
                        md.append(f"**Standards & References:**")
                        for ref in f.remediation.references:
                            md.append(f"- [{ref}]({ref})")
                md.append(f"\n---")

        md.append(f"\n## ⏱️ Agent Execution Telemetry")
        for agent_name, duration in report.agent_execution_times.items():
            md.append(f"- `{agent_name}`: `{duration}s`")

        return "\n".join(md)

    @staticmethod
    def to_pdf(report: ReviewReport) -> bytes:
        """Generates a professional executive PDF report using reportlab."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
                Preformatted,
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=letter,
                rightMargin=40,
                leftMargin=40,
                topMargin=40,
                bottomMargin=40,
            )
            styles = getSampleStyleSheet()

            # Custom styles
            title_style = ParagraphStyle(
                "DocTitle",
                parent=styles["Heading1"],
                fontSize=20,
                textColor=colors.HexColor("#0f172a"),
                spaceAfter=10,
            )
            subtitle_style = ParagraphStyle(
                "SubTitle",
                parent=styles["Normal"],
                fontSize=10,
                textColor=colors.HexColor("#64748b"),
                spaceAfter=15,
            )
            h2_style = ParagraphStyle(
                "SectionHeading",
                parent=styles["Heading2"],
                fontSize=14,
                textColor=colors.HexColor("#1e293b"),
                spaceBefore=12,
                spaceAfter=6,
            )
            body_style = ParagraphStyle(
                "BodyDark",
                parent=styles["Normal"],
                fontSize=9,
                textColor=colors.HexColor("#334155"),
                leading=12,
            )

            elements = []

            # 1. Title Banner
            elements.append(Paragraph("AI Code Review & Security Analysis Report", title_style))
            elements.append(Paragraph(f"Report ID: {report.id} | Generated: {report.timestamp}", subtitle_style))
            elements.append(Spacer(1, 10))

            # 2. Metadata & Verdict Table
            verdict_color = colors.HexColor("#10b981") if "APPROVED" in report.verdict else colors.HexColor("#ef4444")
            meta_data = [
                ["Target File", report.filename, "Health Score", f"{report.health_score} / 100"],
                ["Language", report.language.capitalize(), "Risk Level", report.risk_level],
                ["Lines of Code", str(report.lines_of_code), "PR Verdict", report.verdict],
                ["Cyclomatic Complexity", str(report.cyclomatic_complexity), "Total Findings", str(len(report.findings))],
            ]
            t_meta = Table(meta_data, colWidths=[120, 140, 120, 140])
            t_meta.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1e293b")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ]))
            elements.append(t_meta)
            elements.append(Spacer(1, 15))

            # 3. Severity Counts Table
            elements.append(Paragraph("Severity Distribution Breakdown", h2_style))
            sev_data = [
                ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                [
                    str(report.severity_counts.get("CRITICAL", 0)),
                    str(report.severity_counts.get("HIGH", 0)),
                    str(report.severity_counts.get("MEDIUM", 0)),
                    str(report.severity_counts.get("LOW", 0)),
                    str(report.severity_counts.get("INFO", 0)),
                ],
            ]
            t_sev = Table(sev_data, colWidths=[104, 104, 104, 104, 104])
            t_sev.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#fee2e2")),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#ffedd5")),
                ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#fef9c3")),
                ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#e0f2fe")),
                ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#f1f5f9")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            elements.append(t_sev)
            elements.append(Spacer(1, 15))

            # 4. Findings
            elements.append(Paragraph("Detailed Findings & Remediation Roadmaps", h2_style))
            for idx, f in enumerate(report.findings, start=1):
                f_title = f"<b>{idx}. [{f.severity.value}] {f.title}</b> (Line {f.line_start})"
                elements.append(Paragraph(f_title, body_style))
                f_meta = f"<i>Standard: {f.owasp_category or 'General'} | CWE: {f.cwe_id or 'N/A'}</i>"
                elements.append(Paragraph(f_meta, body_style))
                elements.append(Paragraph(f"Description: {f.description}", body_style))
                if f.remediation:
                    elements.append(Paragraph(f"<b>Remediation:</b> {f.remediation.explanation}", body_style))
                elements.append(Spacer(1, 8))

            doc.build(elements)
            buffer.seek(0)
            return buffer.getvalue()
        except Exception as e:
            # Fallback if PDF generation errors
            return f"PDF generation error: {e}".encode("utf-8")
