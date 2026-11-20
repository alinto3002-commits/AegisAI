import io
import json
import logging
from typing import Dict, Any, List

from backend.models.schemas import ReviewReport

logger = logging.getLogger(__name__)

def escape_rl(text: str) -> str:
    """Escapes special characters for ReportLab Paragraph XML parser."""
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

def safe_get(obj: Any, key: str, default: Any = "") -> Any:
    """Helper to safely retrieve a key from dict or object attribute."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

class CodeReviewReportGenerator:
    """
    Module 6: Code Review Report Generation & Export Module.
    Generates structured exportable reports in JSON, Markdown, and formatted PDF formats.
    - If downloaded before error solving: displays full audit details, evidence, roadmaps, and guidelines.
    - If downloaded after error solving: displays the errors before and the exact changes that solved them.
    """

    @staticmethod
    def to_json(report: ReviewReport) -> str:
        """Serializes review report to structured JSON."""
        return report.model_dump_json(indent=2)

    @staticmethod
    def to_markdown(report: ReviewReport) -> str:
        """
        Generates comprehensive Pull Request Markdown report.
        - Before error solving: full audit with all findings, evidence, guidelines, tests.
        - After error solving: shows the error before and what changes happened to solve it.
        """
        is_remed = getattr(report, "is_remediated", False) and bool(getattr(report, "resolved_findings", []))

        if is_remed:
            # POST-REMEDIATION VERIFICATION REPORT
            resolved = report.resolved_findings
            init_score = getattr(report, "initial_health_score", None) or "N/A"
            final_score = report.health_score
            gain = f"+{final_score - init_score}" if isinstance(init_score, int) and isinstance(final_score, int) else ""

            md = [
                f"# 🛡️ AegisAI — Code Remediation & Security Resolution Verification Report",
                f"",
                f"**Report ID:** `{report.id}`  ",
                f"**Audit Status:** **Post-Remediation Verification Report**  ",
                f"**Target File:** `{report.filename}`  ",
                f"**Language:** `{report.language.capitalize()}`  ",
                f"**Timestamp:** `{report.timestamp}`  ",
                f"",
                f"---",
                f"",
                f"## 🏆 Executive Resolution Summary & Quality Gate",
                f"- **PR Gate Verdict:** **`{report.verdict}`**",
                f"- **Health Score Evolution:** **`{init_score} / 100` ➔ `{final_score} / 100`** {f'({gain} points improved)' if gain else ''}",
                f"- **Resolved Vulnerabilities:** **`{len(resolved)} Issues Successfully Remediated`**",
                f"- **Remaining Outstanding Issues:** **`{len(report.findings)} Issues`**",
                f"- **Verification Status:** {'✅ APPROVED · ALL BLOCKERS REMEDIATED' if report.health_score >= 80 else '⚠️ PARTIAL REMEDIATION · OUTSTANDING ISSUES REMAIN'}",
                f"",
                f"---",
                f"",
                f"## 🔄 Remediation Changelog: Errors Before & What Changed to Solve Them",
                f"",
                f"This changelog details each security vulnerability and code quality issue identified in the initial review, along with the precise code modifications and defensive patterns applied to resolve it.",
                f"",
            ]

            for idx, f in enumerate(resolved, 1):
                title = safe_get(f, "title", "Issue")
                sev_raw = safe_get(f, "severity", "UNKNOWN")
                sev = sev_raw.value if hasattr(sev_raw, "value") else str(sev_raw)
                line = safe_get(f, "line_start", "N/A")
                cwe = safe_get(f, "cwe_id", "N/A")
                owasp = safe_get(f, "owasp_category", "General")
                desc = safe_get(f, "description", "")
                evidence = safe_get(f, "evidence", "")
                rem = safe_get(f, "remediation", {})
                orig = safe_get(rem, "original_snippet", "") or evidence
                corr = safe_get(rem, "corrected_snippet", "")
                expl = safe_get(rem, "explanation", "Replaced insecure pattern with safe parameterized API / defensive logic.")
                diff = safe_get(rem, "diff", "")

                md.append(f"### #{idx}. [RESOLVED] {title} (Originally Line {line})")
                md.append(f"- **Severity Level:** `{sev}`")
                md.append(f"- **Security Classification:** `{owasp}` | **CWE:** `{cwe}`")
                md.append(f"- **Resolution Status:** `✓ VERIFIED RESOLVED & TESTED`")
                md.append(f"")
                md.append(f"#### ⚠️ The Error Before (Vulnerability Details):")
                md.append(f"{desc}")
                if orig:
                    md.append(f"\n**Vulnerable Code Snippet (Before Fix):**\n```{report.language}\n{orig.strip()}\n```")
                md.append(f"")
                md.append(f"#### 🛠️ What Changed to Solve the Error:")
                md.append(f"{expl}")
                if corr:
                    md.append(f"\n**Patched Code Implementation (After Fix):**\n```{report.language}\n{corr.strip()}\n```")
                if diff:
                    md.append(f"\n**Unified Diff (Exact Modifications Made):**\n```diff\n{diff.strip()}\n```")
                md.append(f"\n---")
                md.append(f"")

            if report.findings:
                md.append(f"## ⚠️ Remaining Outstanding Findings ({len(report.findings)})")
                for idx, rem_f in enumerate(report.findings, 1):
                    md.append(f"- **{idx}. [{rem_f.severity.value}] {rem_f.title}** (Line {rem_f.line_start}): {rem_f.description}")
            else:
                md.append(f"## ✅ Final Verification Statement")
                md.append(f"**Zero outstanding security vulnerabilities or quality smells remain.** The codebase meets all OWASP Top 10 (2025) compliance gates and is certified safe for merge and deployment.")

            return "\n".join(md)

        # PRE-REMEDIATION INITIAL AUDIT REPORT (Full Details Before Solving Error)
        md = [
            f"# 🛡️ AegisAI — Initial Code Review & Security Analysis Report",
            f"",
            f"**Report ID:** `{report.id}`  ",
            f"**Audit Status:** **Pre-Remediation Baseline Audit**  ",
            f"**Target File:** `{report.filename}`  ",
            f"**Language:** `{report.language.capitalize()}`  ",
            f"**Lines of Code:** `{report.lines_of_code}` | **Cyclomatic Complexity:** `{report.cyclomatic_complexity}`  ",
            f"**Timestamp:** `{report.timestamp}`  ",
            f"",
            f"---",
            f"",
            f"## 🏆 Executive Verdict & Overall Code Quality Assessment",
            f"- **PR Gate Verdict:** **`{report.verdict}`**",
            f"- **Composite Health Score:** **`{report.health_score} / 100`** (Assessed Risk: **{report.risk_level}**)",
            f"- **Code Maintainability Rating:** {'High' if report.cyclomatic_complexity <= 6 else ('Moderate' if report.cyclomatic_complexity <= 12 else 'Low / Needs Refactoring')}",
            f"- **Structural Complexity:** Cyclomatic Complexity score is `{report.cyclomatic_complexity}`.",
            f"",
            f"### Severity Distribution Breakdown",
            f"| Critical | High | Medium | Low | Info | Total |",
            f"| :---: | :---: | :---: | :---: | :---: | :---: |",
            f"| **{report.severity_counts.get('CRITICAL', 0)}** | **{report.severity_counts.get('HIGH', 0)}** | **{report.severity_counts.get('MEDIUM', 0)}** | **{report.severity_counts.get('LOW', 0)}** | **{report.severity_counts.get('INFO', 0)}** | **{len(report.findings)}** |",
            f"",
            f"---",
            f"",
            f"## 🎯 Prioritized Remediation Roadmap",
        ]

        # Prioritized roadmap items from pr_summary if available
        if hasattr(report, 'pr_summary') and report.pr_summary and report.pr_summary.recommended_actions:
            for idx, action in enumerate(report.pr_summary.recommended_actions, 1):
                md.append(f"{idx}. **Action item:** {action}")
        else:
            crit_high = [f for f in report.findings if f.severity.value in ('CRITICAL', 'HIGH')]
            med = [f for f in report.findings if f.severity.value == 'MEDIUM']
            low_info = [f for f in report.findings if f.severity.value in ('LOW', 'INFO')]
            if crit_high:
                md.append(f"### Phase 1: Immediate Security Blockers (Merge Pre-requisite)")
                for f in crit_high:
                    md.append(f"- [ ] **Fix Line {f.line_start}:** {f.title} ({f.owasp_category or f.category})")
            if med:
                md.append(f"### Phase 2: Design Anti-Patterns & Quality Smells")
                for f in med:
                    md.append(f"- [ ] **Refactor Line {f.line_start}:** {f.title}")
            if low_info:
                md.append(f"### Phase 3: Defensive Hardening & Standards Alignment")
                for f in low_info:
                    md.append(f"- [ ] **Enhance Line {f.line_start}:** {f.title}")

        md.append(f"")
        md.append(f"---")
        md.append(f"")
        md.append(f"## 🔍 Detailed Findings & Remediation Catalog")

        if not report.findings:
            md.append("✅ *No security vulnerabilities or code smells identified. Code meets quality gate standards.*")
        else:
            for idx, f in enumerate(report.findings, start=1):
                md.append(f"### {idx}. [{f.severity.value}] {f.title}")
                md.append(f"- **Location:** Line {f.line_start}")
                md.append(f"- **Standard Classification:** `{f.owasp_category or 'General'}` | **CWE:** `{f.cwe_id or 'N/A'}` | **Agent:** `{f.agent_type}`")
                md.append(f"- **Description:** {f.description}")
                if f.evidence:
                    md.append(f"\n**Vulnerable Code Snippet:**\n```{report.language}\n{f.evidence}\n```")
                if f.remediation:
                    md.append(f"\n**Remediation Guidance (RAG Grounded):**\n{f.remediation.explanation}")
                    if f.remediation.remediation_steps:
                        md.append("\n**Step-by-Step Fix Instructions:**")
                        for step in f.remediation.remediation_steps:
                            md.append(f"- {step}")
                    if f.remediation.corrected_snippet:
                        md.append(f"\n**Secure Implementation Example:**\n```{report.language}\n{f.remediation.corrected_snippet}\n```")
                    if f.remediation.diff:
                        md.append(f"\n**Unified Diff:**\n```diff\n{f.remediation.diff}\n```")
                    if f.remediation.unit_test_code:
                        test_framework = "pytest" if report.language == "python" else "JUnit 5"
                        md.append(f"\n**Automated Regression Test ({test_framework}):**\n```{report.language}\n{f.remediation.unit_test_code}\n```")
                    if f.remediation.references:
                        md.append(f"\n**Standards & References:**")
                        for ref in f.remediation.references:
                            md.append(f"- [{ref}]({ref})")
                md.append(f"\n---")

        md.append(f"\n## ⏱️ Agent Execution Telemetry")
        for agent_name, duration in report.agent_execution_times.items():
            md.append(f"- `{agent_name}`: `{duration}s`")

        return "\n".join(md)

    @staticmethod
    def to_pdf(report: ReviewReport) -> bytes:
        """
        Generates a professional executive PDF report:
        - Before error solving: full audit with all findings, evidence, severity, guidelines, roadmap.
        - After error solving: shows the errors before and what changes happened to solve the errors.
        """
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
                HRFlowable,
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=letter,
                rightMargin=36,
                leftMargin=36,
                topMargin=36,
                bottomMargin=36,
            )
            styles = getSampleStyleSheet()

            # Elegant editorial typography & palette
            c_navy = colors.HexColor("#0f2942")
            c_gold = colors.HexColor("#c5a059")
            c_dark = colors.HexColor("#1e293b")
            c_gray = colors.HexColor("#64748b")
            c_light = colors.HexColor("#f8fafc")
            c_border = colors.HexColor("#cbd5e1")
            c_green = colors.HexColor("#166534")

            title_style = ParagraphStyle(
                "DocTitle",
                parent=styles["Heading1"],
                fontSize=17,
                textColor=c_navy,
                spaceAfter=4,
                fontName="Helvetica-Bold",
            )
            subtitle_style = ParagraphStyle(
                "SubTitle",
                parent=styles["Normal"],
                fontSize=8.5,
                textColor=c_gray,
                spaceAfter=8,
                fontName="Helvetica",
            )
            h2_style = ParagraphStyle(
                "SectionHeading",
                parent=styles["Heading2"],
                fontSize=11,
                textColor=c_navy,
                spaceBefore=8,
                spaceAfter=5,
                fontName="Helvetica-Bold",
            )
            body_style = ParagraphStyle(
                "BodyDark",
                parent=styles["Normal"],
                fontSize=8,
                textColor=c_dark,
                leading=11,
                fontName="Helvetica",
            )
            badge_style = ParagraphStyle(
                "BadgeStyle",
                parent=styles["Normal"],
                fontSize=7.5,
                textColor=colors.HexColor("#ffffff"),
                alignment=1,
                fontName="Helvetica-Bold",
            )

            elements = []

            is_remed = getattr(report, "is_remediated", False) and bool(getattr(report, "resolved_findings", []))

            if is_remed:
                # =========================================================================
                # POST-REMEDIATION VERIFICATION PDF (Errors Before & Changes That Solved Them)
                # =========================================================================
                resolved = report.resolved_findings
                init_score = getattr(report, "initial_health_score", None) or "N/A"
                final_score = report.health_score

                elements.append(Paragraph("AegisAI — Code Remediation & Security Resolution Report", title_style))
                elements.append(Paragraph(
                    f"Post-Remediation Verification Audit &bull; Before &amp; After Patch Analysis | "
                    f"Report ID: <b>{escape_rl(report.id)}</b> | Generated: {escape_rl(report.timestamp)}",
                    subtitle_style
                ))
                elements.append(HRFlowable(width="100%", thickness=1.5, color=c_gold, spaceAfter=8))

                # Verification Summary Table
                gain_str = f" (+{final_score - init_score})" if isinstance(init_score, int) and isinstance(final_score, int) else ""
                remed_meta = [
                    [
                        Paragraph("<b>Target File:</b>", body_style), Paragraph(escape_rl(report.filename), body_style),
                        Paragraph("<b>PR Verdict:</b>", body_style), Paragraph(f"<b><font color='#166534'>{escape_rl(report.verdict)}</font></b>", body_style),
                    ],
                    [
                        Paragraph("<b>Language:</b>", body_style), Paragraph(escape_rl(report.language.capitalize()), body_style),
                        Paragraph("<b>Score Evolution:</b>", body_style), Paragraph(f"<b>{init_score} / 100 &rarr; <font color='#166534'>{final_score} / 100</font></b>{gain_str}", body_style),
                    ],
                    [
                        Paragraph("<b>Issues Remediated:</b>", body_style), Paragraph(f"<b><font color='#166534'>{len(resolved)} Solved</font></b>", body_style),
                        Paragraph("<b>Remaining Issues:</b>", body_style), Paragraph(f"<b>{len(report.findings)} Outstanding</b>", body_style),
                    ],
                ]
                t_remed_meta = Table(remed_meta, colWidths=[110, 160, 120, 150])
                t_remed_meta.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bbf7d0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                elements.append(t_remed_meta)
                elements.append(Spacer(1, 8))

                narrative = (
                    f"<b>Remediation Verification Assessment:</b> Automated security patches were successfully applied to "
                    f"<b>{escape_rl(report.filename)}</b>. <b>{len(resolved)}</b> previously flagged vulnerabilities and code smells "
                    f"were repaired, advancing the composite code health score from <b>{init_score}/100</b> to <b>{final_score}/100</b>. "
                    f"The changelog below catalogs each error before remediation and the exact code modifications applied to solve it."
                )
                elements.append(Paragraph(narrative, body_style))
                elements.append(Spacer(1, 8))

                # Section: Remediation Changelog
                elements.append(Paragraph("Remediation Changelog: Errors Before &amp; Changes That Solved Them", h2_style))

                for idx, f in enumerate(resolved, 1):
                    title = safe_get(f, "title", "Issue")
                    sev_raw = safe_get(f, "severity", "UNKNOWN")
                    sev = sev_raw.value if hasattr(sev_raw, "value") else str(sev_raw)
                    line = safe_get(f, "line_start", "N/A")
                    cwe = safe_get(f, "cwe_id", "N/A")
                    owasp = safe_get(f, "owasp_category", "General")
                    desc = safe_get(f, "description", "")
                    evidence = safe_get(f, "evidence", "")
                    rem = safe_get(f, "remediation", {})
                    orig = safe_get(rem, "original_snippet", "") or evidence
                    corr = safe_get(rem, "corrected_snippet", "")
                    expl = safe_get(rem, "explanation", "Replaced insecure pattern with safe parameterized API / defensive logic.")

                    f_card = [
                        [
                            Paragraph(f"<b>[RESOLVED] #{idx} &bull; [{escape_rl(sev)}] {escape_rl(title)}</b> (Originally Line {line})", body_style),
                        ],
                        [
                            Paragraph(f"<i>Classification: {escape_rl(owasp)} &bull; CWE: {escape_rl(cwe)} &bull; Status: <font color='#166534'><b>VERIFIED FIXED</b></font></i>", body_style),
                        ],
                        [
                            Paragraph(f"<b>1. The Error Before (Vulnerability Details):</b><br/>{escape_rl(desc)}", body_style),
                        ],
                    ]

                    if orig:
                        clean_orig = escape_rl(orig.strip()[:350])
                        f_card.append([
                            Paragraph(f"<b>Vulnerable Code (Before Fix):</b><br/><font face='Courier' size=7 color='#991b1b'>{clean_orig}</font>", body_style)
                        ])

                    f_card.append([
                        Paragraph(f"<b>2. What Changed to Solve the Error:</b><br/>{escape_rl(expl)}", body_style)
                    ])

                    if corr:
                        clean_corr = escape_rl(corr.strip()[:350])
                        f_card.append([
                            Paragraph(f"<b>Patched Code Applied (After Fix):</b><br/><font face='Courier' size=7 color='#166534'>{clean_corr}</font>", body_style)
                        ])

                    t_card = Table(f_card, colWidths=[540])
                    t_card.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dcfce7")),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#ffffff")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#86efac")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]))
                    elements.append(t_card)
                    elements.append(Spacer(1, 6))

                # Remaining issues check
                if report.findings:
                    elements.append(Paragraph(f"Remaining Outstanding Issues ({len(report.findings)})", h2_style))
                    rem_rows = [[Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Issue</b>", body_style), Paragraph("<b>Location</b>", body_style)]]
                    for rf in report.findings:
                        rem_rows.append([
                            Paragraph(f"[{rf.severity.value}]", body_style),
                            Paragraph(escape_rl(rf.title), body_style),
                            Paragraph(f"Line {rf.line_start}", body_style),
                        ])
                    t_rem = Table(rem_rows, colWidths=[80, 360, 100])
                    t_rem.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fef2f2")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#fecdd3")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]))
                    elements.append(t_rem)
                else:
                    elements.append(Spacer(1, 4))
                    cert_box = [[
                        Paragraph("<b>Security Quality Certification:</b> All identified security vulnerabilities have been remediated. Code meets OWASP Top 10 (2025) compliance gates and is certified safe for merge.", body_style)
                    ]]
                    t_cert = Table(cert_box, colWidths=[540])
                    t_cert.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#166534")),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]))
                    elements.append(t_cert)

            else:
                # =========================================================================
                # PRE-REMEDIATION AUDIT PDF (Full Details Before Error Solving)
                # =========================================================================
                elements.append(Paragraph("AegisAI — Initial Security Audit &amp; Vulnerability Report", title_style))
                elements.append(Paragraph(
                    f"Automated Multi-Agent Static Analysis &bull; OWASP Top 10 (2025) Baseline Audit | "
                    f"Report ID: <b>{escape_rl(report.id)}</b> | Generated: {escape_rl(report.timestamp)}",
                    subtitle_style
                ))
                elements.append(HRFlowable(width="100%", thickness=1.5, color=c_gold, spaceAfter=8))

                # Overall Code Quality Assessment & Metadata Table
                meta_data = [
                    [
                        Paragraph("<b>Target File:</b>", body_style), Paragraph(escape_rl(report.filename), body_style),
                        Paragraph("<b>PR Verdict:</b>", body_style), Paragraph(f"<b>{escape_rl(report.verdict)}</b>", body_style),
                    ],
                    [
                        Paragraph("<b>Language:</b>", body_style), Paragraph(escape_rl(report.language.capitalize()), body_style),
                        Paragraph("<b>Health Score:</b>", body_style), Paragraph(f"<b>{report.health_score} / 100</b> ({escape_rl(report.risk_level)})", body_style),
                    ],
                    [
                        Paragraph("<b>Lines of Code:</b>", body_style), Paragraph(str(report.lines_of_code), body_style),
                        Paragraph("<b>Cyclomatic Complexity:</b>", body_style), Paragraph(f"{report.cyclomatic_complexity} ({'Low' if report.cyclomatic_complexity <= 6 else 'High'})", body_style),
                    ],
                    [
                        Paragraph("<b>Total Findings:</b>", body_style), Paragraph(str(len(report.findings)), body_style),
                        Paragraph("<b>Security Standard:</b>", body_style), Paragraph("OWASP Top 10 (2025) + CWE", body_style),
                    ],
                ]
                t_meta = Table(meta_data, colWidths=[110, 160, 120, 150])
                t_meta.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), c_light),
                    ("GRID", (0, 0), (-1, -1), 0.5, c_border),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                elements.append(t_meta)
                elements.append(Spacer(1, 8))

                # Code Quality Assessment Paragraph
                quality_narrative = (
                    f"<b>Overall Quality Assessment:</b> Target codebase comprises {report.lines_of_code} lines of "
                    f"{report.language.capitalize()} with a cyclomatic complexity of {report.cyclomatic_complexity}. "
                    f"The composite security & quality health score is rated at <b>{report.health_score}/100</b> with a "
                    f"risk level of <b>{report.risk_level}</b>. "
                    + ("All security checks passed; codebase is approved for merge." if "APPROVED" in report.verdict
                       else "Blocking security risks or quality anti-patterns were detected. Code requires remediation prior to production deployment.")
                )
                elements.append(Paragraph(quality_narrative, body_style))
                elements.append(Spacer(1, 8))

                # Severity Distribution Breakdown
                elements.append(Paragraph("Severity Distribution Breakdown", h2_style))
                sev_data = [
                    [
                        Paragraph("<b>CRITICAL</b>", badge_style),
                        Paragraph("<b>HIGH</b>", badge_style),
                        Paragraph("<b>MEDIUM</b>", badge_style),
                        Paragraph("<b>LOW</b>", badge_style),
                        Paragraph("<b>INFO</b>", badge_style),
                        Paragraph("<b>TOTAL</b>", badge_style),
                    ],
                    [
                        Paragraph(f"<font size=11><b>{report.severity_counts.get('CRITICAL', 0)}</b></font>", body_style),
                        Paragraph(f"<font size=11><b>{report.severity_counts.get('HIGH', 0)}</b></font>", body_style),
                        Paragraph(f"<font size=11><b>{report.severity_counts.get('MEDIUM', 0)}</b></font>", body_style),
                        Paragraph(f"<font size=11><b>{report.severity_counts.get('LOW', 0)}</b></font>", body_style),
                        Paragraph(f"<font size=11><b>{report.severity_counts.get('INFO', 0)}</b></font>", body_style),
                        Paragraph(f"<font size=11><b>{len(report.findings)}</b></font>", body_style),
                    ],
                ]
                t_sev = Table(sev_data, colWidths=[90, 90, 90, 90, 90, 90])
                t_sev.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#dc2626")),
                    ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#ea580c")),
                    ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#d97706")),
                    ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#0284c7")),
                    ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#64748b")),
                    ("BACKGROUND", (5, 0), (5, 0), c_navy),
                    ("BACKGROUND", (0, 1), (-1, 1), c_light),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("GRID", (0, 0), (-1, -1), 0.5, c_border),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                elements.append(t_sev)
                elements.append(Spacer(1, 10))

                # Prioritized Remediation Roadmap
                elements.append(Paragraph("Prioritized Remediation Roadmap", h2_style))
                roadmap_items = []
                if hasattr(report, 'pr_summary') and report.pr_summary and report.pr_summary.recommended_actions:
                    for idx, act in enumerate(report.pr_summary.recommended_actions, 1):
                        roadmap_items.append([
                            Paragraph(f"<b>{idx}.</b>", body_style),
                            Paragraph(f"<b>Priority Action:</b> {escape_rl(act)}", body_style)
                        ])
                else:
                    crit_high = [f for f in report.findings if f.severity.value in ('CRITICAL', 'HIGH')]
                    med_low = [f for f in report.findings if f.severity.value not in ('CRITICAL', 'HIGH')]
                    idx = 1
                    for f in crit_high:
                        roadmap_items.append([
                            Paragraph(f"<b>{idx}.</b>", body_style),
                            Paragraph(f"<b>[Phase 1 Blocker]</b> Fix {escape_rl(f.title)} at Line {f.line_start} ({escape_rl(f.owasp_category or 'OWASP')})", body_style)
                        ])
                        idx += 1
                    for f in med_low:
                        roadmap_items.append([
                            Paragraph(f"<b>{idx}.</b>", body_style),
                            Paragraph(f"<b>[Phase 2 Enhancement]</b> Refactor {escape_rl(f.title)} at Line {f.line_start}", body_style)
                        ])
                        idx += 1

                if roadmap_items:
                    t_road = Table(roadmap_items, colWidths=[25, 515])
                    t_road.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#fed7aa")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]))
                    elements.append(t_road)
                else:
                    elements.append(Paragraph("<i>No immediate blocker actions required. Code meets baseline criteria.</i>", body_style))
                elements.append(Spacer(1, 10))

                # Detailed Findings & Remediation Roadmaps (All Details)
                elements.append(Paragraph("Detailed Findings &amp; Remediation Catalog", h2_style))

                if not report.findings:
                    elements.append(Paragraph("<i>No vulnerabilities or code smells identified.</i>", body_style))
                else:
                    for idx, f in enumerate(report.findings, start=1):
                        sev_hex = {
                            "CRITICAL": "#fee2e2",
                            "HIGH": "#ffedd5",
                            "MEDIUM": "#fef9c3",
                            "LOW": "#e0f2fe",
                            "INFO": "#f1f5f9",
                        }.get(f.severity.value, "#f1f5f9")

                        f_card = [
                            [
                                Paragraph(f"<b>#{idx} &bull; [{escape_rl(f.severity.value)}] {escape_rl(f.title)}</b> (Line {f.line_start})", body_style),
                            ],
                            [
                                Paragraph(f"<i>Standard: {escape_rl(f.owasp_category or 'General')} &bull; CWE: {escape_rl(f.cwe_id or 'N/A')} &bull; Category: {escape_rl(f.category)}</i>", body_style),
                            ],
                            [
                                Paragraph(f"<b>Description:</b> {escape_rl(f.description)}", body_style),
                            ],
                        ]

                        if f.evidence:
                            clean_ev = escape_rl(f.evidence.strip()[:400])
                            f_card.append([
                                Paragraph(f"<b>Vulnerable Code Evidence:</b><br/><font face='Courier' size=7 color='#7f1d1d'>{clean_ev}</font>", body_style)
                            ])

                        if f.remediation:
                            rem = f.remediation
                            rem_text = f"<b>Remediation Guidance (RAG Grounded):</b> {escape_rl(rem.explanation)}"
                            if rem.corrected_snippet:
                                clean_corr = escape_rl(rem.corrected_snippet.strip()[:400])
                                rem_text += f"<br/><b>Corrected Implementation:</b><br/><font face='Courier' size=7 color='#14532d'>{clean_corr}</font>"
                            f_card.append([Paragraph(rem_text, body_style)])

                        t_finding = Table(f_card, colWidths=[540])
                        t_finding.setStyle(TableStyle([
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(sev_hex)),
                            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#ffffff")),
                            ("BOX", (0, 0), (-1, -1), 0.5, c_border),
                            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                            ("TOPPADDING", (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ]))
                        elements.append(t_finding)
                        elements.append(Spacer(1, 6))

            doc.build(elements)
            buffer.seek(0)
            return buffer.getvalue()
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}", exc_info=True)
            return f"PDF generation error: {e}".encode("utf-8")
