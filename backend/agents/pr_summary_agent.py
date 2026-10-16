from typing import List, Dict, Any

from backend.agents.base_agent import BaseAgent
from backend.models.schemas import Finding, FindingSeverity, PRReviewSummary

class PRSummaryAgent(BaseAgent):
    """
    Agent 4: PR Summary Agent
    Compiles all findings from Code Analysis and Security Agents into
    a structured, human-readable Pull Request style review summary.
    """

    def __init__(self):
        super().__init__(
            name="PR Summary Agent",
            description="Compiles all agent findings into a structured, human-readable pull request review summary.",
        )

    def run(
        self,
        findings: List[Finding],
        filename: str = "main.py",
        language: str = "python",
        loc: int = 0,
        cyclomatic_complexity: int = 1,
    ) -> PRReviewSummary:
        # Calculate severity counts
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Health score calculation
        # Deduct: Critical=25, High=15, Medium=8, Low=3, Info=1
        penalty = (
            severity_counts["CRITICAL"] * 25
            + severity_counts["HIGH"] * 15
            + severity_counts["MEDIUM"] * 8
            + severity_counts["LOW"] * 3
            + severity_counts["INFO"] * 1
        )
        health_score = max(0, min(100, 100 - penalty))

        # Risk level
        if health_score < 50 or severity_counts["CRITICAL"] > 0:
            risk_level = "Critical"
            verdict = "BLOCKING_SECURITY_RISK"
        elif health_score < 75 or severity_counts["HIGH"] > 0:
            risk_level = "High"
            verdict = "CHANGES_REQUESTED"
        elif health_score < 90 or severity_counts["MEDIUM"] > 0:
            risk_level = "Moderate"
            verdict = "CHANGES_REQUESTED"
        else:
            risk_level = "Low"
            verdict = "APPROVED"

        # Key findings summary
        key_findings = [f"[{f.severity.value}] {f.title} (line {f.line_start})" for f in findings[:5]]

        # Actionable recommendations
        actions = []
        if severity_counts["CRITICAL"] > 0:
            actions.append("CRITICAL: Immediately remediate all injection or secret leaks before deploying.")
        if severity_counts["HIGH"] > 0:
            actions.append("HIGH: Replace broken cryptographic primitives or file path concatenations.")
        if severity_counts["MEDIUM"] > 0:
            actions.append("MEDIUM: Refactor nested code blocks and add explicit exception handling.")
        if not actions:
            actions.append("Code meets baseline security and quality standards. Safe to merge!")

        # Build Markdown PR Summary
        verdict_badge = {
            "BLOCKING_SECURITY_RISK": "🛑 **BLOCKING SECURITY RISK**",
            "CHANGES_REQUESTED": "⚠️ **CHANGES REQUESTED**",
            "APPROVED": "✅ **APPROVED**",
        }.get(verdict, verdict)

        md = f"""# 🛡️ Automated Code Review & Security Analysis Report

### PR Review Gate: {verdict_badge}
**Target File:** `{filename}` | **Language:** `{language.capitalize()}` | **Lines of Code:** `{loc}` | **Complexity:** `{cyclomatic_complexity}`

---

### 📊 Health Score & Severity Breakdown
- **Security & Quality Health Score:** **`{health_score} / 100`** (Risk Level: **{risk_level}**)
- 🔴 **Critical:** `{severity_counts['CRITICAL']}`
- 🟠 **High:** `{severity_counts['HIGH']}`
- 🟡 **Medium:** `{severity_counts['MEDIUM']}`
- 🔵 **Low:** `{severity_counts['LOW']}`
- ⚪ **Info:** `{severity_counts['INFO']}`

---

### 🔍 Key Findings Highlights
"""
        if findings:
            for f in findings:
                owasp_tag = f" | `{f.owasp_category}`" if f.owasp_category else ""
                cwe_tag = f" | `{f.cwe_id}`" if f.cwe_id else ""
                md += f"- **[{f.severity.value}]** {f.title} (Lines {f.line_start}-{f.line_end}){owasp_tag}{cwe_tag}\n"
        else:
            md += "✨ *No quality issues or security vulnerabilities detected in the analyzed code snippet.*\n"

        md += "\n---\n\n### 📋 Recommended Next Steps\n"
        for act in actions:
            md += f"1. {act}\n"

        return PRReviewSummary(
            summary_markdown=md,
            verdict=verdict,
            health_score=health_score,
            risk_level=risk_level,
            key_findings=key_findings,
            recommended_actions=actions,
        )
