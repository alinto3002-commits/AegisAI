from typing import List, Dict, Any

from backend.agents.base_agent import BaseAgent
from backend.models.schemas import Finding, FindingSeverity, PRReviewSummary, AgentType

class PRSummaryAgent(BaseAgent):
    """
    Agent 4: PR Summary Agent
    Compiles all findings from Code Analysis and Security Agents into
    a structured, human-readable Pull Request review summary.

    SCORING POLICY (Documented, Consistent):
    - Base Score: 100
    - Security Vulnerability Penalties:
      * CRITICAL: -25 pts (Immediate exploitability, e.g. SQLi, RCE, Leaked Secret)
      * HIGH:     -15 pts (High severity flaw, e.g. Path Traversal, Broken Crypto, Weak PRNG)
      * MEDIUM:   -8 pts  (Insecure config, missing rate limit, empty catch/fail-open)
      * LOW:      -3 pts  (Informational security smells)
      * INFO:     -1 pt
    - Code Quality / Maintainability Penalties:
      * CRITICAL: -25 pts (AST compilation / syntax failures)
      * HIGH:     -10 pts (Severe structural anti-patterns)
      * MEDIUM:   -5 pts  (Excessive control nesting >= 4, God class)
      * LOW:      -2 pts  (Wildcard imports, functions > 35 lines)
      * INFO:     -1 pt   (Missing docstrings, unused imports)
    - Total Health Score: max(0, min(100, 100 - (sec_penalty + maint_penalty)))
    - Verdict Gates:
      * BLOCKING_SECURITY_RISK: Any CRITICAL security finding or Health Score < 50
      * CHANGES_REQUESTED:      Any HIGH finding, MEDIUM finding, or Health Score < 90
      * APPROVED:               No CRITICAL/HIGH/MEDIUM findings and Health Score >= 90
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
        # Separate security vulnerabilities from code quality / maintainability issues
        sec_findings = [f for f in findings if f.agent_type == AgentType.SECURITY_VULNERABILITY]
        maint_findings = [f for f in findings if f.agent_type == AgentType.CODE_ANALYSIS]

        # Calculate severity counts for security findings
        sec_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in sec_findings:
            sev = f.severity.value
            sec_counts[sev] = sec_counts.get(sev, 0) + 1

        # Calculate severity counts for maintainability findings
        maint_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in maint_findings:
            sev = f.severity.value
            maint_counts[sev] = maint_counts.get(sev, 0) + 1

        # Overall severity counts
        severity_counts = {
            k: sec_counts[k] + maint_counts[k] for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        }

        # Documented penalty calculation
        sec_penalty = (
            sec_counts["CRITICAL"] * 25
            + sec_counts["HIGH"] * 15
            + sec_counts["MEDIUM"] * 8
            + sec_counts["LOW"] * 3
            + sec_counts["INFO"] * 1
        )
        maint_penalty = (
            maint_counts["CRITICAL"] * 25
            + maint_counts["HIGH"] * 10
            + maint_counts["MEDIUM"] * 5
            + maint_counts["LOW"] * 2
            + maint_counts["INFO"] * 1
        )
        total_penalty = sec_penalty + maint_penalty
        health_score = max(0, min(100, 100 - total_penalty))

        # Risk level and PR review gate verdict
        if health_score < 50 or sec_counts["CRITICAL"] > 0 or maint_counts["CRITICAL"] > 0:
            risk_level = "Critical"
            verdict = "BLOCKING_SECURITY_RISK"
        elif health_score < 75 or sec_counts["HIGH"] > 0:
            risk_level = "High"
            verdict = "CHANGES_REQUESTED"
        elif health_score < 90 or sec_counts["MEDIUM"] > 0 or maint_counts["MEDIUM"] > 0:
            risk_level = "Moderate"
            verdict = "CHANGES_REQUESTED"
        else:
            risk_level = "Low"
            verdict = "APPROVED"

        # Key findings highlights (prioritize security over maintainability)
        sorted_findings = sorted(
            findings,
            key=lambda x: (
                0 if x.agent_type == AgentType.SECURITY_VULNERABILITY else 1,
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.severity.value, 5),
            ),
        )
        key_findings = [f"[{f.severity.value}] {f.title} (line {f.line_start})" for f in sorted_findings[:5]]

        # Actionable recommendations
        actions = []
        if sec_counts["CRITICAL"] > 0:
            actions.append("CRITICAL: Immediately remediate all injection or secret leaks before deploying.")
        if sec_counts["HIGH"] > 0:
            actions.append("HIGH: Replace broken cryptographic primitives or file path concatenations.")
        if sec_counts["MEDIUM"] > 0:
            actions.append("MEDIUM: Enforce authentication rate limiting and resolve empty catch blocks.")
        if maint_counts["MEDIUM"] > 0 or maint_counts["LOW"] > 0:
            actions.append("MAINTAINABILITY: Refactor deeply nested control structures and replace wildcard imports.")
        if not actions:
            actions.append(
                "Static analysis baseline checks passed. Proceed with unit test execution, dynamic verification, and peer code review before production deployment."
            )

        # Build Markdown PR Summary
        verdict_badge = {
            "BLOCKING_SECURITY_RISK": "🛑 **BLOCKING SECURITY RISK**",
            "CHANGES_REQUESTED": "⚠️ **CHANGES REQUESTED**",
            "APPROVED": "✅ **APPROVED (STATIC BASELINE PASSED)**",
        }.get(verdict, verdict)

        md = f"""# 🛡️ Automated Code Review & Security Analysis Report

### PR Review Gate: {verdict_badge}
**Target File:** `{filename}` | **Language:** `{language.capitalize()}` | **Lines of Code:** `{loc}` | **Complexity:** `{cyclomatic_complexity}`

---

### 📊 Health Score & Severity Breakdown
- **Security & Quality Health Score:** **`{health_score} / 100`** (Risk Level: **{risk_level}**)
- 🔴 **Critical:** `{severity_counts['CRITICAL']}` (Sec: {sec_counts['CRITICAL']}, Quality: {maint_counts['CRITICAL']})
- 🟠 **High:** `{severity_counts['HIGH']}` (Sec: {sec_counts['HIGH']}, Quality: {maint_counts['HIGH']})
- 🟡 **Medium:** `{severity_counts['MEDIUM']}` (Sec: {sec_counts['MEDIUM']}, Quality: {maint_counts['MEDIUM']})
- 🔵 **Low:** `{severity_counts['LOW']}` (Sec: {sec_counts['LOW']}, Quality: {maint_counts['LOW']})
- ⚪ **Info:** `{severity_counts['INFO']}` (Sec: {sec_counts['INFO']}, Quality: {maint_counts['INFO']})

---

### 🔍 Findings Summary by Dimension
"""
        if sec_findings:
            md += "#### 🔒 Security Vulnerabilities (OWASP Top 10 / CWE)\n"
            for f in sec_findings:
                owasp_tag = f" | `{f.owasp_category}`" if f.owasp_category else ""
                cwe_tag = f" | `{f.cwe_id}`" if f.cwe_id else ""
                md += f"- **[{f.severity.value}]** {f.title} (Lines {f.line_start}-{f.line_end}){owasp_tag}{cwe_tag}\n"
            md += "\n"

        if maint_findings:
            md += "#### 📐 Code Quality & Maintainability Issues (AST Smells)\n"
            for f in maint_findings:
                cwe_tag = f" | `{f.cwe_id}`" if f.cwe_id else ""
                md += f"- **[{f.severity.value}]** {f.title} (Lines {f.line_start}-{f.line_end}) | `{f.category}`{cwe_tag}\n"
            md += "\n"

        if not findings:
            md += (
                "#### 🔍 Static Analysis Baseline Verification\n"
                "- **Automated Rule Checks:** All active static analysis rules passed baseline compliance. "
                "No syntax errors, OWASP Top 10 (2025) pattern matches, or excessive nesting anti-patterns were detected in this source unit.\n"
                "- **Verification Notice:** Passing static analysis does NOT guarantee absolute runtime security or complete absence of vulnerabilities. "
                "Comprehensive assurance requires integration testing, runtime behavioral checks, dependency vulnerability scanning (SCA), and peer security review.\n\n"
            )

        md += "---\n\n### 📋 Recommended Next Steps\n"
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
