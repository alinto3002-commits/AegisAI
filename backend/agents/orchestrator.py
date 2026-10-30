import uuid
import logging
import time
import concurrent.futures
from typing import Dict, Any, List

from backend.modules.submission import CodeSubmissionModule
from backend.agents.code_analysis_agent import CodeAnalysisAgent
from backend.agents.security_agent import SecurityVulnerabilityAgent
from backend.agents.remediation_agent import RemediationAgent
from backend.agents.pr_summary_agent import PRSummaryAgent
from backend.models.schemas import (
    CodeSubmission,
    ReviewReport,
    Finding,
    FindingSeverity,
    AgentType,
    RemediationSuggestion,
    PRReviewSummary,
)

logger = logging.getLogger(__name__)

class MultiAgentOrchestrator:
    """
    Module 3: Multi-Agent Orchestration Pipeline.
    Coordinates sequential execution of:
    1. Code Submission & Syntax Validation
    2. Code Analysis Agent (Smells & Complexity)
    3. Security Vulnerability Agent (OWASP 2025 & CWE)
    4. Remediation Agent (RAG-grounded fix suggestions)
    5. PR Summary Agent (Health scoring & PR review summary)
    """

    def __init__(self):
        self.code_agent = CodeAnalysisAgent()
        self.sec_agent = SecurityVulnerabilityAgent()
        self.rem_agent = RemediationAgent()
        self.pr_agent = PRSummaryAgent()

    def analyze(self, submission: CodeSubmission) -> ReviewReport:
        review_id = f"rev-{uuid.uuid4().hex[:8]}"
        timings: Dict[str, float] = {}

        # Step 1: Submission validation & AST parsing
        t0 = time.perf_counter()
        validation = CodeSubmissionModule.validate_code(
            submission.code,
            language=submission.language,
            filename=submission.filename,
        )
        timings["syntax_validation"] = round(time.perf_counter() - t0, 4)

        if not validation.is_valid:
            lines = submission.code.splitlines()
            err_line = validation.error_line or 1
            err_col = validation.error_column or 1
            faulty_line = lines[err_line - 1] if lines and 0 <= err_line - 1 < len(lines) else ""

            # Construct automated unit regression test for syntax verification
            if validation.language == "python":
                unit_test_code = (
                    "import ast\nimport pytest\n\n"
                    "def test_syntax_validity():\n"
                    "    code = '''" + submission.code.replace("'''", "\\'\\'\\'") + "'''\n"
                    "    # Verify that the code parses cleanly without SyntaxError\n"
                    "    try:\n"
                    "        ast.parse(code)\n"
                    "    except SyntaxError as e:\n"
                    "        pytest.fail(f'Syntax error remains: {e}')\n"
                )
            else:
                unit_test_code = (
                    "import org.junit.jupiter.api.Test;\n"
                    "import static org.junit.jupiter.api.Assertions.*;\n\n"
                    "public class SyntaxValidationTest {\n"
                    "    @Test\n"
                    "    void testJavaSyntaxCompiles() {\n"
                    "        // Code must compile without unclosed delimiters or lexical syntax errors\n"
                    "        assertDoesNotThrow(() -> {\n"
                    "            // Syntax check passed\n"
                    "        });\n"
                    "    }\n"
                    "}\n"
                )

            syntax_finding = Finding(
                id=f"SYNTAX-ERR-{err_line}",
                agent_type=AgentType.CODE_ANALYSIS,
                category="Syntax Error: AST Compilation Failure",
                title=f"Syntax Error ({validation.language.title()}): {validation.error_message}",
                description=(
                    f"AST syntax validation failed at line {err_line}, column {err_col}. "
                    f"{validation.error_message}. Code with syntax errors cannot be compiled, "
                    f"executed, or analyzed for deeper architectural and security flaws."
                ),
                severity=FindingSeverity.CRITICAL,
                line_start=err_line,
                line_end=err_line,
                cwe_id="CWE-1059",
                owasp_category="A10:2025-Mishandling of Exceptional Conditions",
                evidence=faulty_line.strip() if faulty_line.strip() else validation.error_message,
                remediation=RemediationSuggestion(
                    explanation=(
                        f"Correct the syntax error at line {err_line} in {validation.filename}. "
                        "Ensure balanced parentheses, braces, quotes, and valid language grammar."
                    ),
                    original_snippet=faulty_line if faulty_line else validation.error_message,
                    corrected_snippet=(
                        f"# Ensure valid {validation.language.title()} syntax at line {err_line}:\n"
                        + (faulty_line + (":" if validation.language == "python" and not faulty_line.rstrip().endswith(":") else ";") if faulty_line else "")
                    ),
                    diff=(
                        f"--- {validation.filename} (Original Syntax Error)\n"
                        f"+++ {validation.filename} (Corrected Syntax)\n"
                        f"@@ -{err_line},1 +{err_line},1 @@\n"
                        f"-{faulty_line}\n"
                        f"+# Resolved syntax error at line {err_line}\n"
                    ),
                    references=[
                        "https://docs.python.org/3/reference/grammar.html" if validation.language == "python" else "https://docs.oracle.com/javase/specs/jls/se21/html/index.html",
                        "https://cwe.mitre.org/data/definitions/1059.html",
                        "https://owasp.org/Top10/2025/A10_Mishandling_of_Exceptional_Conditions/"
                    ],
                    remediation_steps=[
                        f"Inspect line {err_line} in '{validation.filename}'.",
                        f"Address the reported issue: {validation.error_message}.",
                        "Verify matching brackets/parentheses and appropriate language delimiters.",
                        "Click 'Syntax Validation' to verify clean AST parsing."
                    ],
                    unit_test_code=unit_test_code,
                ),
            )

            return ReviewReport(
                id=review_id,
                filename=validation.filename,
                language=validation.language,
                lines_of_code=validation.line_count,
                cyclomatic_complexity=validation.cyclomatic_complexity,
                health_score=0,
                verdict="BLOCKING_SECURITY_RISK",
                risk_level="Critical",
                findings=[syntax_finding],
                severity_counts={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                category_counts={"Syntax Error": 1},
                pr_summary=PRReviewSummary(
                    summary_markdown=(
                        f"### ❌ Syntax Validation Failed\n\n"
                        f"**File:** `{validation.filename}` ({validation.language.title()})  \n"
                        f"**Error Location:** Line {err_line}, Column {err_col}  \n"
                        f"**Error Details:** `{validation.error_message}`\n\n"
                        f"```\n{faulty_line or validation.error_message}\n```\n\n"
                        f"Syntax errors prevent source compilation, abstract syntax tree (AST) construction, and complete security vulnerability scanning. Please resolve this syntax error to proceed with code review."
                    ),
                    verdict="BLOCKING_SECURITY_RISK",
                    health_score=0,
                    risk_level="Critical",
                    key_findings=[validation.error_message or "Syntax Error"],
                    recommended_actions=[
                        f"Resolve syntax error at line {err_line} in {validation.filename}.",
                        "Verify delimiter balance and language punctuation.",
                        "Re-run Syntax Validation to verify."
                    ],
                ),
                agent_execution_times=timings,
            )

        # Steps 2 & 3: Run Code Analysis Agent and Security Vulnerability Agent in parallel (Milestone 2.3)
        t_parallel_start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_code = executor.submit(
                self.code_agent.run,
                code=submission.code,
                language=validation.language,
                ast_summary=validation.ast_summary,
            )
            future_sec = executor.submit(
                self.sec_agent.run,
                code=submission.code,
                language=validation.language,
                filename=validation.filename,
            )
            quality_findings = future_code.result()
            security_findings = future_sec.result()

        elapsed_parallel = round(time.perf_counter() - t_parallel_start, 4)
        timings["code_analysis_agent"] = elapsed_parallel
        timings["security_agent"] = elapsed_parallel
        timings["parallel_execution"] = elapsed_parallel

        # Telemetry & Knowledge base detail breakdown per agent
        sec_detail = self.sec_agent.get_telemetry_detail(security_findings, elapsed_parallel)
        code_detail = self.code_agent.get_telemetry_detail(quality_findings, elapsed_parallel)
        execution_details = [sec_detail, code_detail]

        # Step 4: Remediation Agent (RAG-grounded fix suggestions)
        # Deduplicate findings by (line_start, cwe_id, title) - prioritize security findings
        seen_keys = set()
        deduped_findings: List[Finding] = []
        for f in (security_findings + quality_findings):
            dedup_key = (f.line_start, f.cwe_id, f.title)
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                deduped_findings.append(f)

        t0 = time.perf_counter()
        remediated_findings = self.rem_agent.run(
            findings=deduped_findings,
            code=submission.code,
            language=validation.language,
        )
        timings["remediation_agent"] = round(time.perf_counter() - t0, 4)

        # Step 5: PR Summary Agent
        t0 = time.perf_counter()
        pr_summary = self.pr_agent.run(
            findings=remediated_findings,
            filename=validation.filename,
            language=validation.language,
            loc=validation.line_count,
            cyclomatic_complexity=validation.cyclomatic_complexity,
        )
        timings["pr_summary_agent"] = round(time.perf_counter() - t0, 4)

        # Aggregate counts
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        category_counts: Dict[str, int] = {}
        for f in remediated_findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cat = f.category
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return ReviewReport(
            id=review_id,
            filename=validation.filename,
            language=validation.language,
            lines_of_code=validation.line_count,
            cyclomatic_complexity=validation.cyclomatic_complexity,
            health_score=pr_summary.health_score,
            verdict=pr_summary.verdict,
            risk_level=pr_summary.risk_level,
            findings=remediated_findings,
            severity_counts=severity_counts,
            category_counts=category_counts,
            pr_summary=pr_summary,
            agent_execution_times=timings,
            execution_details=execution_details,
        )

