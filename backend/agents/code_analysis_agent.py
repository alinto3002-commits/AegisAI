import ast
import re
from typing import List, Dict, Any, Optional

from backend.agents.base_agent import BaseAgent
from backend.models.schemas import Finding, FindingSeverity, AgentType

class CodeAnalysisAgent(BaseAgent):
    """
    Agent 1: Code Analysis Agent
    Reviews code structure, identifies code smells, design anti-patterns,
    excessive cyclomatic complexity, and poor programming practices.
    """

    def __init__(self):
        super().__init__(
            name="Code Analysis Agent",
            description="Reviews code structure, code smells, design anti-patterns, and complexity.",
        )

    def run(self, code: str, language: str = "python", ast_summary: Optional[Dict[str, Any]] = None) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.splitlines()

        if language == "python":
            findings.extend(self._analyze_python(code, lines, ast_summary))
        elif language == "java":
            findings.extend(self._analyze_java(code, lines, ast_summary))

        # Common language checks
        findings.extend(self._analyze_general_smells(lines, language))
        return findings

    def _analyze_python(self, code: str, lines: List[str], ast_summary: Optional[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            faulty_line = lines[e.lineno - 1] if (e.lineno and 1 <= e.lineno <= len(lines)) else ""
            findings.append(
                Finding(
                    id=f"SYNTAX-PY-{e.lineno or 1}",
                    agent_type=AgentType.CODE_ANALYSIS,
                    category="Syntax Error: AST Compilation Failure",
                    title=f"Python Syntax Error: {e.msg}",
                    description=f"Python AST parser failed at line {e.lineno}, column {e.offset}: {e.msg}.",
                    severity=FindingSeverity.CRITICAL,
                    line_start=e.lineno or 1,
                    line_end=e.lineno or 1,
                    cwe_id="CWE-1059",
                    owasp_category="A10:2025-Mishandling of Exceptional Conditions",
                    evidence=faulty_line,
                )
            )
            return findings
        except Exception:
            return findings

        # 1. Check for wildcard imports: from module import *
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
                findings.append(
                    Finding(
                        id=f"SMELL-PY-WILDCARD-{node.lineno}",
                        agent_type=AgentType.CODE_ANALYSIS,
                        category="Code Smell: Namespace Pollution",
                        title=f"Wildcard Import Detected (`from {node.module} import *`)",
                        description=f"Using 'from {node.module} import *' pollutes the local namespace, obscures variable origins, and can cause silent name collision bugs.",
                        severity=FindingSeverity.LOW,
                        line_start=node.lineno,
                        line_end=node.lineno,
                        cwe_id="CWE-1075",
                        evidence=lines[node.lineno - 1] if node.lineno <= len(lines) else "",
                    )
                )

        # 2. Check function lengths and complexity
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = node.lineno
                end = getattr(node, "end_lineno", start)
                func_length = end - start + 1

                if func_length > 35:
                    findings.append(
                        Finding(
                            id=f"SMELL-PY-LONGFUNC-{start}",
                            agent_type=AgentType.CODE_ANALYSIS,
                            category="Code Smell: Long Method",
                            title=f"Function '{node.name}' Exceeds Recommended Length ({func_length} lines)",
                            description=f"Function '{node.name}' spans {func_length} lines (recommended: <= 30 lines). Long methods violate the Single Responsibility Principle and increase maintenance burden.",
                            severity=FindingSeverity.MEDIUM if func_length > 60 else FindingSeverity.LOW,
                            line_start=start,
                            line_end=end,
                            cwe_id="CWE-1075",
                            evidence=lines[start - 1] if start <= len(lines) else "",
                        )
                    )

                # Missing docstring in functions with more than 5 lines
                if func_length > 5 and not ast.get_docstring(node):
                    findings.append(
                        Finding(
                            id=f"SMELL-PY-NODOC-{start}",
                            agent_type=AgentType.CODE_ANALYSIS,
                            category="Maintainability: Missing Documentation",
                            title=f"Missing Docstring in Function '{node.name}'",
                            description=f"Public function '{node.name}' does not have a docstring documenting its purpose, arguments, and return types.",
                            severity=FindingSeverity.INFO,
                            line_start=start,
                            line_end=start,
                            cwe_id="CWE-1078",
                            evidence=lines[start - 1] if start <= len(lines) else "",
                        )
                    )

            elif isinstance(node, ast.ClassDef):
                start = node.lineno
                end = getattr(node, "end_lineno", start)
                class_length = end - start + 1
                methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                if class_length > 150 or len(methods) > 10:
                    findings.append(
                        Finding(
                            id=f"SMELL-PY-GODCLASS-{start}",
                            agent_type=AgentType.CODE_ANALYSIS,
                            category="Design Anti-Pattern: God Class",
                            title=f"Class '{node.name}' Shows God Class Characteristics",
                            description=f"Class '{node.name}' has {len(methods)} methods and spans {class_length} lines. Consider decomposing it into smaller, cohesive domain components.",
                            severity=FindingSeverity.MEDIUM,
                            line_start=start,
                            line_end=end,
                            cwe_id="CWE-1061",
                            evidence=lines[start - 1] if start <= len(lines) else "",
                        )
                    )

        # 3. Check for unused imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name_to_check = alias.asname or alias.name
                    # Simple heuristic: is name used in remainder of code?
                    pattern = rf"\b{re.escape(name_to_check)}\b"
                    matches = list(re.finditer(pattern, code))
                    if len(matches) <= 1:  # Only matches import declaration itself
                        findings.append(
                            Finding(
                                id=f"SMELL-PY-UNUSEDIMP-{node.lineno}-{name_to_check}",
                                agent_type=AgentType.CODE_ANALYSIS,
                                category="Code Smell: Dead Code",
                                title=f"Potentially Unused Import '{name_to_check}'",
                                description=f"Imported module '{name_to_check}' does not appear to be referenced anywhere in this file.",
                                severity=FindingSeverity.INFO,
                                line_start=node.lineno,
                                line_end=node.lineno,
                                cwe_id="CWE-561",
                                evidence=lines[node.lineno - 1] if node.lineno <= len(lines) else "",
                            )
                        )

        return findings

    def _analyze_java(self, code: str, lines: List[str], ast_summary: Optional[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []

        # 0. Check Java syntax validity
        from backend.modules.submission import CodeSubmissionModule
        java_val = CodeSubmissionModule.validate_java(code)
        if not java_val.is_valid:
            err_line = java_val.error_line or 1
            faulty_line = lines[err_line - 1] if lines and 0 <= err_line - 1 < len(lines) else ""
            findings.append(
                Finding(
                    id=f"SYNTAX-JAVA-{err_line}",
                    agent_type=AgentType.CODE_ANALYSIS,
                    category="Syntax Error: Lexical Parsing Failure",
                    title=f"Java Syntax Error: {java_val.error_message}",
                    description=f"Java syntax validation failed at line {err_line}: {java_val.error_message}",
                    severity=FindingSeverity.CRITICAL,
                    line_start=err_line,
                    line_end=err_line,
                    cwe_id="CWE-1059",
                    owasp_category="A10:2025-Mishandling of Exceptional Conditions",
                    evidence=faulty_line.strip() if faulty_line else java_val.error_message,
                )
            )
            return findings

        # 1. Wildcard package imports (import java.util.*;)
        for idx, line in enumerate(lines, start=1):
            if re.search(r"^\s*import\s+[a-zA-Z0-9_.]+\.\*\s*;", line):
                findings.append(
                    Finding(
                        id=f"SMELL-JAVA-WILDCARD-{idx}",
                        agent_type=AgentType.CODE_ANALYSIS,
                        category="Code Smell: Wildcard Import",
                        title="Wildcard Package Import Detected in Java",
                        description="Wildcard imports (`.*`) import entire packages, which clutters namespaces and obscures dependency boundaries.",
                        severity=FindingSeverity.LOW,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-1075",
                        evidence=line.strip(),
                    )
                )

        # 2. Check for God Class in Java
        class_matches = re.finditer(r"\bpublic\s+class\s+([a-zA-Z0-9_]+)", code)
        for m in class_matches:
            class_name = m.group(1)
            if len(lines) > 200:
                findings.append(
                    Finding(
                        id=f"SMELL-JAVA-GODCLASS-{class_name}",
                        agent_type=AgentType.CODE_ANALYSIS,
                        category="Design Anti-Pattern: God Class",
                        title=f"Large Class '{class_name}' ({len(lines)} lines)",
                        description=f"Class '{class_name}' is unusually large. Review whether it violates the Single Responsibility Principle.",
                        severity=FindingSeverity.MEDIUM,
                        line_start=1,
                        line_end=len(lines),
                        cwe_id="CWE-1061",
                        evidence=m.group(0),
                    )
                )

        return findings

    def _analyze_general_smells(self, lines: List[str], language: str) -> List[Finding]:
        findings: List[Finding] = []

        # Deep nesting check
        for idx, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Check indentation level
            indent_spaces = len(line) - len(stripped)
            nesting_level = indent_spaces // 4

            if nesting_level >= 4:
                findings.append(
                    Finding(
                        id=f"SMELL-NESTING-{idx}",
                        agent_type=AgentType.CODE_ANALYSIS,
                        category="Code Smell: Deep Nesting",
                        title=f"Excessive Nesting Level ({nesting_level} levels deep)",
                        description=f"Deeply nested control structures at line {idx} hinder readability. Refactor using early returns (guard clauses) or extract nested logic into helper methods.",
                        severity=FindingSeverity.MEDIUM if nesting_level >= 5 else FindingSeverity.LOW,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-1075",
                        evidence=line.strip(),
                    )
                )

        return findings
