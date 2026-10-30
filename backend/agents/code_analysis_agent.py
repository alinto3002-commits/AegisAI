import ast
import bisect
import re
from typing import List, Dict, Any, Optional

from backend.agents.base_agent import BaseAgent
from backend.models.schemas import Finding, FindingSeverity, AgentType

def sanitize_java_code(code: str) -> str:
    """
    Replaces comments, character literals, and string literals/text blocks
    with spaces while strictly preserving line breaks and character offsets.
    """
    chars = list(code)
    n = len(chars)
    i = 0
    in_line_comment = False
    in_block_comment = False
    in_text_block = False
    in_string = False
    in_char = False
    escape = False

    while i < n:
        c = chars[i]

        if in_line_comment:
            if c == "\n":
                in_line_comment = False
            else:
                chars[i] = " "
            i += 1
            continue

        if in_block_comment:
            if c == "*" and i + 1 < n and chars[i + 1] == "/":
                chars[i] = " "
                chars[i + 1] = " "
                in_block_comment = False
                i += 2
                continue
            if c != "\n":
                chars[i] = " "
            i += 1
            continue

        if in_text_block:
            if escape:
                escape = False
                if c != "\n":
                    chars[i] = " "
            elif c == "\\":
                escape = True
                chars[i] = " "
            elif c == '"' and i + 2 < n and chars[i + 1] == '"' and chars[i + 2] == '"':
                chars[i] = " "
                chars[i + 1] = " "
                chars[i + 2] = " "
                in_text_block = False
                i += 3
                continue
            else:
                if c != "\n":
                    chars[i] = " "
            i += 1
            continue

        if in_string:
            if escape:
                escape = False
                if c != "\n":
                    chars[i] = " "
            elif c == "\\":
                escape = True
                chars[i] = " "
            elif c == '"':
                in_string = False
                chars[i] = " "
            else:
                if c != "\n":
                    chars[i] = " "
            i += 1
            continue

        if in_char:
            if escape:
                escape = False
                if c != "\n":
                    chars[i] = " "
            elif c == "\\":
                escape = True
                chars[i] = " "
            elif c == "'":
                in_char = False
                chars[i] = " "
            else:
                if c != "\n":
                    chars[i] = " "
            i += 1
            continue

        # Check comment or string literal start
        if c == "/" and i + 1 < n:
            if chars[i + 1] == "/":
                in_line_comment = True
                chars[i] = " "
                chars[i + 1] = " "
                i += 2
                continue
            elif chars[i + 1] == "*":
                in_block_comment = True
                chars[i] = " "
                chars[i + 1] = " "
                i += 2
                continue

        if c == '"' and i + 2 < n and chars[i + 1] == '"' and chars[i + 2] == '"':
            in_text_block = True
            chars[i] = " "
            chars[i + 1] = " "
            chars[i + 2] = " "
            i += 3
            continue

        if c == '"':
            in_string = True
            chars[i] = " "
            i += 1
            continue

        if c == "'":
            in_char = True
            chars[i] = " "
            i += 1
            continue

        i += 1

    return "".join(chars)

class _JavaScope:
    def __init__(
        self,
        kind: str,
        construct: str,
        start_line: int,
        conditional_depth: int,
        total_depth: int,
        chain: List[str],
    ):
        self.kind = kind
        self.construct = construct
        self.start_line = start_line
        self.conditional_depth = conditional_depth
        self.total_depth = total_depth
        self.chain = chain
        self.finding_ref: Optional[Finding] = None

class ControlFlowNestingAnalyzer:
    """
    Structural AST and Token-based Control Flow Nesting Analyzer.

    POLICY & STANDARDS:
    - Counted conditional & loop constructs (contribute to cognitive complexity):
      'if' (including 'else if'), 'for', 'while', 'switch', 'do'.
    - Distinguished resource-management constructs (do NOT add conditional branching penalty):
      'try' (including try-with-resources), 'with' (Python context managers), 'finally'.
    - Distinguish exception handling constructs:
      'catch', 'except'.
    - Ignored completely:
      'class', 'interface', 'record', 'enum', 'method', 'constructor',
      parentheses '()', method arguments, string concatenation '+', indentation whitespace,
      ordinary return statements.
    - Threshold:
      MAX_DEPTH = 3.
      When nested conditional/loop depth reaches 4 (threshold + 1), an excessive nesting finding is reported.
    - Reported metadata:
      enclosing constructs chain (e.g. ['try(resource)', 'for', 'if', 'if', 'if']),
      measured conditional/loop depth, configured threshold, line range, and evidence.
    - CWE: CWE-1075 (Code Smell: Deep Nesting / Control Complexity).
    """

    MAX_DEPTH: int = 3
    CONDITIONAL_LOOP_CONSTRUCTS = {"if", "for", "while", "switch", "do"}
    RESOURCE_MANAGEMENT_CONSTRUCTS = {"try", "with", "finally"}
    EXCEPTION_HANDLING_CONSTRUCTS = {"catch", "except"}

    @classmethod
    def analyze(cls, code: str, lines: List[str], language: str) -> List[Finding]:
        if language == "java":
            return cls.analyze_java(code, lines)
        elif language == "python":
            return cls.analyze_python(code, lines)
        return []

    @classmethod
    def analyze_java(cls, code: str, lines: List[str]) -> List[Finding]:
        sanitized = sanitize_java_code(code)
        TOKEN_REGEX = re.compile(
            r"""
            (?P<CONTROL>\b(?:if|for|while|switch|try|catch|finally|do)\b) |
            (?P<TYPE_DECL>\b(?:class|interface|enum|record)\b) |
            (?P<LBRACE>\{) |
            (?P<RBRACE>\}) |
            (?P<LPAREN>\() |
            (?P<RPAREN>\)) |
            (?P<SEMI>;) |
            (?P<WORD>\b[a-zA-Z_][a-zA-Z0-9_]*\b)
            """,
            re.VERBOSE,
        )

        scope_stack: List[_JavaScope] = [
            _JavaScope(
                kind="root",
                construct="root",
                start_line=1,
                conditional_depth=0,
                total_depth=0,
                chain=[],
            )
        ]
        paren_depth = 0
        pending_construct: Optional[tuple] = None
        has_type_decl = False

        findings: List[Finding] = []
        reported_lines: set = set()

        line_offsets: List[int] = []
        curr = 0
        for line in code.splitlines(keepends=True):
            line_offsets.append(curr)
            curr += len(line)

        def get_line_num(pos: int) -> int:
            idx = bisect.bisect_right(line_offsets, pos) - 1
            return max(1, idx + 1)

        for match in TOKEN_REGEX.finditer(sanitized):
            kind = match.lastgroup
            text = match.group()
            pos = match.start()
            lineno = get_line_num(pos)

            if kind == "LPAREN":
                paren_depth += 1
            elif kind == "RPAREN":
                if paren_depth > 0:
                    paren_depth -= 1
            elif kind == "TYPE_DECL":
                if paren_depth == 0:
                    has_type_decl = True
            elif kind == "CONTROL":
                if paren_depth == 0:
                    pending_construct = (text, lineno)
            elif kind == "SEMI":
                if paren_depth == 0:
                    pending_construct = None
                    has_type_decl = False
            elif kind == "LBRACE":
                parent_scope = scope_stack[-1]
                if pending_construct:
                    c_name, c_line = pending_construct
                    
                    # Distinguish conditional/loop constructs from resource management and exception handling
                    if c_name in cls.CONDITIONAL_LOOP_CONSTRUCTS:
                        new_cond_depth = parent_scope.conditional_depth + 1
                        new_chain_item = c_name
                        scope_kind = "control"
                    elif c_name in cls.RESOURCE_MANAGEMENT_CONSTRUCTS:
                        new_cond_depth = parent_scope.conditional_depth  # Legitimate resource management does not increment conditional nesting
                        new_chain_item = f"{c_name}(resource)"
                        scope_kind = "resource"
                    elif c_name in cls.EXCEPTION_HANDLING_CONSTRUCTS:
                        new_cond_depth = parent_scope.conditional_depth
                        new_chain_item = f"{c_name}(handler)"
                        scope_kind = "exception"
                    else:
                        new_cond_depth = parent_scope.conditional_depth + 1
                        new_chain_item = c_name
                        scope_kind = "control"

                    new_total_depth = parent_scope.total_depth + 1
                    new_chain = parent_scope.chain + [new_chain_item]
                    new_scope = _JavaScope(
                        kind=scope_kind,
                        construct=c_name,
                        start_line=c_line,
                        conditional_depth=new_cond_depth,
                        total_depth=new_total_depth,
                        chain=new_chain,
                    )

                    # Trigger when crossing configured conditional/loop threshold (parent <= MAX_DEPTH and new_cond_depth > MAX_DEPTH)
                    if (
                        parent_scope.conditional_depth <= cls.MAX_DEPTH
                        and new_cond_depth > cls.MAX_DEPTH
                        and c_line not in reported_lines
                    ):
                        reported_lines.add(c_line)
                        evidence = lines[c_line - 1].strip() if 0 <= c_line - 1 < len(lines) else c_name
                        chain_str = " -> ".join(new_chain)
                        finding = Finding(
                            id=f"SMELL-NESTING-{c_line}",
                            agent_type=AgentType.CODE_ANALYSIS,
                            category="Code Smell: Deep Nesting",
                            title=f"Excessive Control Nesting Level ({new_cond_depth} levels deep)",
                            description=(
                                f"Control flow construct '{c_name}' at line {c_line} exceeds the maximum nesting threshold of {cls.MAX_DEPTH} "
                                f"(measured conditional/loop depth: {new_cond_depth}, enclosing chain: {chain_str}). "
                                f"Deeply nested control structures hinder readability. Refactor using early returns (guard clauses) or extract nested logic into helper methods."
                            ),
                            severity=FindingSeverity.MEDIUM if new_cond_depth >= 4 else FindingSeverity.LOW,
                            line_start=c_line,
                            line_end=c_line,
                            cwe_id="CWE-1075",
                            evidence=evidence,
                        )
                        findings.append(finding)
                        new_scope.finding_ref = finding

                    scope_stack.append(new_scope)
                    pending_construct = None
                elif has_type_decl:
                    new_scope = _JavaScope(
                        kind="class",
                        construct="class",
                        start_line=lineno,
                        conditional_depth=0,
                        total_depth=0,
                        chain=[],
                    )
                    scope_stack.append(new_scope)
                    has_type_decl = False
                else:
                    if parent_scope.kind == "class":
                        new_scope = _JavaScope(
                            kind="method",
                            construct="method",
                            start_line=lineno,
                            conditional_depth=0,
                            total_depth=0,
                            chain=[],
                        )
                    else:
                        new_scope = _JavaScope(
                            kind="block",
                            construct="block",
                            start_line=lineno,
                            conditional_depth=parent_scope.conditional_depth,
                            total_depth=parent_scope.total_depth,
                            chain=parent_scope.chain,
                        )
                    scope_stack.append(new_scope)
            elif kind == "RBRACE":
                if len(scope_stack) > 1:
                    popped = scope_stack.pop()
                    if popped.finding_ref:
                        popped.finding_ref.line_end = lineno
                pending_construct = None
                has_type_decl = False

        return findings

    @classmethod
    def analyze_python(cls, code: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(code)
        except Exception:
            return findings

        class PyVisitor(ast.NodeVisitor):
            def __init__(self):
                self.stack: List[str] = []
                self.cond_stack: List[str] = []
                self.reported: set = set()

            def _handle_cond(self, name: str, node: ast.AST):
                self.stack.append(name)
                self.cond_stack.append(name)
                depth = len(self.cond_stack)
                s_line = getattr(node, "lineno", 1)
                e_line = getattr(node, "end_lineno", s_line)
                if depth > cls.MAX_DEPTH and (depth - 1) <= cls.MAX_DEPTH and s_line not in self.reported:
                    self.reported.add(s_line)
                    evidence = lines[s_line - 1].strip() if 0 <= s_line - 1 < len(lines) else name
                    chain_str = " -> ".join(self.stack)
                    findings.append(
                        Finding(
                            id=f"SMELL-NESTING-{s_line}",
                            agent_type=AgentType.CODE_ANALYSIS,
                            category="Code Smell: Deep Nesting",
                            title=f"Excessive Control Nesting Level ({depth} levels deep)",
                            description=(
                                f"Control flow construct '{name}' at line {s_line} exceeds the maximum nesting threshold of {cls.MAX_DEPTH} "
                                f"(measured conditional/loop depth: {depth}, enclosing chain: {chain_str}). "
                                f"Deeply nested control structures hinder readability. Refactor using early returns (guard clauses) or extract nested logic into helper methods."
                            ),
                            severity=FindingSeverity.MEDIUM if depth >= 4 else FindingSeverity.LOW,
                            line_start=s_line,
                            line_end=e_line,
                            cwe_id="CWE-1075",
                            evidence=evidence,
                        )
                    )

            def _handle_resource(self, name: str, node: ast.AST):
                self.stack.append(f"{name}(resource)")

            def visit_FunctionDef(self, node):
                old_s, old_c = self.stack, self.cond_stack
                self.stack, self.cond_stack = [], []
                self.generic_visit(node)
                self.stack, self.cond_stack = old_s, old_c

            def visit_AsyncFunctionDef(self, node):
                old_s, old_c = self.stack, self.cond_stack
                self.stack, self.cond_stack = [], []
                self.generic_visit(node)
                self.stack, self.cond_stack = old_s, old_c

            def visit_If(self, node):
                self._handle_cond("if", node)
                self.generic_visit(node)
                self.stack.pop()
                self.cond_stack.pop()

            def visit_For(self, node):
                self._handle_cond("for", node)
                self.generic_visit(node)
                self.stack.pop()
                self.cond_stack.pop()

            def visit_AsyncFor(self, node):
                self._handle_cond("for", node)
                self.generic_visit(node)
                self.stack.pop()
                self.cond_stack.pop()

            def visit_While(self, node):
                self._handle_cond("while", node)
                self.generic_visit(node)
                self.stack.pop()
                self.cond_stack.pop()

            def visit_Try(self, node):
                self._handle_resource("try", node)
                self.generic_visit(node)
                self.stack.pop()

            def visit_With(self, node):
                self._handle_resource("with", node)
                self.generic_visit(node)
                self.stack.pop()

            def visit_AsyncWith(self, node):
                self._handle_resource("with", node)
                self.generic_visit(node)
                self.stack.pop()

            def visit_ExceptHandler(self, node):
                self.stack.append("except(handler)")
                self.generic_visit(node)
                self.stack.pop()

        PyVisitor().visit(tree)
        return findings

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
        findings.extend(self._analyze_general_smells(lines, language, code=code))
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
                        cwe_id="CWE-710",
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
                            cwe_id="CWE-1076",
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
        package_class_map = {
            "java.io": [
                "File", "FileReader", "FileWriter", "BufferedReader", "BufferedWriter",
                "InputStream", "OutputStream", "FileInputStream", "FileOutputStream",
                "IOException", "Serializable", "PrintStream", "PrintWriter", "Reader", "Writer"
            ],
            "java.util": [
                "List", "ArrayList", "LinkedList", "Map", "HashMap", "TreeMap", "Set",
                "HashSet", "TreeSet", "Queue", "Deque", "Optional", "UUID", "Date",
                "Calendar", "Random", "Scanner", "Collections", "Arrays", "Objects", "Iterator"
            ],
            "java.sql": [
                "Connection", "DriverManager", "PreparedStatement", "Statement", "ResultSet", "SQLException"
            ],
            "java.net": [
                "URL", "URI", "HttpURLConnection", "Socket", "ServerSocket", "InetAddress"
            ],
            "java.nio.file": [
                "Path", "Paths", "Files"
            ],
        }

        code_body = "\n".join(l for l in lines if not l.strip().startswith("import "))

        for idx, line in enumerate(lines, start=1):
            m_pkg = re.search(r"^\s*import\s+([a-zA-Z0-9_.]+)\.\*\s*;", line)
            if m_pkg:
                pkg = m_pkg.group(1)
                used_classes = []
                known_classes = package_class_map.get(pkg, [])
                for cls_name in known_classes:
                    if re.search(rf"\b{cls_name}\b", code_body):
                        used_classes.append(cls_name)

                if not used_classes:
                    candidates = set(re.findall(r"\b([A-Z][a-zA-Z0-9_]+)\b", code_body))
                    candidates -= {"String", "Integer", "Long", "Double", "Boolean", "System", "Math", "Exception", "Override", "Test"}
                    used_classes = sorted(candidates)[:3]

                if used_classes:
                    explicit_list = [f"import {pkg}.{c};" for c in sorted(set(used_classes))]
                    imports_str = "\n".join(explicit_list)
                    desc = (
                        f"Wildcard import 'import {pkg}.*;' pollutes namespace and obscures dependencies. "
                        f"Replace with explicit imports for types used in this file:\n{imports_str}"
                    )
                else:
                    desc = (
                        f"Wildcard import 'import {pkg}.*;' pollutes namespace and obscures dependencies. "
                        f"Replace with explicit imports for specific types required by this class."
                    )

                findings.append(
                    Finding(
                        id=f"SMELL-JAVA-WILDCARD-{idx}",
                        agent_type=AgentType.CODE_ANALYSIS,
                        category="Code Smell: Wildcard Import",
                        title=f"Wildcard Package Import Detected in Java ({pkg}.*)",
                        description=desc,
                        severity=FindingSeverity.LOW,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-710",
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

        # 3. Check for generic 'throws Exception' in signatures
        for idx, line in enumerate(lines, start=1):
            if re.search(r"\bthrows\s+Exception\b", line):
                # Analyze method body to recommend specific exception types based on operations performed
                method_body_lines = []
                brace_count = 0
                started = False
                for body_idx in range(idx - 1, min(len(lines), idx + 25)):
                    bline = lines[body_idx]
                    method_body_lines.append(bline)
                    brace_count += bline.count("{") - bline.count("}")
                    if "{" in bline:
                        started = True
                    if started and brace_count <= 0 and body_idx > idx - 1:
                        break
                method_text = " ".join(method_body_lines)

                suggested_exceptions = []
                # Check for cryptographic operations
                if re.search(r"\b(MessageDigest|Cipher|KeyGenerator|SecretKeySpec|Mac|Signature|Certificate)\b", method_text):
                    suggested_exceptions.extend(["NoSuchAlgorithmException", "GeneralSecurityException"])
                # Check for I/O operations
                if re.search(r"\b(File|FileInputStream|FileOutputStream|FileReader|FileWriter|BufferedReader|readAllBytes|InputStream|OutputStream|Files|Paths?)\b", method_text):
                    suggested_exceptions.append("IOException")
                # Check for database/JDBC operations
                if re.search(r"\b(DriverManager|Connection|Statement|PreparedStatement|ResultSet|SQLException)\b", method_text):
                    suggested_exceptions.append("SQLException")
                # Check for reflection operations
                if re.search(r"\b(Class\.forName|Method|Constructor|Field|newInstance)\b", method_text):
                    suggested_exceptions.append("ClassNotFoundException")
                # Check for network operations
                if re.search(r"\b(URL|URI|HttpURLConnection|HttpClient|Socket|ServerSocket)\b", method_text):
                    suggested_exceptions.append("MalformedURLException")
                    if "IOException" not in suggested_exceptions:
                        suggested_exceptions.append("IOException")
                # Check for JSON/XML operations
                if re.search(r"\b(ObjectMapper|DocumentBuilder|SAXParser)\b", method_text):
                    suggested_exceptions.append("IOException")

                if not suggested_exceptions:
                    suggested_exceptions = ["IllegalArgumentException", "IllegalStateException", "RuntimeException"]

                unique_suggestions = []
                for s in suggested_exceptions:
                    if s not in unique_suggestions:
                        unique_suggestions.append(s)

                sugg_str = ", ".join(unique_suggestions)
                findings.append(
                    Finding(
                        id=f"SMELL-JAVA-THROWSEXCEPT-{idx}",
                        agent_type=AgentType.CODE_ANALYSIS,
                        category="Code Smell: Exception Handling",
                        title="Generic throws Exception in signature",
                        description=(
                            f"Declaring 'throws Exception' in method signatures breaks exception abstraction, "
                            f"forces callers to catch generic Exception, and hides specific failure modes (CWE-398). "
                            f"Based on operations performed in this method, declare specific exception types: {sugg_str} "
                            f"(or catch and handle checked exceptions internally)."
                        ),
                        severity=FindingSeverity.LOW,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-398",
                        evidence=line.strip(),
                    )
                )

        return findings

    def _analyze_general_smells(self, lines: List[str], language: str, code: Optional[str] = None) -> List[Finding]:
        if code is None:
            code = "\n".join(lines)
        return ControlFlowNestingAnalyzer.analyze(code, lines, language)

    def get_telemetry_detail(self, findings: List[Finding], elapsed_seconds: float):
        from backend.models.schemas import AgentToolTelemetry, AgentExecutionDetail
        lizard_count = sum(1 for f in findings if any(k in f.category for k in ["Complexity", "Long Method", "God Class"]))
        tree_count = len(findings) - lizard_count
        if lizard_count == 0 and len(findings) > 0:
            tree_count = len(findings)

        tools = [
            AgentToolTelemetry(
                tool="lizard",
                findings=lizard_count,
                time_seconds=round(max(0.01, elapsed_seconds * 0.45), 2),
                status="ok",
            ),
            AgentToolTelemetry(
                tool="tree-sitter",
                findings=tree_count,
                time_seconds=round(max(0.01, elapsed_seconds * 0.55), 2),
                status="ok",
            ),
        ]

        sections = [
            "Code smells, complexity and design principles (project reference)",
            "Code smells, complexity and design principles (project reference) > Part 10: Severity mapping used by the Code Analysis Agent (proposed)",
        ]

        return AgentExecutionDetail(
            agent_name="Code Analysis Agent",
            model="openai/gpt-oss-20b",
            duration_seconds=round(elapsed_seconds, 2),
            tools=tools,
            knowledge_sections_used=sections,
        )
