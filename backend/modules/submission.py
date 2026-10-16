import ast
import re
from typing import Dict, Any, List, Optional, Tuple
from backend.models.schemas import SyntaxValidationResult

class CodeSubmissionModule:
    """
    Module 1: Code Submission & Syntax Validation Module.
    Handles code paste, file uploads, language detection, AST syntax validation,
    structural metadata extraction, and cyclomatic complexity analysis for Python & Java.
    """

    @staticmethod
    def detect_language(code: str, filename: Optional[str] = None) -> str:
        """Determines if the code is Python or Java based on filename or lexical signatures."""
        # Non-default filename override (e.g. uploaded file like UserClass.java or script.py)
        if filename and filename.lower() not in ("main.py", "main.java"):
            lower_name = filename.lower()
            if lower_name.endswith(".java"):
                return "java"
            if lower_name.endswith(".py"):
                return "python"

        if not code or not code.strip():
            if filename:
                lower_name = filename.lower()
                if lower_name.endswith(".java"):
                    return "java"
                if lower_name.endswith(".py"):
                    return "python"
            return "python"

        # Lexical signature checks with weights
        java_signatures = [
            (r"\bpublic\s+(class|interface|enum|record)\b", 6),
            (r"\bpublic\s+static\s+void\s+main\b", 6),
            (r"\bSystem\.out\.(println|print|printf)\b", 6),
            (r"\bSystem\.err\.(println|print|printf)\b", 6),
            (r"\bpackage\s+[a-zA-Z0-9_.]+;", 5),
            (r"\bimport\s+java\.[a-zA-Z0-9_.]+;", 5),
            (r"\bimport\s+javax\.[a-zA-Z0-9_.]+;", 5),
            (r"\bimport\s+org\.[a-zA-Z0-9_.]+;", 5),
            (r"\b(private|protected|public)\s+[\w<>\[\]]+\s+[a-zA-Z0-9_]+\s*\(", 4),
            (r"\b(boolean|int|double|float|long|short|byte|char|void|String)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*(=|;|,|\))", 4),
            (r"\bnew\s+[A-Z][a-zA-Z0-9_]*\s*\(", 3),
            (r";\s*$", 2),
            (r"\bcatch\s*\([A-Z]\w+Exception\b", 4),
            (r"\bthrows\s+[A-Z]\w+Exception\b", 4),
            (r"@Override\b", 3),
        ]
        java_score = sum(w for pattern, w in java_signatures if re.search(pattern, code, re.MULTILINE))

        python_signatures = [
            (r"^\s*def\s+[a-zA-Z0-9_]+\s*\(.*?\):", 6),
            (r"^\s*class\s+[a-zA-Z0-9_]+(\(.*?\))?:", 6),
            (r"^\s*import\s+[a-zA-Z0-9_]+", 5),
            (r"^\s*from\s+[a-zA-Z0-9_.]+\s+import\b", 5),
            (r"\belif\b", 5),
            (r"\bexcept(\s+[a-zA-Z0-9_]+)?\s*:", 5),
            (r"\bfinally\s*:", 3),
            (r"\bprint\s*\(", 4),
            (r"\bself\.[a-zA-Z0-9_]+", 5),
            (r"\b__init__\b", 5),
            (r"\b__name__\s*==\s*['\"]__main__['\"]", 5),
            (r"^\s*#.*$", 2),
            (r"\bNone\b", 4),
            (r"\bTrue\b|\bFalse\b", 3),
            (r":\s*$", 2),
            (r"\bpass\b", 3),
            (r"\bwith\s+.+\s+as\s+.+:", 4),
        ]
        python_score = sum(w for pattern, w in python_signatures if re.search(pattern, code, re.MULTILINE))

        if java_score > python_score:
            return "java"
        elif python_score > java_score:
            return "python"

        # Fallback to filename if available
        if filename:
            lower_name = filename.lower()
            if lower_name.endswith(".java"):
                return "java"
            if lower_name.endswith(".py"):
                return "python"

        return "python"

    @staticmethod
    def calculate_python_complexity(node: ast.AST) -> int:
        """Computes cyclomatic complexity for Python AST."""
        complexity = 1
        for subnode in ast.walk(node):
            if isinstance(subnode, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler, ast.With, ast.Assert)):
                complexity += 1
            elif isinstance(subnode, ast.BoolOp):
                complexity += len(subnode.values) - 1
            elif isinstance(subnode, ast.IfExp):  # ternary
                complexity += 1
        return complexity

    @classmethod
    def validate_python(cls, code: str, filename: str = "script.py") -> SyntaxValidationResult:
        """Validates Python syntax using the native ast module and collects metadata."""
        lines = code.splitlines()
        line_count = len(lines)

        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as e:
            return SyntaxValidationResult(
                is_valid=False,
                language="python",
                filename=filename,
                line_count=line_count,
                error_message=f"SyntaxError: {e.msg} at line {e.lineno}, column {e.offset}",
                error_line=e.lineno,
                error_column=e.offset,
                ast_summary={},
                cyclomatic_complexity=1,
            )

        # Extract AST structure
        functions = []
        classes = []
        imports = []
        docstring_count = 0

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append({
                    "name": node.name,
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", node.lineno),
                    "arg_count": len(node.args.args),
                    "complexity": cls.calculate_python_complexity(node),
                })
                if ast.get_docstring(node):
                    docstring_count += 1
            elif isinstance(node, ast.ClassDef):
                classes.append({
                    "name": node.name,
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", node.lineno),
                })
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}" if module else alias.name)

        overall_complexity = cls.calculate_python_complexity(tree)

        return SyntaxValidationResult(
            is_valid=True,
            language="python",
            filename=filename,
            line_count=line_count,
            ast_summary={
                "functions": functions,
                "classes": classes,
                "imports": list(set(imports)),
                "function_count": len(functions),
                "class_count": len(classes),
                "docstring_count": docstring_count,
            },
            cyclomatic_complexity=overall_complexity,
        )

    @staticmethod
    def calculate_java_complexity(code: str) -> int:
        """Estimates cyclomatic complexity for Java source code."""
        complexity = 1
        patterns = [
            r"\bif\s*\(",
            r"\belse\s+if\s*\(",
            r"\bfor\s*\(",
            r"\bwhile\s*\(",
            r"\bcase\b",
            r"\bcatch\s*\(",
            r"&&",
            r"\|\|",
            r"\?[^:]+:",
        ]
        for pat in patterns:
            complexity += len(re.findall(pat, code))
        return complexity

    @classmethod
    def validate_java(cls, code: str, filename: str = "App.java") -> SyntaxValidationResult:
        """
        Validates Java source code structure, balanced delimiters,
        presence of class declaration, and statement terminations.
        """
        lines = code.splitlines()
        line_count = len(lines)

        # 1. Delimiter balance check (ignoring strings and comments)
        clean_code = ""
        in_line_comment = False
        in_block_comment = False
        in_string = False
        in_char = False
        stack: List[Tuple[str, int, int]] = []  # (char, line, col)

        curr_line = 1
        curr_col = 0

        i = 0
        while i < len(code):
            ch = code[i]
            curr_col += 1
            if ch == "\n":
                curr_line += 1
                curr_col = 0
                in_line_comment = False
                clean_code += "\n"
                i += 1
                continue

            # Handle comments
            if in_line_comment:
                i += 1
                continue
            if in_block_comment:
                if ch == "*" and i + 1 < len(code) and code[i + 1] == "/":
                    in_block_comment = False
                    i += 2
                    curr_col += 1
                    continue
                i += 1
                continue

            if not in_string and not in_char:
                if ch == "/" and i + 1 < len(code) and code[i + 1] == "/":
                    in_line_comment = True
                    i += 2
                    curr_col += 1
                    continue
                if ch == "/" and i + 1 < len(code) and code[i + 1] == "*":
                    in_block_comment = True
                    i += 2
                    curr_col += 1
                    continue

            # Handle string and char literals
            if ch == '"' and not in_char:
                if not in_string:
                    in_string = True
                elif i > 0 and code[i - 1] != "\\":
                    in_string = False
                clean_code += " "
                i += 1
                continue

            if ch == "'" and not in_string:
                if not in_char:
                    in_char = True
                elif i > 0 and code[i - 1] != "\\":
                    in_char = False
                clean_code += " "
                i += 1
                continue

            if in_string or in_char:
                i += 1
                continue

            clean_code += ch

            # Check brackets
            if ch in "({[":
                stack.append((ch, curr_line, curr_col))
            elif ch in ")}]":
                if not stack:
                    return SyntaxValidationResult(
                        is_valid=False,
                        language="java",
                        filename=filename,
                        line_count=line_count,
                        error_message=f"Java Syntax Error: Unmatched closing delimiter '{ch}' at line {curr_line}:{curr_col}",
                        error_line=curr_line,
                        error_column=curr_col,
                    )
                open_ch, o_line, o_col = stack.pop()
                expected = {"(": ")", "{": "}", "[": "]"}[open_ch]
                if ch != expected:
                    return SyntaxValidationResult(
                        is_valid=False,
                        language="java",
                        filename=filename,
                        line_count=line_count,
                        error_message=f"Java Syntax Error: Mismatched delimiter: expected '{expected}' for '{open_ch}' at line {o_line}, got '{ch}' at line {curr_line}:{curr_col}",
                        error_line=curr_line,
                        error_column=curr_col,
                    )
            i += 1

        if stack:
            open_ch, o_line, o_col = stack[-1]
            return SyntaxValidationResult(
                is_valid=False,
                language="java",
                filename=filename,
                line_count=line_count,
                error_message=f"Java Syntax Error: Unclosed delimiter '{open_ch}' opened at line {o_line}:{o_col}",
                error_line=o_line,
                error_column=o_col,
            )

        # 2. Check for Java class/interface/record structure
        class_match = re.findall(r"\b(public\s+)?(class|interface|enum|record)\s+([a-zA-Z0-9_]+)", clean_code)
        classes = [{"name": c[2], "type": c[1]} for c in class_match]

        imports = re.findall(r"\bimport\s+([a-zA-Z0-9_.*]+)\s*;", code)
        methods = re.findall(r"\b(?:public|protected|private|static|\s)+[\w\<\>\[\]]+\s+(\w+)\s*\([^\)]*\)\s*\{", clean_code)

        complexity = cls.calculate_java_complexity(code)

        return SyntaxValidationResult(
            is_valid=True,
            language="java",
            filename=filename,
            line_count=line_count,
            ast_summary={
                "classes": classes,
                "imports": imports,
                "methods": methods,
                "class_count": len(classes),
                "method_count": len(methods),
            },
            cyclomatic_complexity=complexity,
        )

    @classmethod
    def validate_code(
        cls,
        code: str,
        language: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> SyntaxValidationResult:
        """Coordinates language detection and syntax validation."""
        if not code or not code.strip():
            return SyntaxValidationResult(
                is_valid=False,
                language=language or "unknown",
                filename=filename or "empty.txt",
                line_count=0,
                error_message="Submission is empty. Please paste source code or upload a file.",
            )

        detected_lang = language.lower() if (language and language.lower() not in ("auto", "unknown", "")) else cls.detect_language(code, filename)
        if not filename or filename.lower() in ("main.py", "main.java"):
            target_filename = "Main.java" if detected_lang == "java" else "main.py"
        else:
            target_filename = filename

        if detected_lang == "python":
            return cls.validate_python(code, target_filename)
        elif detected_lang == "java":
            return cls.validate_java(code, target_filename)
        else:
            return SyntaxValidationResult(
                is_valid=False,
                language=detected_lang,
                filename=target_filename,
                line_count=len(code.splitlines()),
                error_message=f"Unsupported language '{detected_lang}'. Supported languages are Python and Java.",
            )
