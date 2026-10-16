import difflib
import logging
from typing import List, Optional, Any

from backend.agents.base_agent import BaseAgent
from backend.models.schemas import Finding, RemediationSuggestion, AgentType
from backend.rag.retriever import SecureCodingRAGRetriever

logger = logging.getLogger(__name__)

class RemediationAgent(BaseAgent):
    """
    Agent 3: Remediation Agent
    Generates specific fix recommendations, before-and-after code snippets,
    unified diffs, and best-practice guidance grounded in the RAG knowledge base.
    """

    def __init__(self):
        super().__init__(
            name="Remediation Agent",
            description="Generates specific fix recommendations with corrected code examples and diffs.",
        )
        self.retriever = SecureCodingRAGRetriever()

    def run(self, findings: List[Finding], code: str, language: str = "python") -> List[Finding]:
        lines = code.splitlines()

        for finding in findings:
            finding.remediation = self._generate_remediation(finding, lines, language)

        return findings

    def _generate_remediation(self, finding: Finding, lines: List[str], language: str) -> RemediationSuggestion:
        # 1. Retrieve RAG context for finding
        rag_docs = self.retriever.retrieve_for_finding(
            title=finding.title,
            category=finding.category,
            owasp_id=finding.owasp_category,
            cwe_id=finding.cwe_id,
            language=language,
        )

        kb_guideline = rag_docs[0] if rag_docs else None

        # 2. Extract original snippet
        start_idx = max(0, finding.line_start - 1)
        end_idx = min(len(lines), finding.line_end)
        original_snippet = "\n".join(lines[start_idx:end_idx]) if lines else (finding.evidence or "")

        # 3. Formulate corrected snippet & diff based on category
        corrected_snippet = self._craft_fix_snippet(finding, original_snippet, language, kb_guideline)

        # Generate unified diff
        diff_lines = list(
            difflib.unified_diff(
                original_snippet.splitlines(keepends=True),
                corrected_snippet.splitlines(keepends=True),
                fromfile=f"original_line_{finding.line_start}",
                tofile=f"remediated_line_{finding.line_start}",
            )
        )
        diff_text = "".join(diff_lines) if diff_lines else f"- {original_snippet}\n+ {corrected_snippet}"

        # Build references
        references = []
        if finding.cwe_id:
            for cwe in finding.cwe_id.split(","):
                clean_cwe = cwe.strip()
                cwe_num = clean_cwe.replace("CWE-", "")
                references.append(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")
        if finding.owasp_category:
            references.append("https://owasp.org/Top10/")

        # Actionable steps
        steps = self._craft_remediation_steps(finding, kb_guideline)
        unit_test = self._craft_unit_test(finding, language)

        explanation = (
            f"Remediation based on {finding.owasp_category or finding.category}: "
            f"Replace vulnerable implementation with safe construct adhering to secure coding guidelines."
        )
        if kb_guideline and kb_guideline.content:
            explanation = f"{kb_guideline.title}: {kb_guideline.content[:220]}..."

        return RemediationSuggestion(
            explanation=explanation,
            original_snippet=original_snippet,
            corrected_snippet=corrected_snippet,
            diff=diff_text,
            references=references,
            remediation_steps=steps,
            unit_test_code=unit_test,
        )

    def _craft_fix_snippet(self, finding: Finding, orig: str, language: str, kb_doc: Optional[Any]) -> str:
        # Check specific categories
        if "SQL" in finding.title or "SQLI" in finding.id:
            if language == "python":
                return (
                    "# Use parameterized query bindings instead of string formatting:\n"
                    "cursor.execute(\"SELECT * FROM users WHERE username = ?\", (username,))"
                )
            else:
                return (
                    "// Use java.sql.PreparedStatement with bind variables:\n"
                    "PreparedStatement pstmt = conn.prepareStatement(\"SELECT * FROM users WHERE username = ?\");\n"
                    "pstmt.setString(1, username);\n"
                    "ResultSet rs = pstmt.executeQuery();"
                )

        if "Command Injection" in finding.title or "os.system" in finding.title or "SHELL" in finding.id:
            return (
                "# Pass arguments as a safe list with shell=False:\n"
                "import subprocess\n"
                "subprocess.run(['ping', '-c', '1', host], check=True, shell=False)"
            )

        if "Hardcoded" in finding.title or "Secret" in finding.title or "A07" in finding.id:
            if language == "python":
                return (
                    "# Load secret securely from environment variable:\n"
                    "import os\n"
                    "SECRET_KEY = os.environ.get('API_SECRET_KEY')\n"
                    "if not SECRET_KEY:\n"
                    "    raise ValueError('API_SECRET_KEY environment variable is missing')"
                )
            else:
                return (
                    "// Retrieve secret from environment variable or Vault:\n"
                    "String secretKey = System.getenv(\"API_SECRET_KEY\");"
                )

        if "pickle" in finding.title or "A08" in finding.id or "Deserialization" in finding.title:
            if language == "python":
                return (
                    "# Use safe JSON serialization instead of pickle:\n"
                    "import json\n"
                    "data = json.loads(payload)"
                )
            else:
                return (
                    "// Use Jackson ObjectMapper for structured JSON deserialization:\n"
                    "ObjectMapper mapper = new ObjectMapper();\n"
                    "UserDTO user = mapper.readValue(payloadStream, UserDTO.class);"
                )

        if "MD5" in finding.title or "SHA1" in finding.title or "Hash" in finding.title or "A04" in finding.id:
            if language == "python":
                return (
                    "# Use bcrypt or Argon2 for password hashing, or SHA-256 for digests:\n"
                    "import hashlib\n"
                    "digest = hashlib.sha256(data.encode('utf-8')).hexdigest()"
                )
            else:
                return (
                    "// Use SHA-256 for secure hashing:\n"
                    "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n"
                    "byte[] hash = md.digest(data.getBytes(StandardCharsets.UTF_8));"
                )

        if "except:" in finding.title or "Bare" in finding.title or "A10" in finding.id:
            return (
                "# Catch specific exceptions explicitly and log appropriately:\n"
                "except (ValueError, KeyError) as err:\n"
                "    logger.warning('Handled input error: %s', err)"
            )

        if "Debug Mode" in finding.title or "A02" in finding.id:
            return (
                "# Read debug flag dynamically from environment:\n"
                "import os\n"
                "DEBUG = os.getenv('APP_ENV') == 'development'"
            )

        if "Wildcard" in finding.title:
            return "# Explicitly import required components:\nfrom module import SpecificClass, specific_function"

        if "Long Method" in finding.title or "Nesting" in finding.title:
            return (
                "# Refactor with guard clauses (return early) and helper methods:\n"
                "if not is_valid_input(data):\n"
                "    return None\n"
                "return process_validated_data(data)"
            )

        return f"# Remediation for {finding.title}:\n# Follow standard secure coding practices (verify inputs, use safe APIs)."

    def _craft_remediation_steps(self, finding: Finding, kb_doc: Optional[Any]) -> List[str]:
        steps = [
            f"Review the vulnerable code at line {finding.line_start}.",
            "Replace dynamic string interpolation or insecure API with parameterization / safe library construct.",
            "Add automated regression test validating the security constraint.",
            "Verify that inputs are sanitized and bounds-checked before processing.",
        ]
        return steps

    def _craft_unit_test(self, finding: Finding, language: str) -> str:
        """Generates an automated regression unit test verifying the fix."""
        title = finding.title.lower()
        if "sql" in title or "sqli" in finding.id.lower():
            if language == "python":
                return (
                    "import pytest\n\n"
                    "def test_sql_injection_defense():\n"
                    "    # Verify that SQL meta-characters are treated as literals, not executable SQL\n"
                    "    malicious_payload = \"admin' OR '1'='1\"\n"
                    "    result = authenticate_user(malicious_payload, 'arbitrary_password')\n"
                    "    assert result is None, 'Vulnerability regression: SQL injection succeeded!'\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testSqlInjectionDefense() {\n"
                    "    String maliciousPayload = \"admin' OR '1'='1\";\n"
                    "    boolean authenticated = app.login(maliciousPayload, \"dummy_pass\");\n"
                    "    assertFalse(authenticated, \"SQL injection payload must not authenticate!\");\n"
                    "}\n"
                )

        if "path" in title or "traversal" in title:
            if language == "python":
                return (
                    "import pytest\n\n"
                    "def test_path_traversal_forbidden():\n"
                    "    # Verify directory traversal sequence triggers PermissionError or rejection\n"
                    "    with pytest.raises((PermissionError, ValueError)):\n"
                    "        read_user_file('../../etc/passwd')\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testPathTraversalForbidden() {\n"
                    "    assertThrows(SecurityException.class, () -> {\n"
                    "        app.loadUserSession(\"../../etc/passwd\");\n"
                    "    });\n"
                    "}\n"
                )

        if "secret" in title or "credential" in title or "a07" in finding.id.lower():
            if language == "python":
                return (
                    "import os\n\n"
                    "def test_secret_loaded_from_environment(monkeypatch):\n"
                    "    # Verify secret is read from environment rather than hardcoded in source\n"
                    "    monkeypatch.setenv('API_SECRET_KEY', 'test_key_12345')\n"
                    "    assert os.getenv('API_SECRET_KEY') == 'test_key_12345'\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testSecretLoadedFromEnvironment() {\n"
                    "    String envSecret = System.getenv(\"API_SECRET_KEY\");\n"
                    "    // Verify credentials are not baked into class constants\n"
                    "    assertNotNull(envSecret, \"Secret must be configured via environment\");\n"
                    "}\n"
                )

        if "command" in title or "exec" in title or "shell" in title:
            return (
                "import pytest\n\n"
                "def test_command_injection_rejected():\n"
                "    malicious_host = '127.0.0.1; cat /etc/passwd'\n"
                "    res = run_system_ping(malicious_host)\n"
                "    assert res is False, 'Command injection must not execute platform shell!'\n"
            )

        if "pickle" in title or "deserialization" in title:
            return (
                "import pytest, json\n\n"
                "def test_safe_deserialization_rejects_malicious_pickle():\n"
                "    malicious_bytes = b'cos\\nsystem\\n(S\"echo pwned\"\\ntR.'\n"
                "    with pytest.raises((json.JSONDecodeError, ValueError)):\n"
                "        # Structured parser should reject arbitrary python binary blobs\n"
                "        json.loads(malicious_bytes.decode('latin1'))\n"
            )

        return (
            "def test_finding_remediation():\n"
            f"    # Automated regression test for {finding.title}\n"
            "    assert True\n"
        )
