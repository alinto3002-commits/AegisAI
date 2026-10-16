import re
from typing import List, Dict, Any, Optional

from backend.agents.base_agent import BaseAgent
from backend.models.schemas import Finding, FindingSeverity, AgentType

class SecurityVulnerabilityAgent(BaseAgent):
    """
    Agent 2: Security Vulnerability Agent
    Scans for OWASP Top 10 (2025) standard vulnerabilities and CWE patterns:
    - A01: Broken Access Control (Path traversal, missing authorization checks)
    - A02: Security Misconfiguration (Wildcard CORS, debug mode enabled)
    - A03: Software Supply Chain Failures (Risky imports, outdated/unsafe packages)
    - A04: Cryptographic Failures (Broken MD5/SHA1 hashing, weak ciphers)
    - A05: Injection (SQL Injection, Command Injection, XSS)
    - A06: Insecure Design (Missing rate limits on sensitive endpoints)
    - A07: Authentication Failures (Hardcoded secrets, API tokens, passwords)
    - A08: Software or Data Integrity Failures (Insecure deserialization: pickle, yaml, ObjectInputStream)
    - A09: Security Logging and Alerting Failures (Logging credentials/PII)
    - A10: Mishandling of Exceptional Conditions (Bare except: pass, empty catch blocks)
    """

    def __init__(self):
        super().__init__(
            name="Security Vulnerability Agent",
            description="Scans for OWASP Top 10 (2025) vulnerabilities and CWE compliance.",
        )

    def run(self, code: str, language: str = "python", filename: str = "source") -> List[Finding]:
        findings: List[Finding] = []
        lines = code.splitlines()

        # Run detection suites
        findings.extend(self._scan_owasp_a01_access_control(code, lines, language))
        findings.extend(self._scan_owasp_a02_misconfiguration(code, lines, language))
        findings.extend(self._scan_owasp_a03_supply_chain(code, lines, language))
        findings.extend(self._scan_owasp_a04_crypto(code, lines, language))
        findings.extend(self._scan_owasp_a05_injection(code, lines, language))
        findings.extend(self._scan_owasp_a06_insecure_design(code, lines, language))
        findings.extend(self._scan_owasp_a07_auth_secrets(code, lines, language))
        findings.extend(self._scan_owasp_a08_deserialization(code, lines, language))
        findings.extend(self._scan_owasp_a09_logging(code, lines, language))
        findings.extend(self._scan_owasp_a10_exception_handling(code, lines, language))

        return findings

    # --- A01: Broken Access Control ---
    def _scan_owasp_a01_access_control(self, code: str, lines: List[str], language: str) -> List[Finding]:
        findings = []
        # Path traversal patterns: open(f"...", os.path.join with request inputs without resolve/normalize)
        for idx, line in enumerate(lines, start=1):
            if re.search(r"open\s*\(\s*(f[\"']|\"|')[^\"']*(filename|path|file|user_input|param)[^\"']*[\"']", line, re.I):
                findings.append(
                    Finding(
                        id=f"SEC-A01-PATH-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Broken Access Control (A01:2025)",
                        title="Potential Path Traversal / Arbitrary File Access",
                        description="File open operation concatenates user-controlled variable without path normalization or canonicalization checks (CWE-22).",
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-22",
                        owasp_category="A01:2025 - Broken Access Control",
                        evidence=line.strip(),
                    )
                )
            if language == "java" and re.search(r"new\s+File\s*\([^)]*(request\.getParameter|filename|path)", line):
                findings.append(
                    Finding(
                        id=f"SEC-A01-JAVA-PATH-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Broken Access Control (A01:2025)",
                        title="Unsanitized File Path Instantiation in Java",
                        description="Creating a java.io.File directly from request parameters exposes the server to Directory Traversal attacks (CWE-22).",
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-22",
                        owasp_category="A01:2025 - Broken Access Control",
                        evidence=line.strip(),
                    )
                )
        return findings

    # --- A02: Security Misconfiguration ---
    def _scan_owasp_a02_misconfiguration(self, code: str, lines: List[str], language: str) -> List[Finding]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            # Debug mode enabled
            if re.search(r"\b(debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)\b", line):
                findings.append(
                    Finding(
                        id=f"SEC-A02-DEBUG-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Security Misconfiguration (A02:2025)",
                        title="Debug Mode Enabled in Application Configuration",
                        description="Debug mode exposes interactive debuggers, memory states, and detailed stack traces to external visitors (CWE-16).",
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-16",
                        owasp_category="A02:2025 - Security Misconfiguration",
                        evidence=line.strip(),
                    )
                )
            # Wildcard CORS
            if re.search(r"(allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]|origins\s*=\s*['\"]\*['\"])", line):
                findings.append(
                    Finding(
                        id=f"SEC-A02-CORS-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Security Misconfiguration (A02:2025)",
                        title="Overly Permissive Wildcard CORS Configuration (`*`)",
                        description="Access-Control-Allow-Origin: '*' allows any external domain to make cross-origin requests to this endpoint (CWE-942).",
                        severity=FindingSeverity.MEDIUM,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-942",
                        owasp_category="A02:2025 - Security Misconfiguration",
                        evidence=line.strip(),
                    )
                )
        return findings

    # --- A03: Software Supply Chain Failures ---
    def _scan_owasp_a03_supply_chain(self, code: str, lines: List[str], language: str) -> List[Finding]:
        findings = []
        risky_python_packages = ["telnetlib", "cgi", "pipes", "smtpd", "formatter"]
        for idx, line in enumerate(lines, start=1):
            for pkg in risky_python_packages:
                if re.search(rf"\b(import\s+{pkg}|from\s+{pkg}\s+import)\b", line):
                    findings.append(
                        Finding(
                            id=f"SEC-A03-DEPRECATED-{idx}",
                            agent_type=AgentType.SECURITY_VULNERABILITY,
                            category="Software Supply Chain Failures (A03:2025)",
                            title=f"Use of Deprecated/Insecure Module '{pkg}'",
                            description=f"Module '{pkg}' is deprecated, lacks modern security maintenance, or provides unencrypted communication (CWE-1104).",
                            severity=FindingSeverity.MEDIUM,
                            line_start=idx,
                            line_end=idx,
                            cwe_id="CWE-1104",
                            owasp_category="A03:2025 - Software Supply Chain Failures",
                            evidence=line.strip(),
                        )
                    )
        return findings

    # --- A04: Cryptographic Failures ---
    def _scan_owasp_a04_crypto(self, code: str, lines: List[str], language: str) -> List[Finding]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            # Broken hash algorithms: md5, sha1 for passwords or hashing
            if re.search(r"\bhashlib\.(md5|sha1)\s*\(", line, re.I):
                findings.append(
                    Finding(
                        id=f"SEC-A04-WEAKHASH-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Cryptographic Failures (A04:2025)",
                        title="Use of Cryptographically Broken Hash Algorithm (MD5/SHA1)",
                        description="MD5 and SHA1 are cryptographically broken due to collision vulnerabilities. For password storage, use Argon2id or bcrypt; for signatures, use SHA-256/SHA-512 (CWE-328).",
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-328",
                        owasp_category="A04:2025 - Cryptographic Failures",
                        evidence=line.strip(),
                    )
                )
            if language == "java" and re.search(r'MessageDigest\.getInstance\s*\(\s*["\'](MD5|SHA-1)["\']\s*\)', line, re.I):
                findings.append(
                    Finding(
                        id=f"SEC-A04-JAVA-WEAKHASH-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Cryptographic Failures (A04:2025)",
                        title="Weak MessageDigest Instance in Java (MD5/SHA-1)",
                        description="MD5 and SHA-1 algorithms suffer from known collision weaknesses and must not be used for security-critical hashing (CWE-328).",
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-328",
                        owasp_category="A04:2025 - Cryptographic Failures",
                        evidence=line.strip(),
                    )
                )
        return findings

    # --- A05: Injection (SQLi, Command Injection, XSS) ---
    def _scan_owasp_a05_injection(self, code: str, lines: List[str], language: str) -> List[Finding]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            # 1. SQL Injection via raw f-string or % or string concatenation
            if re.search(r"(execute|cursor\.execute|raw_query|rawQuery|\bquery|\bsql|\bstmt)\s*(\(|=)\s*f[\"'].*?(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*?\{.*?\}", line, re.I):
                findings.append(
                    Finding(
                        id=f"SEC-A05-SQLI-FSTRING-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Injection (A05:2025)",
                        title="SQL Injection via Formatted String (f-string)",
                        description="Dynamic SQL query built using f-string interpolation allows attackers to manipulate query structure and execute arbitrary SQL commands (CWE-89).",
                        severity=FindingSeverity.CRITICAL,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-89",
                        owasp_category="A05:2025 - Injection",
                        evidence=line.strip(),
                    )
                )
            elif re.search(r"(execute|cursor\.execute|\bquery|\bsql)\s*(\(|=)\s*[\"'].*?(SELECT|INSERT|UPDATE|DELETE).*?['\"]\s*%", line, re.I):
                findings.append(
                    Finding(
                        id=f"SEC-A05-SQLI-FORMAT-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Injection (A05:2025)",
                        title="SQL Injection via String Formatting (%)",
                        description="SQL query string is constructed using percent (%) formatting instead of query parameter placeholders (CWE-89).",
                        severity=FindingSeverity.CRITICAL,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-89",
                        owasp_category="A05:2025 - Injection",
                        evidence=line.strip(),
                    )
                )
            elif language == "java" and re.search(r'(executeQuery|executeUpdate)\s*\(\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?["\']\s*\+', line, re.I):
                findings.append(
                    Finding(
                        id=f"SEC-A05-JAVA-SQLI-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Injection (A05:2025)",
                        title="SQL Injection via String Concatenation in Java JDBC",
                        description="Building SQL statements via string concatenation (+) with Statement.executeQuery allows SQL injection. Use java.sql.PreparedStatement with bind variables instead (CWE-89).",
                        severity=FindingSeverity.CRITICAL,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-89",
                        owasp_category="A05:2025 - Injection",
                        evidence=line.strip(),
                    )
                )

            # 2. OS Command Injection
            if re.search(r"\b(os\.system|os\.popen)\s*\(", line):
                findings.append(
                    Finding(
                        id=f"SEC-A05-CMDINJ-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Injection (A05:2025)",
                        title="OS Command Injection via os.system / os.popen",
                        description="Invoking system shells via os.system allows command execution and shell metacharacter injection. Use subprocess.run with argument lists and shell=False (CWE-78).",
                        severity=FindingSeverity.CRITICAL,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-78",
                        owasp_category="A05:2025 - Injection",
                        evidence=line.strip(),
                    )
                )
            if re.search(r"subprocess\.(call|Popen|run|check_output)\s*\([^)]*shell\s*=\s*True", line):
                findings.append(
                    Finding(
                        id=f"SEC-A05-SHELLTRUE-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Injection (A05:2025)",
                        title="Insecure Subprocess Execution with `shell=True`",
                        description="Using shell=True with subprocess invokes the platform shell (/bin/sh or cmd.exe) allowing arbitrary command injection (CWE-78).",
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-78",
                        owasp_category="A05:2025 - Injection",
                        evidence=line.strip(),
                    )
                )
            if language == "java" and re.search(r"Runtime\.getRuntime\(\)\.exec\s*\(", line):
                findings.append(
                    Finding(
                        id=f"SEC-A05-JAVA-EXEC-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Injection (A05:2025)",
                        title="Process Execution via Runtime.getRuntime().exec",
                        description="Direct invocation of Runtime.exec without argument arrays or input validation can lead to OS command injection (CWE-78).",
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-78",
                        owasp_category="A05:2025 - Injection",
                        evidence=line.strip(),
                    )
                )
        return findings

    # --- A06: Insecure Design ---
    def _scan_owasp_a06_insecure_design(self, code: str, lines: List[str], language: str) -> List[Finding]:
        findings = []
        # Check login or auth endpoint without rate limiting decorator
        has_login = False
        login_line = 1
        has_limiter = False

        for idx, line in enumerate(lines, start=1):
            if re.search(r"@(app|router)\.(post|get)\s*\([^)]*(login|authenticate|signin|reset-password)", line, re.I):
                has_login = True
                login_line = idx
            if "@limiter.limit" in line:
                has_limiter = True

        if has_login and not has_limiter:
            findings.append(
                Finding(
                    id=f"SEC-A06-RATELIMIT-{login_line}",
                    agent_type=AgentType.SECURITY_VULNERABILITY,
                    category="Insecure Design (A06:2025)",
                    title="Missing Rate Limiting on Authentication Endpoint",
                    description="Authentication and password endpoints without rate limiting are susceptible to credential stuffing and brute-force attacks (CWE-1059).",
                    severity=FindingSeverity.MEDIUM,
                    line_start=login_line,
                    line_end=login_line,
                    cwe_id="CWE-1059",
                    owasp_category="A06:2025 - Insecure Design",
                    evidence=lines[login_line - 1].strip() if login_line <= len(lines) else "",
                )
            )
        return findings

    # --- A07: Authentication Failures & Hardcoded Secrets ---
    def _scan_owasp_a07_auth_secrets(self, code: str, lines: List[str], language: str) -> List[Finding]:
        findings = []
        # Secret regex patterns
        secret_patterns = [
            (r"(api[_-]?key|apikey)\s*=\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", "Hardcoded API Key"),
            (r"(secret[_-]?key|jwt[_-]?secret)\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded Secret / JWT Key"),
            (r"(password|passwd|db_pass)\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded Password / Credential"),
            (r"AKIA[0-9A-Z]{16}", "Hardcoded AWS Access Key ID"),
            (r"ghp_[a-zA-Z0-9]{36}", "Hardcoded GitHub Personal Access Token"),
        ]

        for idx, line in enumerate(lines, start=1):
            if line.strip().startswith("#") or line.strip().startswith("//"):
                continue
            for pattern, title in secret_patterns:
                if re.search(pattern, line, re.I):
                    findings.append(
                        Finding(
                            id=f"SEC-A07-SECRET-{idx}",
                            agent_type=AgentType.SECURITY_VULNERABILITY,
                            category="Authentication Failures (A07:2025)",
                            title=f"Hardcoded Credential Detected: {title}",
                            description="Sensitive cryptographic secrets or credentials embedded directly into source code risk leakage in version control systems (CWE-798).",
                            severity=FindingSeverity.CRITICAL,
                            line_start=idx,
                            line_end=idx,
                            cwe_id="CWE-798",
                            owasp_category="A07:2025 - Authentication Failures",
                            evidence=re.sub(r"(=['\"])[^'\"]+(['\"])", r"\1********\2", line.strip()),
                        )
                    )
                    break
        return findings

    # --- A08: Software or Data Integrity Failures ---
    def _scan_owasp_a08_deserialization(self, code: str, lines: List[str], language: str) -> List[Finding]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            # Python pickle
            if re.search(r"\bpickle\.(loads|load)\s*\(", line):
                findings.append(
                    Finding(
                        id=f"SEC-A08-PICKLE-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Software or Data Integrity Failures (A08:2025)",
                        title="Unsafe Deserialization via Python `pickle`",
                        description="Deserializing untrusted data with pickle allows attackers to execute arbitrary shellcode and achieve Remote Code Execution (RCE) (CWE-502).",
                        severity=FindingSeverity.CRITICAL,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-502",
                        owasp_category="A08:2025 - Software or Data Integrity Failures",
                        evidence=line.strip(),
                    )
                )
            # PyYAML unsafe load
            if re.search(r"\byaml\.load\s*\([^)]*(?!Loader=yaml\.SafeLoader)[^)]*\)", line):
                findings.append(
                    Finding(
                        id=f"SEC-A08-YAML-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Software or Data Integrity Failures (A08:2025)",
                        title="Unsafe YAML Deserialization (`yaml.load`)",
                        description="yaml.load() without SafeLoader can instantiate arbitrary Python objects and execute arbitrary code. Use yaml.safe_load() (CWE-502).",
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-502",
                        owasp_category="A08:2025 - Software or Data Integrity Failures",
                        evidence=line.strip(),
                    )
                )
            # Java ObjectInputStream
            if language == "java" and re.search(r"new\s+ObjectInputStream\s*\(", line):
                findings.append(
                    Finding(
                        id=f"SEC-A08-JAVA-OIS-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Software or Data Integrity Failures (A08:2025)",
                        title="Unrestricted Java ObjectInputStream Deserialization",
                        description="Java native serialization via ObjectInputStream is vulnerable to gadget-chain exploits leading to RCE. Use ObjectInputFilter or JSON (CWE-502).",
                        severity=FindingSeverity.CRITICAL,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-502",
                        owasp_category="A08:2025 - Software or Data Integrity Failures",
                        evidence=line.strip(),
                    )
                )
        return findings

    # --- A09: Security Logging and Alerting Failures ---
    def _scan_owasp_a09_logging(self, code: str, lines: List[str], language: str) -> List[Finding]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if re.search(r"(logger|logging|print)\.(info|debug|warn|error)?\s*\([^)]*(password|secret|token|api_key)", line, re.I):
                findings.append(
                    Finding(
                        id=f"SEC-A09-LOGLEAK-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Security Logging and Alerting Failures (A09:2025)",
                        title="Sensitive Data / Credential Leakage in Application Logs",
                        description="Logging authentication credentials or API tokens in application log files exposes confidential data to log monitoring systems (CWE-532).",
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-532",
                        owasp_category="A09:2025 - Security Logging and Alerting Failures",
                        evidence=line.strip(),
                    )
                )
        return findings

    # --- A10: Mishandling of Exceptional Conditions ---
    def _scan_owasp_a10_exception_handling(self, code: str, lines: List[str], language: str) -> List[Finding]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            # Bare except in Python
            if re.search(r"^\s*except\s*:\s*(pass)?\s*$", line):
                findings.append(
                    Finding(
                        id=f"SEC-A10-BAREEXCEPT-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Mishandling of Exceptional Conditions (A10:2025)",
                        title="Bare `except:` Swallowing Exceptions (Fail-Open Risk)",
                        description="A bare 'except:' catches all exceptions (including SystemExit, KeyboardInterrupt) and silently swallows errors, risking a fail-open security state (CWE-755).",
                        severity=FindingSeverity.MEDIUM,
                        line_start=idx,
                        line_end=min(len(lines), idx + 1),
                        cwe_id="CWE-755",
                        owasp_category="A10:2025 - Mishandling of Exceptional Conditions",
                        evidence=line.strip(),
                    )
                )
            # Empty catch in Java
            if language == "java" and re.search(r"catch\s*\([^)]+\)\s*\{\s*\}", line):
                findings.append(
                    Finding(
                        id=f"SEC-A10-JAVA-EMPTYCATCH-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Mishandling of Exceptional Conditions (A10:2025)",
                        title="Empty `catch` Block Silently Swallowing Exceptions",
                        description="Empty catch block in Java suppresses errors and causes silent security failures (CWE-390).",
                        severity=FindingSeverity.MEDIUM,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-390",
                        owasp_category="A10:2025 - Mishandling of Exceptional Conditions",
                        evidence=line.strip(),
                    )
                )
        return findings
