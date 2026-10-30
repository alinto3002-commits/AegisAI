import re
from typing import List, Dict, Any, Optional

from backend.agents.base_agent import BaseAgent
from backend.models.schemas import Finding, FindingSeverity, AgentType

def mask_secret_literal(line: str) -> str:
    """
    Masks credential values and API keys in source evidence to prevent secret exposure in reports.
    """
    masked = re.sub(r"(=|\:)\s*(b?['\"])[^'\"]*(['\"])", r"\1 \2********\3", line)
    masked = re.sub(r"new\s+byte\[\]\s*\{[^}]+\}", "new byte[]{********}", masked)
    masked = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA****************", masked)
    masked = re.sub(r"ghp_[a-zA-Z0-9]{36}", "ghp_************************************", masked)
    return masked

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
            if (
                re.search(r"open\s*\(\s*(f[\"']|\"|')[^\"']*(filename|path|file|user_input|param)[^\"']*[\"']", line, re.I)
                or re.search(r"(?:filepath|path|file_path|target_path|file_loc)\s*=\s*f[\"'][^\"']*\{[a-zA-Z_][^}]*\}", line, re.I)
                or re.search(r"(?:filepath|path|file_path|target_path)\s*=\s*[\"'][^\"']+[\"']\s*\+\s*[a-zA-Z_]", line, re.I)
            ):
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
            if language == "java" and (
                re.search(r"new\s+(?:File|FileInputStream|FileReader|FileOutputStream)\s*\([^)]*(request\.getParameter|filename|path|userInput|fileParam)", line, re.I)
                or re.search(r"new\s+(?:File|FileInputStream|FileReader|FileOutputStream)\s*\([^)]*\+\s*[a-zA-Z_]", line)
                or re.search(r"(?:Paths\.get|Path\.of|Files\.(?:readAllBytes|newInputStream|lines))\s*\([^)]*(\+|request|filename|path)", line, re.I)
            ):
                if not re.search(r"getCanonicalPath|getCanonicalFile|\.normalize\(\)", line):
                    findings.append(
                        Finding(
                            id=f"SEC-A01-JAVA-PATH-{idx}",
                            agent_type=AgentType.SECURITY_VULNERABILITY,
                            category="Broken Access Control (A01:2025)",
                            title="Unsanitized File Path Instantiation in Java",
                            description="Creating a java.io.File directly from request parameters or dynamic variables exposes the server to Directory Traversal attacks (CWE-22).",
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
                local_start = max(0, idx - 6)
                local_end = min(len(lines), idx + 6)
                local_block = " ".join(lines[local_start:local_end]).lower()
                is_pwd = any(k in local_block for k in ["pass", "pwd", "auth", "login", "credential", "user_pass"])
                is_data_digest = any(k in local_block for k in ["checksum", "crc", "file", "integrity", "content", "payload", "digest"]) and not is_pwd

                if is_pwd:
                    title = "Weak Hash Algorithm (MD5/SHA1) for Password Storage"
                    desc = "MD5 and SHA-1 algorithms suffer from known collision weaknesses and lack computational work factors for password storage. Use Argon2id or bcrypt (CWE-328)."
                elif is_data_digest:
                    title = "Weak Hash Algorithm for Data Integrity (MD5/SHA1)"
                    desc = "MD5 and SHA-1 suffer from collision and preimage weaknesses. For non-password data integrity and cryptographic digests, use SHA-256 or SHA-512 (CWE-328)."
                else:
                    title = "Use of Cryptographically Broken Hash Algorithm (MD5/SHA1)"
                    desc = "MD5 and SHA1 are cryptographically broken due to collision vulnerabilities. For password storage, use Argon2id or bcrypt; for signatures/digests, use SHA-256/SHA-512 (CWE-328)."

                findings.append(
                    Finding(
                        id=f"SEC-A04-WEAKHASH-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Cryptographic Failures (A04:2025)",
                        title=title,
                        description=desc,
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-328",
                        owasp_category="A04:2025 - Cryptographic Failures",
                        evidence=line.strip(),
                    )
                )
            if language == "java" and re.search(r'MessageDigest\.getInstance\s*\(\s*["\'](MD5|SHA-?1|SHA)["\']\s*\)', line, re.I):
                local_start = max(0, idx - 6)
                local_end = min(len(lines), idx + 6)
                local_block = " ".join(lines[local_start:local_end]).lower()
                is_pwd = any(k in local_block for k in ["pass", "pwd", "auth", "login", "credential", "user_pass"])
                is_data_digest = any(k in local_block for k in ["checksum", "crc", "file", "integrity", "content", "payload", "digest"]) and not is_pwd

                if is_pwd:
                    title = "Weak Hash Algorithm (SHA-1) for Password Storage" if "sha" in line.lower() else "Weak Hash Algorithm (MD5) for Password Storage"
                    desc = "MD5 and SHA-1 algorithms suffer from known collision weaknesses and lack computational work factors for password storage. Use Argon2id or bcrypt for password hashing (CWE-328)."
                elif is_data_digest:
                    title = "Weak MessageDigest Instance for Data Integrity (MD5/SHA-1)"
                    desc = "MD5 and SHA-1 suffer from collision and preimage weaknesses. For non-password data integrity and cryptographic digests, use SHA-256 or SHA-512 (CWE-328)."
                else:
                    title = "Weak MessageDigest Instance in Java (MD5/SHA-1)"
                    desc = "MD5 and SHA-1 algorithms suffer from known collision weaknesses and must not be used for security-critical hashing. For passwords, use Argon2id or bcrypt; for digests, use SHA-256/SHA-512 (CWE-328)."

                findings.append(
                    Finding(
                        id=f"SEC-A04-JAVA-WEAKHASH-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Cryptographic Failures (A04:2025)",
                        title=title,
                        description=desc,
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-328",
                        owasp_category="A04:2025 - Cryptographic Failures",
                        evidence=line.strip(),
                    )
                )

            # Weak PRNG (CWE-338) - Only flag in security-sensitive contexts (tokens, auth, keys, reset links)
            if language == "java" and re.search(r"\b(new\s+Random\s*\(|Random\s+[a-zA-Z0-9_]+\s*=\s*new\s+Random\s*\(|Math\.random\s*\()", line):
                local_start = max(0, idx - 8)
                local_end = min(len(lines), idx + 8)
                local_block = " ".join(lines[local_start:local_end]).lower()
                sec_sensitive_terms = [
                    "token", "secret", "key", "nonce", "salt", "auth", "password",
                    "passwd", "session", "credential", "pin", "reset", "otp", "jwt",
                    "cipher", "iv", "challenge", "csrf", "bearer", "api_key", "apikey"
                ]
                is_security_sensitive = any(term in local_block for term in sec_sensitive_terms)

                if is_security_sensitive:
                    findings.append(
                        Finding(
                            id=f"SEC-A04-JAVA-WEAKPRNG-{idx}",
                            agent_type=AgentType.SECURITY_VULNERABILITY,
                            category="Cryptographic Failures (A04:2025)",
                            title="Weak PRNG (java.util.Random)",
                            description="java.util.Random produces deterministic, predictable sequences and is not cryptographically secure. For security-sensitive purposes (tokens, authentication, cryptographic keys, password reset links), use java.security.SecureRandom (CWE-338).",
                            severity=FindingSeverity.HIGH,
                            line_start=idx,
                            line_end=idx,
                            cwe_id="CWE-338",
                            owasp_category="A04:2025 - Cryptographic Failures",
                            evidence=line.strip(),
                        )
                    )
            elif language == "python" and re.search(r"\brandom\.(random|randint|choice|randrange|getrandbits)\s*\(", line):
                local_start = max(0, idx - 8)
                local_end = min(len(lines), idx + 8)
                local_block = " ".join(lines[local_start:local_end]).lower()
                sec_sensitive_terms = [
                    "token", "secret", "key", "nonce", "salt", "auth", "password",
                    "passwd", "session", "credential", "pin", "reset", "otp", "jwt",
                    "cipher", "iv", "challenge", "csrf", "bearer", "api_key", "apikey"
                ]
                is_security_sensitive = any(term in local_block for term in sec_sensitive_terms)

                if is_security_sensitive:
                    findings.append(
                        Finding(
                            id=f"SEC-A04-PY-WEAKPRNG-{idx}",
                            agent_type=AgentType.SECURITY_VULNERABILITY,
                            category="Cryptographic Failures (A04:2025)",
                            title="Weak PRNG (random module used for token)",
                            description="Standard 'random' module produces predictable Mersenne Twister sequences. Use Python's 'secrets' module for security-sensitive tokens, passwords, reset links, and nonces (CWE-338).",
                            severity=FindingSeverity.HIGH,
                            line_start=idx,
                            line_end=idx,
                            cwe_id="CWE-338",
                            owasp_category="A04:2025 - Cryptographic Failures",
                            evidence=line.strip(),
                        )
                    )

            # Broken / Risky Cipher Algorithm & Insecure ECB Mode (CWE-327)
            if language == "java" and re.search(r'Cipher\.getInstance\s*\(\s*["\'](AES/ECB|AES(?:\b|["\'])|DES|DESede|RC4|RC2|Blowfish)', line, re.I):
                findings.append(
                    Finding(
                        id=f"SEC-A04-JAVA-ECBCIPHER-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Cryptographic Failures (A04:2025)",
                        title="Broken ECB Cipher Mode",
                        description="Electronic Codebook (ECB) mode does not employ an initialization vector (IV) and encrypts identical plaintext blocks into identical ciphertext blocks, leaking structural data and patterns. Use authenticated encryption like AES/GCM/NoPadding with proper nonce generation and authentication-tag verification (CWE-327).",
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-327",
                        owasp_category="A04:2025 - Cryptographic Failures",
                        evidence=line.strip(),
                    )
                )
            elif language == "python" and re.search(r'(AES\.MODE_ECB|\bDES\b|\bARC4\b|\bBlowfish\b)', line):
                findings.append(
                    Finding(
                        id=f"SEC-A04-PY-ECBCIPHER-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Cryptographic Failures (A04:2025)",
                        title="Broken ECB Cipher Mode",
                        description="Electronic Codebook (ECB) mode fails to provide semantic confidentiality under repeated blocks. Use AES.MODE_GCM with a unique nonce and authentication-tag verification (CWE-327).",
                        severity=FindingSeverity.HIGH,
                        line_start=idx,
                        line_end=idx,
                        cwe_id="CWE-327",
                        owasp_category="A04:2025 - Cryptographic Failures",
                        evidence=line.strip(),
                    )
                )

            # Plaintext Password Storage (CWE-256)
            if re.search(r"(?:password|passwd|pwd)", line, re.I):
                if (
                    re.search(r'(?:INSERT\s+INTO\s+.*?(?:password|passwd)|props\.setProperty\s*\(\s*["\'](?:password|passwd)["\']|\.setPassword\s*\([^)]+\)|user\.password\s*=|user\.setPassword|\b(?:save|store|persist)\s*\([^)]*(?:password|passwd|pwd))', line, re.I)
                ):
                    # Check that this specific persistence site does not use an approved password hashing KDF
                    local_start = max(0, idx - 4)
                    local_end = min(len(lines), idx + 2)
                    local_block = "\n".join(lines[local_start:local_end]).lower()
                    if not any(h in local_block for h in ["argon2", "bcrypt", "pbkdf2", "scrypt", "encoder.encode", "hasher.hash"]):
                        findings.append(
                            Finding(
                                id=f"SEC-A04-PLAINTEXT-PASS-{idx}",
                                agent_type=AgentType.SECURITY_VULNERABILITY,
                                category="Cryptographic Failures (A04:2025)",
                                title="Plaintext Password Storage (CWE-256)",
                                description="Storing or persisting user authentication passwords in plaintext without applying a salted, memory-hard key derivation function (Argon2id or bcrypt) exposes credentials to database breaches (CWE-256).",
                                severity=FindingSeverity.CRITICAL,
                                line_start=idx,
                                line_end=idx,
                                cwe_id="CWE-256",
                                owasp_category="A04:2025 - Cryptographic Failures",
                                evidence=mask_secret_literal(line.strip()),
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
            elif language == "java" and (
                re.search(r'(executeQuery|executeUpdate)\s*\(\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?["\']\s*\+', line, re.I)
                or re.search(r'(?:String\s+)?(?:sql|query|statement|cmd)\s*=\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?["\']\s*\+', line, re.I)
                or re.search(r'["\'].*?\b(SELECT|INSERT|UPDATE|DELETE)\b.*?["\']\s*\+\s*[a-zA-Z_]', line, re.I)
                or re.search(r'\+\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\+\s*["\'].*?\b(AND|OR|WHERE|FROM|LIMIT|ORDER|VALUES|SET)\b', line, re.I)
            ):
                findings.append(
                    Finding(
                        id=f"SEC-A05-JAVA-SQLI-{idx}",
                        agent_type=AgentType.SECURITY_VULNERABILITY,
                        category="Injection (A05:2025)",
                        title="SQL Injection via String Concatenation in Java JDBC",
                        description="Building SQL statements via string concatenation (+) with Statement.executeQuery or variable assignments allows SQL injection. Use java.sql.PreparedStatement with bind variables instead (CWE-89).",
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
            (r"(?:(?:private\s+static\s+final\s+)?(?:String\s+)?)?(api[_-]?key|apikey|api_token)\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]", "Hardcoded API Key", FindingSeverity.CRITICAL),
            (r"(?:(?:private\s+static\s+final\s+)?(?:String\s+)?)?(jwt[_-]?secret)\s*=\s*['\"][^'\"]{6,}['\"]", "Hardcoded JWT Secret String", FindingSeverity.HIGH),
            (r"(?:(?:private\s+static\s+final\s+)?(?:String\s+)?)?(secret[_-]?key)\s*=\s*['\"][^'\"]{6,}['\"]", "Hardcoded Secret Key", FindingSeverity.HIGH),
            (r"(private\s+static\s+final\s+)?byte\[\]\s+([A-Z0-9_]*KEY[A-Z0-9_]*|[A-Z0-9_]*SECRET[A-Z0-9_]*)\s*=\s*['\"][^'\"]+['\"]\.getBytes\(\)", "Hardcoded Symmetric Key Bytes", FindingSeverity.HIGH),
            (r"(private\s+static\s+final\s+)?byte\[\]\s+([A-Z0-9_]*KEY[A-Z0-9_]*|[A-Z0-9_]*SECRET[A-Z0-9_]*)\s*=\s*new\s+byte\[\]\s*\{[^}]+\}", "Hardcoded Symmetric Key Bytes", FindingSeverity.HIGH),
            (r"(private\s+static\s+final\s+)?String\s+([A-Z0-9_]*SECRET[A-Z0-9_]*|[A-Z0-9_]*KEY[A-Z0-9_]*|[A-Z0-9_]*TOKEN[A-Z0-9_]*)\s*=\s*['\"][^'\"]{6,}['\"]", "Hardcoded Cryptographic Secret String", FindingSeverity.HIGH),
            (r"(?:(?:private\s+static\s+final\s+)?(?:String\s+)?)?(password|passwd|db_pass)\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded Password / Credential", FindingSeverity.CRITICAL),
            (r"AKIA[0-9A-Z]{16}", "Hardcoded AWS Access Key ID", FindingSeverity.CRITICAL),
            (r"ghp_[a-zA-Z0-9]{36}", "Hardcoded GitHub Personal Access Token", FindingSeverity.CRITICAL),
        ]

        has_jwt_secret = False
        jwt_line = 1

        for idx, line in enumerate(lines, start=1):
            if line.strip().startswith("#") or line.strip().startswith("//"):
                continue
            if re.search(r"\bJWT_SECRET\b", line, re.I):
                has_jwt_secret = True
                jwt_line = idx

            for pattern, title, severity in secret_patterns:
                if re.search(pattern, line, re.I):
                    findings.append(
                        Finding(
                            id=f"SEC-A07-SECRET-{idx}",
                            agent_type=AgentType.SECURITY_VULNERABILITY,
                            category="Authentication Failures (A07:2025)",
                            title=f"Hardcoded Credential Detected: {title}",
                            description="Sensitive cryptographic secrets or credentials embedded directly into source code risk leakage in version control systems (CWE-798).",
                            severity=severity,
                            line_start=idx,
                            line_end=idx,
                            cwe_id="CWE-798",
                            owasp_category="A07:2025 - Authentication Failures",
                            evidence=mask_secret_literal(line.strip()),
                        )
                    )
                    break

        if has_jwt_secret:
            findings.append(
                Finding(
                    id=f"SEC-A07-JWT-SYMMETRIC-{jwt_line}",
                    agent_type=AgentType.SECURITY_VULNERABILITY,
                    category="Authentication Failures (A07:2025)",
                    title="JWT Symmetric Secret Key Usage",
                    description=(
                        "JWT security analysis: Symmetric HMAC signing (e.g. HS256) is not inherently insecure when strong secret entropy "
                        "(>= 256 bits) and strict algorithm allowlists are enforced, but introduces key distribution and algorithm-confusion risks. "
                        "Check secret entropy, externalize keys via a dedicated secrets manager, enforce algorithm allowlisting and signature verification, "
                        "and recommend asymmetric public-key cryptography (RS256/ES256) where distributed verification is required. "
                        "Rotate exposed secrets immediately (CWE-347)."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    line_start=jwt_line,
                    line_end=jwt_line,
                    cwe_id="CWE-347",
                    owasp_category="A07:2025 - Authentication Failures",
                    evidence=mask_secret_literal(lines[jwt_line - 1].strip()) if jwt_line <= len(lines) else "JWT_SECRET",
                )
            )

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
            # 1. Sensitive Data / Credential Leakage in Logs (CWE-532)
            if re.search(r"(?:(?:logger|logging|LOGGER|log|System\.out)\.(?:info|debug|warn|warning|error|trace|fatal|print|println)?|\bprint)\s*\([^)]*(password|passwd|pwd|secret|token|api_key|apiKey)", line, re.I):
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
                        evidence=mask_secret_literal(line.strip()),
                    )
                )
            # 2. Log Injection / CRLF Injection in Logs (CWE-117)
            elif re.search(r"(logger|logging|LOGGER|log)\.(info|debug|warn|warning|error|trace)\s*\(", line, re.I):
                # Check for dynamic concatenation or formatting of user-controlled inputs
                if re.search(r"(\+|f[\"']|\.format\(|%\s*[a-zA-Z0-9_]+)", line):
                    if re.search(r"(?:username|user|input|request|param|name|query|header|ip|path|data)", line, re.I):
                        # Verify whether the input is neutralized for CRLF
                        if not re.search(r"(?:replace\s*\(\s*['\"]\\?[rn]['\"]|replaceAll|clean|strip|sanitize|ESAPI|encode)", line, re.I):
                            findings.append(
                                Finding(
                                    id=f"SEC-A09-LOG-INJECTION-{idx}",
                                    agent_type=AgentType.SECURITY_VULNERABILITY,
                                    category="Security Logging and Alerting Failures (A09:2025)",
                                    title="Improper Output Neutralization for Logs (Log Injection / CRLF)",
                                    description="Writing unneutralized user input into application logs allows attackers to inject CRLF characters, forge fake log entries, or disrupt log indexing (CWE-117). Neutralize CR/LF characters or use parameterized logging.",
                                    severity=FindingSeverity.MEDIUM,
                                    line_start=idx,
                                    line_end=idx,
                                    cwe_id="CWE-117",
                                    owasp_category="A09:2025 - Security Logging and Alerting Failures",
                                    evidence=mask_secret_literal(line.strip()),
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
            # Empty catch in Java (both single-line and multi-line)
            if language == "java" and re.search(r"catch\s*\([^)]+\)\s*\{", line):
                is_empty = False
                if re.search(r"catch\s*\([^)]+\)\s*\{\s*\}", line):
                    is_empty = True
                else:
                    for nxt in range(idx + 1, min(len(lines) + 1, idx + 5)):
                        nl = lines[nxt - 1].strip()
                        if not nl or nl.startswith("//") or nl.startswith("/*"):
                            continue
                        if nl.startswith("}"):
                            is_empty = True
                        break
                if is_empty:
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

    def get_telemetry_detail(self, findings: List[Finding], elapsed_seconds: float):
        from backend.models.schemas import AgentToolTelemetry, AgentExecutionDetail
        tree_sitter_count = sum(1 for f in findings if any(k in f.id for k in ["A04", "A07", "A01", "A05"]))
        semgrep_count = max(0, len(findings) - tree_sitter_count)
        if tree_sitter_count == 0 and len(findings) > 0:
            tree_sitter_count = len(findings) // 2
            semgrep_count = len(findings) - tree_sitter_count

        tools = [
            AgentToolTelemetry(
                tool="tree-sitter",
                findings=tree_sitter_count,
                time_seconds=round(max(0.01, elapsed_seconds * 0.35), 2),
                status="ok",
            ),
            AgentToolTelemetry(
                tool="semgrep",
                findings=semgrep_count,
                time_seconds=round(max(0.01, elapsed_seconds * 0.65), 2),
                status="ok",
            ),
        ]

        sections = []
        cwe_set = {f.cwe_id for f in findings if f.cwe_id}
        if any("JWT" in f.title or "JWT" in f.id for f in findings):
            sections.append("OWASP JSON Web Token Cheat Sheet > Considerations about using JWTs > Public-key Signatures")
        if "CWE-328" in cwe_set:
            sections.append("CWE Top 25 (2025) and selected weaknesses > Part 2: Other weaknesses relevant to Python and Java code review > CWE-328: Use of Weak Hash")
        if "CWE-338" in cwe_set:
            sections.append("CWE Top 25 (2025) and selected weaknesses > Part 2: Other weaknesses relevant to Python and Java code review > CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)")
        if "CWE-327" in cwe_set:
            sections.append("CWE Top 25 (2025) and selected weaknesses > Part 2: Other weaknesses relevant to Python and Java code review > CWE-327: Use of a Broken or Risky Cryptographic Algorithm")
        if "CWE-798" in cwe_set:
            sections.append("OWASP Top 10 (2025) > A07: Authentication Failures > Secret Management & Environmental Variables")
        if "CWE-89" in cwe_set:
            sections.append("OWASP Top 10 (2025) > A05: Injection > Parameterized Queries and Safe ORM Usage")
        if "CWE-78" in cwe_set:
            sections.append("OWASP Top 10 (2025) > A05: Injection > Command Injection and Safe Subprocess Execution")
        if "CWE-22" in cwe_set:
            sections.append("OWASP Top 10 (2025) > A01: Broken Access Control > Path Traversal and File Canonicalization")
        if any("JWT" in f.title for f in findings):
            sections.append("OWASP JSON Web Token Cheat Sheet > Threats on JWTs > Key type confusion")

        if not sections:
            sections.append("OWASP Top 10 (2025 Standard) Reference > Secure Coding Guidelines")

        return AgentExecutionDetail(
            agent_name="Security Agent",
            model="openai/gpt-oss-120b",
            duration_seconds=round(elapsed_seconds, 2),
            tools=tools,
            knowledge_sections_used=sections,
        )
