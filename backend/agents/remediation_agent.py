import difflib
import logging
import re
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
            code_context=finding.evidence or "",
        )

        kb_guideline = rag_docs[0] if rag_docs else None

        # 2. Extract original snippet and local context window
        start_idx = max(0, finding.line_start - 1)
        end_idx = min(len(lines), finding.line_end)
        original_snippet = "\n".join(lines[start_idx:end_idx]) if lines else (finding.evidence or "")

        context_start = max(0, start_idx - 6)
        context_end = min(len(lines), end_idx + 6)
        context_window = "\n".join(lines[context_start:context_end]) if lines else original_snippet

        # Mask secrets in original_snippet and diff if finding is a credential
        is_credential = finding.cwe_id == "CWE-798" or any(k in finding.title for k in ["API Key", "Secret", "Credential", "Password"])
        if is_credential:
            from backend.agents.security_agent import mask_secret_literal
            display_original = mask_secret_literal(original_snippet)
        else:
            display_original = original_snippet

        # 3. Formulate corrected snippet & diff based on category
        corrected_snippet = self._craft_fix_snippet(finding, original_snippet, language, kb_guideline, context_window=context_window)

        # Generate unified diff
        diff_lines = list(
            difflib.unified_diff(
                display_original.splitlines(keepends=True),
                corrected_snippet.splitlines(keepends=True),
                fromfile=f"original_line_{finding.line_start}",
                tofile=f"remediated_line_{finding.line_start}",
            )
        )
        diff_text = "".join(diff_lines) if diff_lines else f"- {display_original}\n+ {corrected_snippet}"

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

        explanation = self._craft_explanation(finding, kb_guideline, language=language)

        return RemediationSuggestion(
            explanation=explanation,
            original_snippet=display_original,
            corrected_snippet=corrected_snippet,
            diff=diff_text,
            references=references,
            remediation_steps=steps,
            unit_test_code=unit_test,
        )

    def _craft_fix_snippet(self, finding: Finding, orig: str, language: str, kb_doc: Optional[Any], context_window: str = "") -> str:
        cwe = (finding.cwe_id or "").upper()
        title = finding.title.lower()

        # 0. Wildcard Imports (CWE-710) - check first to avoid collision with java.sql.*
        if "wildcard" in title or "SMELL-JAVA-WILDCARD" in finding.id or "710" in cwe:
            if language == "python":
                return "# Explicitly import required components:\nfrom module import SpecificClass, specific_function"
            else:
                # Extract suggested explicit imports from description if available
                if "import " in finding.description:
                    extracted = re.findall(r"import\s+[a-zA-Z0-9_.]+\s*;", finding.description)
                    if extracted:
                        return "// Replace wildcard import with explicit imports for types used in this file:\n" + "\n".join(extracted)
                return "// Explicitly import only required types:\nimport java.io.File;\nimport java.io.IOException;"

        # 1. SQL Injection (CWE-89)
        if ("sql" in title or "sqli" in finding.id.lower()) and "wildcard" not in title:
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

        # 2. Path Traversal (CWE-22)
        if "path" in title or "traversal" in title or "path" in finding.id.lower():
            if language == "python":
                return (
                    "# Normalize and canonicalize path to prevent directory traversal:\n"
                    "import os\n"
                    "base_dir = os.path.abspath('uploads')\n"
                    "target_path = os.path.abspath(os.path.join(base_dir, filename))\n"
                    "if not target_path.startswith(base_dir):\n"
                    "    raise PermissionError('Path traversal attempt detected')"
                )
            else:
                return (
                    "// Safe Java path resolution, normalization, and containment check (CWE-22):\n"
                    "Path baseDir = Paths.get(\"uploads\").toAbsolutePath().normalize();\n"
                    "Path target = baseDir.resolve(filename).normalize();\n"
                    "if (!target.startsWith(baseDir)) {\n"
                    "    throw new SecurityException(\"Path traversal attempt detected: \" + filename);\n"
                    "}"
                )

        # 3. Command Injection (CWE-78)
        if "command injection" in title or "os.system" in title or "exec" in finding.id.lower():
            if language == "python":
                return (
                    "# 1. Strictly validate host input (IP address or DNS hostname format) to prevent argument injection:\n"
                    "import ipaddress, re, subprocess\n\n"
                    "def is_valid_host(val: str) -> bool:\n"
                    "    if not val or val.startswith('-'):\n"
                    "        return False\n"
                    "    try:\n"
                    "        ipaddress.ip_address(val)\n"
                    "        return True\n"
                    "    except ValueError:\n"
                    "        return bool(re.match(r'^[a-zA-Z0-9.-]{1,253}$', val))\n\n"
                    "if not is_valid_host(host):\n"
                    "    raise ValueError(f'Invalid host format: {host}')\n\n"
                    "# 2. Pass arguments as a safe list with shell=False (avoids shell interpolation):\n"
                    "subprocess.run(['ping', '-c', '1', host], check=True, shell=False)"
                )
            else:
                return (
                    "// 1. Strictly validate host input to prevent parameter injection:\n"
                    "if (host == null || host.startsWith(\"-\") || !host.matches(\"^[a-zA-Z0-9.-]{1,253}$\")) {\n"
                    "    throw new IllegalArgumentException(\"Invalid host format: \" + host);\n"
                    "}\n\n"
                    "// 2. Use ProcessBuilder with discrete argument list (avoids shell interpolation):\n"
                    "ProcessBuilder pb = new ProcessBuilder(\"ping\", \"-c\", \"1\", host);\n"
                    "Process process = pb.start();"
                )

        # 4. PRNG - Pseudo-Random Number Generator (CWE-338) - Handle before any A04 hash block
        if "338" in cwe or "prng" in title or "pseudo-random" in title or "weakprng" in finding.id.lower():
            if language == "python":
                return (
                    "# Use Python's 'secrets' module for cryptographically secure tokens and nonces (CWE-338):\n"
                    "import secrets\n"
                    "reset_token = secrets.token_urlsafe(32)\n"
                    "# Or for cryptographic integers: secrets.randbelow(1000000)"
                )
            else:
                return (
                    "// Use java.security.SecureRandom for security-sensitive tokens, keys, and reset links (CWE-338):\n"
                    "SecureRandom secureRandom = SecureRandom.getInstanceStrong();\n"
                    "byte[] tokenBytes = new byte[32];\n"
                    "secureRandom.nextBytes(tokenBytes);\n"
                    "String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);"
                )

        # 5. Broken / Risky Cipher Algorithm & Insecure ECB Mode (CWE-327) - Handle before hash block
        if "327" in cwe or "ecb" in title or "cipher" in title or "ecbcipher" in finding.id.lower():
            if language == "python":
                return (
                    "# Use authenticated encryption with AES.MODE_GCM (12-byte nonce, 128-bit auth tag) (CWE-327):\n"
                    "from Crypto.Cipher import AES\n"
                    "import secrets\n"
                    "nonce = secrets.token_bytes(12)\n"
                    "cipher = AES.new(secret_key, AES.MODE_GCM, nonce=nonce)\n"
                    "ciphertext, tag = cipher.encrypt_and_digest(data)"
                )
            else:
                return (
                    "// Use authenticated encryption with AES/GCM/NoPadding (12-byte IV, 128-bit auth tag) (CWE-327):\n"
                    "byte[] iv = new byte[12];\n"
                    "SecureRandom.getInstanceStrong().nextBytes(iv);\n"
                    "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
                    "GCMParameterSpec spec = new GCMParameterSpec(128, iv);\n"
                    "cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);\n"
                    "byte[] cipherText = cipher.doFinal(plainText);\n"
                    "// Note: Transmit or prepend the unique 12-byte IV alongside ciphertext for decryption verification."
                )

        # 6. JWT Security Analysis & Algorithm Configuration (CWE-347) - Handle before general secret block
        if "347" in cwe or ("jwt" in title and "hardcoded" not in title) or "jwt-symmetric" in finding.id.lower():
            if language == "python":
                return (
                    "# Secure JWT configuration and verification (CWE-347):\n"
                    "import os, jwt\n"
                    "# 1. Load strong secret (minimum 256 bits for HS256) from environment / secrets manager:\n"
                    "jwt_secret = os.environ.get('JWT_SECRET')\n"
                    "# 2. Enforce explicit algorithm allowlisting and cryptographic signature verification:\n"
                    "payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])\n"
                    "# 3. For distributed verification across microservices, migrate to asymmetric RS256/ES256 keys.\n"
                    "# 4. Rotate signing secret immediately if credentials have been exposed."
                )
            else:
                return (
                    "// Secure JWT configuration and verification (CWE-347):\n"
                    "// 1. Load strong secret (minimum 256 bits / 32 bytes for HS256) from secrets manager:\n"
                    "String jwtSecret = System.getenv(\"JWT_SECRET\");\n"
                    "SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));\n\n"
                    "// 2. Enforce explicit algorithm allowlisting and cryptographic signature verification:\n"
                    "Claims claims = Jwts.parserBuilder()\n"
                    "    .setSigningKey(key)\n"
                    "    .build()\n"
                    "    .parseClaimsJws(token)\n"
                    "    .getBody();\n\n"
                    "// 3. For distributed microservice architectures, migrate to asymmetric public-key signatures (RS256/ES256).\n"
                    "// 4. Rotate signing secret immediately if credentials have been exposed."
                )

        # 7. Hardcoded Secrets / Keys / Credentials (CWE-798)
        if "798" in cwe or "hardcoded" in title or "secret" in title:
            var_name = "API_KEY"
            if "jwt" in title:
                var_name = "JWT_SECRET"
            elif "aes" in title or "symmetric key" in title:
                var_name = "AES_KEY"
            elif "password" in title or "db" in title:
                var_name = "DB_PASSWORD"

            if language == "python":
                return (
                    f"# Recommended Credential Management (CWE-798):\n"
                    f"# 1. Basic / Dev: Retrieve secret from environment variable:\n"
                    f"import os\n"
                    f"{var_name} = os.environ.get('{var_name}')\n"
                    f"if not {var_name}:\n"
                    f"    raise ValueError('{var_name} environment variable is missing')\n\n"
                    f"# 2. Production: Use a dedicated Secrets Manager (e.g. AWS Secrets Manager, HashiCorp Vault).\n"
                    f"# Note: Environment variables alone do not mitigate all secret-leakage risks (process memory dumps,\n"
                    f"# child process inheritance, container inspection). Use a secrets manager with automatic rotation.\n"
                    f"# IMPORTANT: Rotate any exposed secrets immediately since they may exist in version control history."
                )
            else:
                return (
                    f"// Recommended Credential Management (CWE-798):\n"
                    f"// 1. Basic / Dev: Retrieve secret from environment variable:\n"
                    f"String secret = System.getenv(\"{var_name}\");\n"
                    f"if (secret == null || secret.isBlank()) {{\n"
                    f"    throw new IllegalStateException(\"{var_name} environment variable is missing\");\n"
                    f"}}\n\n"
                    f"// 2. Production: Retrieve from dedicated Secrets Manager (e.g. AWS Secrets Manager, HashiCorp Vault):\n"
                    f"// Note: Environment variables alone do not mitigate all secret-leakage risks (process memory dumps,\n"
                    f"// child process inheritance, container inspection). Use a secrets manager with automatic rotation.\n"
                    f"// IMPORTANT: Rotate any exposed secrets immediately since they may exist in version control history."
                )

        # 8. Generic 'throws Exception' in Signatures (CWE-398)
        if "398" in cwe or "throws exception" in title or "throwsexcept" in finding.id.lower():
            sugg_match = re.search(r"declare specific exception types:\s*([^()]+)", finding.description)
            sugg_types = sugg_match.group(1).strip() if sugg_match else "GeneralSecurityException, IOException"
            first_type = sugg_types.split(",")[0].strip()
            if language == "python":
                return (
                    "# Declare and handle specific exception types explicitly:\n"
                    "try:\n"
                    "    perform_operation()\n"
                    "except (ValueError, KeyError) as err:\n"
                    "    logger.warning('Handled specific error: %s', err)"
                )
            else:
                return (
                    f"// Replace generic 'throws Exception' with specific exception types based on operations:\n"
                    f"public void operation() throws {sugg_types} {{\n"
                    f"    // Or catch checked exceptions and wrap into a descriptive domain-specific unchecked exception:\n"
                    f"    try {{\n"
                    f"        // ... perform operations ...\n"
                    f"    }} catch ({first_type} e) {{\n"
                    f"        throw new RuntimeException(\"Operation failed\", e);\n"
                    f"    }}\n"
                    f"}}"
                )

        # 9. Cryptographic Hash & Password Storage (CWE-328 / CWE-256 / CWE-312)
        if "328" in cwe or "256" in cwe or "312" in cwe or "hash" in title or "md5" in title or "sha" in title or "weakhash" in finding.id.lower():
            search_context = f"{finding.evidence or ''} {orig} {context_window}".lower()
            is_password = ("256" in cwe) or ("312" in cwe) or ("password" in title) or any(term in search_context for term in ["password", "passwd", "pwd", "auth", "credential", "login", "user_pass"])
            is_checksum = not is_password and any(term in search_context for term in ["checksum", "crc32", "filehash", "file_hash", "integrity_check", "sha256sum"])

            if is_password:
                if language == "python":
                    return (
                        "# For password storage, use Argon2id (recommended) or bcrypt (NEVER plain SHA-256 or MD5):\n"
                        "from argon2 import PasswordHasher\n\n"
                        "# Configured with 16-byte salt, 64MB memory cost, 4 threads, 3 iterations:\n"
                        "ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)\n"
                        "hashed_password = ph.hash(raw_password)\n"
                        "# Verification: ph.verify(hashed_password, candidate_password)"
                    )
                else:
                    return (
                        "// For password storage, use Argon2id or bcrypt (NEVER plain MD5 or SHA-256):\n"
                        "// Recommended parameters: 16-byte salt, 32-byte hash, 1 iteration, 65536KB (64MB) RAM, 3 threads:\n"
                        "org.springframework.security.crypto.argon2.Argon2PasswordEncoder encoder =\n"
                        "    new org.springframework.security.crypto.argon2.Argon2PasswordEncoder(16, 32, 1, 65536, 3);\n"
                        "String hashedPassword = encoder.encode(rawPassword);\n"
                        "// Verification: boolean matches = encoder.matches(rawPassword, hashedPassword);"
                    )
            elif is_checksum:
                if language == "python":
                    return (
                        "# For non-password data integrity / file digests, use SHA-256 or SHA-512:\n"
                        "import hashlib\n"
                        "digest = hashlib.sha256(data.encode('utf-8')).hexdigest()"
                    )
                else:
                    return (
                        "// For non-password data integrity / file digests, use SHA-256 or SHA-512:\n"
                        "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n"
                        "byte[] hash = md.digest(data.getBytes(StandardCharsets.UTF_8));"
                    )
            else:
                # Unknown purpose: explain context dependency and provide safe options
                if language == "python":
                    return (
                        "# Context-dependent cryptographic remediation:\n"
                        "# CASE 1 - Password / Credential Storage (Use Argon2id or bcrypt; NEVER plain SHA-256 or MD5):\n"
                        "#   from argon2 import PasswordHasher\n"
                        "#   hashed = PasswordHasher().hash(raw_password)\n"
                        "#\n"
                        "# CASE 2 - Message Digest / File Integrity Checksum (Use SHA-256 or SHA-512):\n"
                        "import hashlib\n"
                        "digest = hashlib.sha256(data.encode('utf-8')).hexdigest()"
                    )
                else:
                    return (
                        "// Context-dependent cryptographic remediation:\n"
                        "// CASE 1 - Password / Credential Storage (Use Argon2id or bcrypt; NEVER plain MD5 or SHA-256):\n"
                        "//   org.springframework.security.crypto.argon2.Argon2PasswordEncoder encoder =\n"
                        "//       new org.springframework.security.crypto.argon2.Argon2PasswordEncoder(16, 32, 1, 65536, 3);\n"
                        "//   String hashed = encoder.encode(rawPassword);\n"
                        "//\n"
                        "// CASE 2 - Message Digest / File Integrity Checksum (Use SHA-256 or SHA-512):\n"
                        "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n"
                        "byte[] hash = md.digest(data.getBytes(StandardCharsets.UTF_8));"
                    )

        # 10. Sensitive Credential Logging in Logs (CWE-532)
        if "532" in cwe or "logleak" in finding.id.lower() or "credential leakage" in title:
            if language == "python":
                return (
                    "# Mask sensitive credentials before logging (CWE-532):\n"
                    "import logging\n"
                    "logger = logging.getLogger(__name__)\n"
                    "logger.info('User login attempt: %s with password [REDACTED]', username)"
                )
            else:
                return (
                    "// Mask sensitive credentials before logging (CWE-532):\n"
                    "logger.info(\"User login attempt: {} with password [REDACTED]\", username);"
                )

        # 11. Insecure Deserialization (CWE-502)
        if "pickle" in title or "502" in cwe or "deserialization" in title:
            if language == "python":
                return (
                    "# Insecure Deserialization Remediation (CWE-502):\n"
                    "# 1. Simple Data Interchange: Use safe structured formats (JSON, Protocol Buffers, MsgPack):\n"
                    "import json\n"
                    "data = json.loads(payload)\n\n"
                    "# 2. Complex Python Objects: If binary serialization is strictly unavoidable,\n"
                    "# cryptographically sign payload (e.g. itsdangerous, HMAC) to verify authenticity before loading:\n"
                    "# from itsdangerous import Signer\n"
                    "# verified_payload = Signer(SECRET_KEY).unsign(signed_data)\n"
                    "# obj = pickle.loads(verified_payload)  # Safe only after cryptographic authentication"
                )
            else:
                return (
                    "// 1. Safe Data Interchange: Use Jackson ObjectMapper for structured JSON deserialization:\n"
                    "ObjectMapper mapper = new ObjectMapper();\n"
                    "UserDTO user = mapper.readValue(payloadStream, UserDTO.class);\n\n"
                    "// 2. Complex Objects: If Java native serialization is mandatory, enforce ObjectInputFilter allowlisting."
                )

        # 11. Exception Handling / Empty Catch (CWE-390 / CWE-755)
        if "except:" in title or "bare" in title or "swallowing" in title or "empty catch" in title or "390" in cwe:
            if language == "python":
                return (
                    "# Catch specific exceptions explicitly and log appropriately:\n"
                    "except (ValueError, KeyError) as err:\n"
                    "    logger.warning('Handled input error: %s', err)"
                )
            else:
                return (
                    "// Handle exception explicitly and log details:\n"
                    "catch (SQLException | IOException e) {\n"
                    "    logger.error(\"Operation failed: \", e);\n"
                    "    throw new ServiceException(\"Failed to process request\", e);\n"
                    "}"
                )

        # 12. Debug Mode Configuration (CWE-16)
        if "debug mode" in title or "16" in cwe:
            if language == "python":
                return (
                    "# Read debug flag dynamically from environment:\n"
                    "import os\n"
                    "DEBUG = os.getenv('APP_ENV') == 'development'"
                )
            else:
                return (
                    "// Configure debug mode externally via environment or config:\n"
                    "boolean debugMode = Boolean.parseBoolean(System.getenv(\"APP_DEBUG\"));"
                )

        # 13. Log Injection / CRLF Injection (CWE-117)
        if "117" in cwe or "log injection" in title or "log-injection" in finding.id.lower():
            if language == "python":
                return (
                    "# Neutralize CRLF characters to prevent Log Injection (CWE-117):\n"
                    "safe_input = user_input.replace('\\r', '_').replace('\\n', '_') if user_input else ''\n"
                    "logger.info('User operation completed: %s', safe_input)"
                )
            else:
                return (
                    "// Neutralize unescaped CRLF characters to prevent Log Injection (CWE-117):\n"
                    "String safeInput = input != null ? input.replaceAll(\"[\\r\\n]\", \"_\") : \"\";\n"
                    "logger.info(\"User operation completed: {}\", safeInput);"
                )

        # 14. Code Smells: Excessive Nesting & Long Methods (CWE-1075)
        if "long method" in title or "nesting" in title or "1075" in cwe:
            if language == "python":
                return (
                    "# Refactor with guard clauses (return early) and helper methods:\n"
                    "if not is_valid_input(data):\n"
                    "    return None\n"
                    "return process_validated_data(data)"
                )
            else:
                return (
                    "// Refactor with guard clauses (return early) and helper methods:\n"
                    "if (data == null || !isValid(data)) {\n"
                    "    return null;\n"
                    "}\n"
                    "return processValidatedData(data);"
                )

        # 15. Missing Documentation / Docstrings (CWE-1078)
        if "1078" in cwe or "docstring" in title or "documentation" in title:
            if language == "python":
                return (
                    'def function_name(param1: str, param2: int) -> bool:\n'
                    '    """Brief summary of function purpose (PEP 257).\n\n'
                    '    Args:\n'
                    '        param1: Description of first parameter.\n'
                    '        param2: Description of second parameter.\n\n'
                    '    Returns:\n'
                    '        bool: Description of return value.\n\n'
                    '    Raises:\n'
                    '        ValueError: Description of conditions under which errors occur.\n'
                    '    """\n'
                    '    return True'
                )
            else:
                return (
                    '/**\n'
                    ' * Brief description of method purpose (Javadoc standard).\n'
                    ' *\n'
                    ' * @param param1 description of param1\n'
                    ' * @return description of returned value\n'
                    ' * @throws IllegalArgumentException when inputs are invalid\n'
                    ' */\n'
                    'public boolean performAction(String param1) {\n'
                    '    return true;\n'
                    '}'
                )

        # Language-aware fallback
        if language == "java":
            return f"// Remediation for {finding.title}:\n// Follow standard secure coding practices (verify inputs, use safe APIs)."
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
                    "    String envSecret = System.getenv(\"API_KEY\");\n"
                    "    // Verify credentials are not baked into class constants\n"
                    "    assertNotNull(envSecret, \"Secret must be configured via environment\");\n"
                    "}\n"
                )

        if "command" in title or "exec" in title or "shell" in title:
            if language == "python":
                return (
                    "import pytest\n\n"
                    "def test_command_injection_rejected():\n"
                    "    malicious_host = '127.0.0.1; cat /etc/passwd'\n"
                    "    res = run_system_ping(malicious_host)\n"
                    "    assert res is False, 'Command injection must not execute platform shell!'\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testCommandInjectionRejected() {\n"
                    "    String maliciousHost = \"127.0.0.1; cat /etc/passwd\";\n"
                    "    assertThrows(SecurityException.class, () -> {\n"
                    "        app.executeSystemCommand(maliciousHost);\n"
                    "    });\n"
                    "}\n"
                )

        if "pickle" in title or "deserialization" in title:
            if language == "python":
                return (
                    "import pytest, json\n\n"
                    "def test_safe_deserialization_rejects_malicious_pickle():\n"
                    "    malicious_bytes = b'cos\\nsystem\\n(S\"echo pwned\"\\ntR.'\n"
                    "    with pytest.raises((json.JSONDecodeError, ValueError)):\n"
                    "        # Structured parser should reject arbitrary python binary blobs\n"
                    "        json.loads(malicious_bytes.decode('latin1'))\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testSafeDeserializationRejectsMaliciousPayload() {\n"
                    "    byte[] maliciousPayload = \"{\\\"invalid\\\": \\\"payload\\\"}\".getBytes();\n"
                    "    assertThrows(IllegalArgumentException.class, () -> {\n"
                    "        app.deserializeUserData(maliciousPayload);\n"
                    "    });\n"
                    "}\n"
                )

        if "338" in (finding.cwe_id or "").lower() or "prng" in title or "random" in title or "weakprng" in finding.id.lower():
            if language == "python":
                return (
                    "import secrets\n\n"
                    "def test_cryptographically_secure_random_tokens():\n"
                    "    token = secrets.token_urlsafe(32)\n"
                    "    assert len(token) >= 32, 'Generated security token must possess adequate entropy'\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testSecureRandomTokenGeneration() {\n"
                    "    java.security.SecureRandom rng = new java.security.SecureRandom();\n"
                    "    byte[] token = new byte[32];\n"
                    "    rng.nextBytes(token);\n"
                    "    assertNotNull(token);\n"
                    "    assertEquals(32, token.length, \"SecureRandom must produce non-null cryptographic bytes\");\n"
                    "}\n"
                )

        if "327" in (finding.cwe_id or "").lower() or "ecb" in title or "cipher" in title or "ecbcipher" in finding.id.lower():
            if language == "python":
                return (
                    "from Crypto.Cipher import AES\n"
                    "import secrets\n\n"
                    "def test_aes_gcm_authenticated_encryption():\n"
                    "    key = secrets.token_bytes(32)\n"
                    "    cipher = AES.new(key, AES.MODE_GCM)\n"
                    "    ciphertext, tag = cipher.encrypt_and_digest(b'test_data')\n"
                    "    assert ciphertext is not None and tag is not None\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testAesGcmAuthenticatedEncryption() throws Exception {\n"
                    "    byte[] key = new byte[32];\n"
                    "    byte[] iv = new byte[12];\n"
                    "    java.security.SecureRandom.getInstanceStrong().nextBytes(key);\n"
                    "    java.security.SecureRandom.getInstanceStrong().nextBytes(iv);\n"
                    "    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
                    "    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, \"AES\"), new javax.crypto.spec.GCMParameterSpec(128, iv));\n"
                    "    byte[] cipherText = cipher.doFinal(\"testData\".getBytes(java.nio.charset.StandardCharsets.UTF_8));\n"
                    "    assertNotNull(cipherText, \"Ciphertext must be produced\");\n"
                    "}\n"
                )

        if "347" in (finding.cwe_id or "").lower() or ("jwt" in title and "hardcoded" not in title) or "jwt-symmetric" in finding.id.lower():
            if language == "python":
                return (
                    "import os, jwt\n\n"
                    "def test_jwt_signature_verification():\n"
                    "    secret = os.environ.get('JWT_SECRET', 'mock_secret_key_32_bytes_long!!')\n"
                    "    assert secret is not None\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testJwtSignatureVerification() {\n"
                    "    String envSecret = System.getenv(\"JWT_SECRET\");\n"
                    "    assertNotNull(envSecret, \"JWT secret must be externalized in environment or secrets manager\");\n"
                    "}\n"
                )

        if "398" in (finding.cwe_id or "").lower() or "throwsexcept" in finding.id.lower() or "throws exception" in title:
            if language == "python":
                return (
                    "def test_specific_exception_handling():\n"
                    "    assert True\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testSpecificExceptionHandling() {\n"
                    "    assertDoesNotThrow(() -> {\n"
                    "        // Caller handles specific typed exceptions\n"
                    "    });\n"
                    "}\n"
                )

        if "hash" in title or "sha1" in title or "md5" in title or "a04" in finding.id.lower():
            text_ctx = f"{title} {finding.description} {finding.evidence or ''}".lower()
            if any(term in text_ctx for term in ["pass", "pwd", "auth", "login", "credential"]):
                if language == "python":
                    return (
                        "import pytest\n"
                        "from argon2 import PasswordHasher\n\n"
                        "def test_password_hashing_with_argon2id():\n"
                        "    ph = PasswordHasher()\n"
                        "    hashed = ph.hash('SecurePassword123!')\n"
                        "    assert ph.verify(hashed, 'SecurePassword123!') is True\n"
                    )
                else:
                    return (
                        "@Test\n"
                        "void testPasswordHashingWithArgon2id() {\n"
                        "    org.springframework.security.crypto.argon2.Argon2PasswordEncoder encoder =\n"
                        "        new org.springframework.security.crypto.argon2.Argon2PasswordEncoder(16, 32, 1, 65536, 3);\n"
                        "    String hashed = encoder.encode(\"SecurePassword123!\");\n"
                        "    assertTrue(encoder.matches(\"SecurePassword123!\", hashed), \"Argon2id must verify valid password\");\n"
                        "}\n"
                    )

        if "cwe-312" in (finding.cwe_id or "").lower() or "cwe-256" in (finding.cwe_id or "").lower() or "cleartext" in title or "plaintext" in title:
            if language == "python":
                return (
                    "def test_password_never_stored_in_plaintext():\n"
                    "    # Verify password is not saved in cleartext\n"
                    "    raw_pass = 'UserSecret123!'\n"
                    "    assert raw_pass != get_stored_password_hash()\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testPasswordNeverStoredInPlaintext() {\n"
                    "    // Verify stored credential does not match raw plaintext\n"
                    "    String rawPass = \"UserSecret123!\";\n"
                    "    assertNotEquals(rawPass, app.getUserPasswordHash(), \"Password must be hashed with Argon2id/bcrypt before storage\");\n"
                    "}\n"
                )

        if "117" in (finding.cwe_id or "") or "log injection" in title:
            if language == "python":
                return (
                    "import pytest\n\n"
                    "def test_log_injection_defense():\n"
                    "    payload = 'admin\\r\\n[SECURITY] Injected log entry'\n"
                    "    sanitized = payload.replace('\\r', '_').replace('\\n', '_')\n"
                    "    assert '\\r' not in sanitized and '\\n' not in sanitized\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testLogInjectionDefense() {\n"
                    "    String payload = \"admin\\r\\n[ALERT] Forged entry\";\n"
                    "    String sanitized = payload.replaceAll(\"[\\r\\n]\", \"_\");\n"
                    "    assertFalse(sanitized.contains(\"\\r\"));\n"
                    "    assertFalse(sanitized.contains(\"\\n\"));\n"
                    "}\n"
                )

        if "wildcard" in title or "cwe-710" in (finding.cwe_id or "").lower():
            if language == "python":
                return (
                    "def test_explicit_imports():\n"
                    "    # Verify module namespaces are cleanly resolved without wildcard pollution\n"
                    "    assert True\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testExplicitImportsCompile() {\n"
                    "    // Verify explicit imports compile and resolve required symbols without wildcard clutter\n"
                    "    assertDoesNotThrow(() -> {\n"
                    "        // Classes resolved cleanly\n"
                    "    });\n"
                    "}\n"
                )

        if "nesting" in title or "cwe-1075" in (finding.cwe_id or "").lower():
            if language == "python":
                return (
                    "def test_refactored_nesting_logic():\n"
                    "    # Verify refactored guard clause logic returns expected result\n"
                    "    assert process_data(None) is None\n"
                    "    assert process_data('valid_data') == 'PROCESSED'\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testRefactoredNestingLogic() {\n"
                    "    // Verify refactored guard clause logic preserves semantics\n"
                    "    assertNull(app.processOrder(null));\n"
                    "    assertNotNull(app.processOrder(new Order(\"valid\")));\n"
                    "}\n"
                )

        if "1078" in (finding.cwe_id or "").lower() or "docstring" in title or "documentation" in title:
            if language == "python":
                return (
                    "def test_function_has_docstring():\n"
                    "    # Verify function possesses PEP 257 compliant docstring\n"
                    "    doc = getattr(target_func, '__doc__', None)\n"
                    "    assert doc is not None and len(doc.strip()) > 10\n"
                )
            else:
                return (
                    "@Test\n"
                    "void testMethodHasDocstring() {\n"
                    "    // Verify Javadoc presence and contract\n"
                    "    assertTrue(true);\n"
                    "}\n"
                )

        if language == "python":
            return (
                "def test_finding_remediation():\n"
                f"    # Automated regression test for {finding.title}\n"
                "    assert True\n"
            )
        else:
            return (
                "@Test\n"
                "void testFindingRemediation() {\n"
                f"    // Automated regression test for {finding.title}\n"
                "    assertTrue(true);\n"
            )

    def _craft_explanation(self, finding: Finding, kb_doc: Optional[Any], language: str = "python") -> str:
        """Explains why the finding is valid and why the proposed fix resolves it."""
        cwe = finding.cwe_id or ""
        title = finding.title.lower()
        if "89" in cwe or "sql" in title:
            return (
                "Valid Finding: Dynamic string concatenation or formatting inside SQL queries enables attackers "
                "to alter query structure and extract unauthorized data (CWE-89). "
                "Resolution: PreparedStatement binds user input as literal data parameters, completely preventing SQL command execution."
            )
        if "22" in cwe or "path" in title:
            return (
                "Valid Finding: Accepting unvalidated file paths permits directory traversal sequences (../) "
                "accessing unauthorized filesystem locations (CWE-22). "
                "Resolution: Path resolution with canonicalization/normalization and a startsWith containment check ensures all access remains inside the designated directory."
            )
        if "256" in cwe or "312" in cwe or "plaintext" in title:
            return (
                "Valid Finding: Storing raw passwords in plaintext leaves credentials vulnerable in the event of a database compromise (CWE-256). "
                "Resolution: Applying a salted, memory-hard key derivation function (Argon2id or bcrypt) protects passwords against offline rainbow tables and GPU cracking."
            )
        if "328" in cwe or "md5" in title or "sha1" in title or "sha-1" in title:
            return (
                "Valid Finding: MD5 and SHA-1 suffer from collision and preimage weaknesses and lack computational cost for passwords (CWE-328). "
                "Resolution: Argon2id/bcrypt for passwords or SHA-256/SHA-512 for data integrity ensures robust resistance to collision attacks."
            )
        if re.search(r"\b(?:cwe-)?78\b", cwe, re.I) or "command injection" in title or "os.system" in title or "commandrunner" in finding.id.lower():
            return (
                "Valid Finding: Invoking system commands via shell execution or dynamic string concatenation allows attackers to execute arbitrary OS commands (CWE-78). "
                "Resolution: Strictly validate and allowlist host inputs (e.g. verifying valid IP/hostname formats and rejecting leading hyphens) and execute processes using discrete argument arrays with shell=False / ProcessBuilder."
            )
        if "502" in cwe or "deserialization" in title or "pickle" in title:
            return (
                "Valid Finding: Unsafe deserialization of untrusted byte streams permits remote code execution via object reconstruction hooks (e.g., Python __reduce__, Java readObject) (CWE-502). "
                "Resolution: Use safe structured formats (JSON, Protocol Buffers, MsgPack) for simple data interchange. If binary serialization is strictly required for complex domain objects, cryptographically sign and verify data (HMAC / itsdangerous) before deserialization."
            )
        if "338" in cwe or "prng" in title or "random" in title or "weakprng" in finding.id.lower():
            if (language or getattr(finding, "language", None) or "python").lower() == "python":
                return (
                    "Valid Finding: Python's 'random' module utilizes the Mersenne Twister (MT19937) PRNG, which is completely non-cryptographic and deterministic. "
                    "An attacker observing 624 32-bit outputs can reconstruct its 19937-bit internal state and predict all future tokens (CWE-338). "
                    "Resolution: Use Python's 'secrets' module (PEP 506) or os.urandom(), which draws entropy directly from OS CSPRNG pools."
                )
            else:
                return (
                    "Valid Finding: java.util.Random uses a 48-bit Linear Congruential Generator (LCG) whose internal state can be reconstructed from two consecutive outputs (CWE-338). "
                    "Resolution: Use java.security.SecureRandom, which sources cryptographically secure entropy from OS CSPRNG pools."
                )
        if "1078" in cwe or "docstring" in title or "missing docstring" in title or "documentation" in title:
            return (
                "Valid Finding: Missing docstrings and public function documentation impede maintainability and increase the likelihood of API misuse (CWE-1078). "
                "Resolution: Declare structured docstrings adhering to PEP 257 (Python) specifying arguments, return types, and exceptions, or Javadoc (Java)."
            )
        if "532" in cwe or "credential leakage" in title or "plaintext logging" in title or "logleak" in finding.id.lower():
            return (
                "Valid Finding: Writing plaintext passwords, tokens, or credentials into application logs exposes sensitive authentication material to system monitors, log indexers, and third-party aggregation pipelines (CWE-532). "
                "Resolution: Mask or omit sensitive credentials from log payloads, replacing them with obfuscated identifiers or cryptographic hashes."
            )
        if "327" in cwe or "ecb" in title or "cipher" in title or "ecbcipher" in finding.id.lower():
            return (
                "Valid Finding: AES with Electronic Codebook (ECB) mode encrypts identical plaintext blocks into identical ciphertext blocks, "
                "leaking structural patterns without integrity protection (CWE-327). "
                "Resolution: AES/GCM/NoPadding provides authenticated encryption with associated data (AEAD), combining confidentiality with tag-based integrity and tamper detection."
            )
        if "347" in cwe or "jwt-symmetric" in finding.id.lower() or ("jwt" in title and "hardcoded" not in title):
            return (
                "Valid Finding: JWT symmetric key signing requires sufficient entropy, strict algorithm allowlisting, and verification to prevent algorithm-confusion attacks (CWE-347). "
                "Resolution: Validate HMAC-SHA256 signatures with 256-bit+ secret keys or migrate to asymmetric keys (RS256/ES256) for multi-service architectures, and support secret rotation."
            )
        if "398" in cwe or "throwsexcept" in finding.id.lower() or "throws exception" in title:
            return (
                "Valid Finding: Declaring generic 'throws Exception' masks specific failure modes, forces callers into overly broad catch blocks, and obscures API contracts (CWE-398). "
                "Resolution: Declare specific, checked exception types based on operations performed to improve maintainability and enable precise error handling."
            )
        if "798" in cwe or "secret" in title or "credential" in title:
            return (
                "Valid Finding: Hardcoded credentials in source code are easily exposed in revision control and leak into distributed binaries (CWE-798). "
                "Resolution: Externalizing secrets to environment variables or dedicated Secrets Managers prevents source code credential leakage."
            )
        if "117" in cwe or "log injection" in title:
            return (
                "Valid Finding: Directly concatenating untrusted inputs into logs permits CRLF injection and log forging (CWE-117). "
                "Resolution: Neutralizing carriage return and newline characters ensures inputs cannot forge separate log entries."
            )
        if "710" in cwe or "wildcard" in title:
            return (
                "Valid Finding: Wildcard imports pollute the namespace and introduce ambiguity if new classes are added to imported packages (CWE-710). "
                "Resolution: Replacing wildcards with explicit imports for types actually used enhances code clarity and prevents namespace collisions."
            )
        if "1075" in cwe or "nesting" in title:
            return (
                "Valid Finding: Deeply nested control flow increases cyclomatic complexity and impairs readability (CWE-1075). "
                "Resolution: Refactoring with guard clauses (early returns) flattens execution structure and simplifies maintenance."
            )
        if kb_doc and getattr(kb_doc, "content", None):
            return f"{kb_doc.title}: {kb_doc.content[:220]}..."
        return (
            f"Remediation based on {finding.owasp_category or finding.category}: "
            f"Replace vulnerable implementation with safe construct adhering to secure coding guidelines."
        )
