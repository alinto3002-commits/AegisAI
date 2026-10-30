import pytest
from pathlib import Path
from backend.agents.orchestrator import MultiAgentOrchestrator
from backend.agents.code_analysis_agent import CodeAnalysisAgent
from backend.agents.security_agent import SecurityVulnerabilityAgent
from backend.agents.remediation_agent import RemediationAgent
from backend.models.schemas import CodeSubmission, FindingSeverity, AgentType

@pytest.fixture
def orchestrator():
    return MultiAgentOrchestrator()

@pytest.fixture
def code_agent():
    return CodeAnalysisAgent()

@pytest.fixture
def sec_agent():
    return SecurityVulnerabilityAgent()

@pytest.fixture
def rem_agent():
    return RemediationAgent()


def test_1_jdbc_connection_string_no_nesting_warning(orchestrator):
    """
    Test 1: A JDBC connection string does not trigger an excessive nesting warning.
    Verifies that lines with indentation or method calls inside try blocks
    (like DriverManager.getConnection) are not falsely counted as control-flow nesting.
    """
    code = """
package com.example.service;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseService {
    public Connection createConnection() throws SQLException {
        try {
            Connection conn = DriverManager.getConnection("jdbc:sqlite:users.db");
            return conn;
        } catch (SQLException e) {
            return null;
        }
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="DatabaseService.java")
    report = orchestrator.analyze(submission)

    # Must NOT contain CWE-1075 (Excessive Nesting)
    nesting_findings = [f for f in report.findings if f.cwe_id == "CWE-1075"]
    assert len(nesting_findings) == 0, f"Expected 0 nesting findings, found: {nesting_findings}"


def test_2_sql_concatenation_triggers_sqli_not_nesting(orchestrator):
    """
    Test 2: SQL string concatenation does not trigger a nesting warning but triggers SQL injection (CWE-89).
    Verifies that multiline string concatenation (+ username + ...) is not flagged for deep nesting,
    while genuinely flagging CWE-89 SQL Injection.
    """
    code = """
package com.example.auth;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;

public class AuthService {
    public boolean login(String username, String password) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:sqlite:users.db");
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE username = '" 
                + username + "' AND password = '" + password + "'";
            ResultSet rs = stmt.executeQuery(sql);
            return rs.next();
        } catch (Exception e) {
            return false;
        }
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="AuthService.java")
    report = orchestrator.analyze(submission)

    # 1. Must NOT trigger nesting warning (CWE-1075)
    nesting_findings = [f for f in report.findings if f.cwe_id == "CWE-1075"]
    assert len(nesting_findings) == 0, f"Nesting warning falsely triggered: {nesting_findings}"

    # 2. MUST trigger SQL injection (CWE-89)
    sqli_findings = [f for f in report.findings if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) >= 1, "SQL Injection (CWE-89) was not detected!"
    assert any("SQL" in f.title for f in sqli_findings)


def test_3_excessive_nested_control_structures_trigger_warning(orchestrator):
    """
    Test 3: Genuinely excessive nested control structures (e.g. OrderProcessor.java) trigger a nesting warning.
    Verifies that control flow nesting >= 4 (try -> for -> if -> if) triggers CWE-1075,
    reporting measured depth, threshold of 3, and enclosing constructs chain.
    """
    sample_file = Path("evaluation/samples/java/OrderProcessor.java")
    assert sample_file.exists(), "OrderProcessor.java sample file must exist"
    code = sample_file.read_text(encoding="utf-8")

    submission = CodeSubmission(code=code, language="java", filename="OrderProcessor.java")
    report = orchestrator.analyze(submission)

    nesting_findings = [f for f in report.findings if f.cwe_id == "CWE-1075"]
    assert len(nesting_findings) >= 1, "Excessive nesting was not detected in OrderProcessor.java!"

    f = nesting_findings[0]
    assert "Excessive" in f.title
    assert "Nesting" in f.title
    assert f.category == "Code Smell: Deep Nesting"
    assert "depth: 4" in f.description or "levels deep" in f.title
    assert "threshold of 3" in f.description or "threshold" in f.description
    assert "try" in f.description and "for" in f.description and "if" in f.description
    assert f.line_start == 11


def test_4_path_traversal_flagged(orchestrator):
    """
    Test 4: new File("uploads/" + filename) is flagged for path traversal risk (CWE-22).
    """
    code = """
package com.example.files;

import java.io.File;

public class FileStorageService {
    public File getUploadedFile(String filename) {
        // Direct concatenation of user-supplied filename without normalization
        File file = new File("uploads/" + filename);
        return file;
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="FileStorageService.java")
    report = orchestrator.analyze(submission)

    path_findings = [f for f in report.findings if f.cwe_id == "CWE-22"]
    assert len(path_findings) >= 1, "Path Traversal (CWE-22) was not detected!"
    assert any("Path" in f.title or "File" in f.title for f in path_findings)


def test_5_hardcoded_api_key_detected(orchestrator):
    """
    Test 5: A hardcoded API key is detected (CWE-798).
    """
    code = """
package com.example.client;

public class PaymentGatewayClient {
    private static final String API_KEY = "my_secret_key_123";

    public void processPayment() {
        System.out.println("Processing with key: " + API_KEY);
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="PaymentGatewayClient.java")
    report = orchestrator.analyze(submission)

    secret_findings = [f for f in report.findings if f.cwe_id == "CWE-798"]
    assert len(secret_findings) >= 1, "Hardcoded API Key (CWE-798) was not detected!"
    assert any("API Key" in f.title or "Secret" in f.title for f in secret_findings)


def test_6_parameterized_sql_does_not_trigger_sqli(orchestrator):
    """
    Test 6: Parameterized SQL does not trigger SQL injection without additional evidence.
    Verifies that java.sql.PreparedStatement with bind variables does NOT trigger CWE-89.
    """
    code = """
package com.example.auth;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SecureAuthService {
    public boolean authenticate(Connection conn, String username, String password) throws SQLException {
        String sql = "SELECT id FROM users WHERE username = ? AND password = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, password);
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next();
            }
        }
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="SecureAuthService.java")
    report = orchestrator.analyze(submission)

    sqli_findings = [f for f in report.findings if f.cwe_id == "CWE-89"]
    assert len(sqli_findings) == 0, f"Parameterized query falsely flagged as SQL injection: {sqli_findings}"


def test_7_scans_do_not_reuse_stale_findings(orchestrator):
    """
    Test 7: A new scan does not reuse stale findings from previous scans.
    Performs scan on vulnerable code, then on clean code (StringUtils.java),
    verifying complete isolation and zero leftover findings.
    """
    vulnerable_code = """
package com.example.bad;
import java.io.File;
public class BadService {
    public static final String API_KEY = "my_secret_key_123";
    public File getFile(String filename) {
        return new File("uploads/" + filename);
    }
}
"""
    sub_vuln = CodeSubmission(code=vulnerable_code, language="java", filename="BadService.java")
    report_vuln = orchestrator.analyze(sub_vuln)
    assert len(report_vuln.findings) >= 2, "Vulnerable code should have findings"

    # Now scan clean baseline
    clean_sample = Path("evaluation/samples/java/StringUtils.java")
    assert clean_sample.exists()
    clean_code = clean_sample.read_text(encoding="utf-8")

    sub_clean = CodeSubmission(code=clean_code, language="java", filename="StringUtils.java")
    report_clean = orchestrator.analyze(sub_clean)

    # Clean code must have 0 findings and 100 health score
    assert len(report_clean.findings) == 0, f"Clean scan leaked stale findings: {report_clean.findings}"
    assert report_clean.health_score == 100
    assert report_clean.verdict == "APPROVED"


def test_8_java_remediation_language_awareness(orchestrator):
    """
    Test 8: Language-aware remediation for Java findings.
    Verifies that Java findings receive Java remediation (PreparedStatement, System.getenv,
    File canonical checks, JUnit 5 unit tests with @Test, // comments)
    and NEVER Python guard clauses (if not is_valid_input) or Python # comments.
    """
    code = """
package com.example.mixed;

import java.io.File;
import java.util.List;

public class OrderController {
    private static final String API_KEY = "my_secret_key_123";

    public File download(String filename) {
        return new File("uploads/" + filename);
    }

    public void process(List<String> items) {
        try {
            for (String a : items) {
                while (a != null) {
                    if (a.length() > 0) {
                        if (a.startsWith("ITEM")) {
                            System.out.println(a);
                        }
                    }
                }
            }
        } catch (Exception e) {
        }
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="OrderController.java")
    report = orchestrator.analyze(submission)

    assert len(report.findings) >= 3

    for finding in report.findings:
        rem = finding.remediation
        assert rem is not None, f"Finding {finding.id} has no remediation"

        # 1. No Python '#' comments at start of lines in corrected_snippet
        for line in rem.corrected_snippet.splitlines():
            stripped = line.strip()
            assert not stripped.startswith("#"), (
                f"Finding {finding.id} has Python comment in Java remediation: '{line}'"
            )

        # 2. Never return Python guard clauses
        assert "if not is_valid_input" not in rem.corrected_snippet, (
            f"Finding {finding.id} returned Python guard clause for Java code!"
        )

        # 3. Unit test code must use JUnit 5 (@Test), not pytest or Python def
        assert "@Test" in rem.unit_test_code, (
            f"Finding {finding.id} unit test is not JUnit 5: {rem.unit_test_code}"
        )
        assert "import pytest" not in rem.unit_test_code, (
            f"Finding {finding.id} unit test contains pytest for Java!"
        )
        assert "def test_" not in rem.unit_test_code, (
            f"Finding {finding.id} unit test contains Python def for Java!"
        )


def test_nested_resource_management_try_with_resources_no_nesting_warning(orchestrator):
    """
    Test 9: Nested resource-management constructs (try-with-resources) do NOT trigger an excessive nesting warning.
    Verifies that nested try (...) blocks for Connection, PreparedStatement, and ResultSet
    are properly distinguished from conditional/loop branching and do NOT trigger CWE-1075.
    """
    code = """
package com.example.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDAO {
    public String findEmail(String username) throws SQLException {
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:users.db")) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT email FROM users WHERE username = ?")) {
                stmt.setString(1, username);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString("email");
                    }
                }
            }
        }
        return null;
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="UserDAO.java")
    report = orchestrator.analyze(submission)

    nesting_findings = [f for f in report.findings if f.cwe_id == "CWE-1075"]
    assert len(nesting_findings) == 0, (
        f"Legitimate nested try-with-resources triggered false-positive nesting warnings: {nesting_findings}"
    )


def test_password_hashing_recommends_argon2id_or_bcrypt(orchestrator):
    """
    Test 10: Password hashing findings recommend Argon2id or bcrypt, never plain SHA-256 or MD5.
    Verifies that remediation suggestions explicitly recommend memory-hard KDFs for password storage.
    """
    code = """
package com.example.service;

import java.security.MessageDigest;
import java.util.Base64;

public class UserService {
    public String hashUserPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return Base64.getEncoder().encodeToString(md.digest(password.getBytes()));
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="UserService.java")
    report = orchestrator.analyze(submission)

    crypto_findings = [f for f in report.findings if f.cwe_id == "CWE-328"]
    assert len(crypto_findings) >= 1, "Expected weak hash finding for MD5 password hashing"

    f = crypto_findings[0]
    rem = f.remediation
    assert rem is not None
    # Must recommend Argon2id or bcrypt
    assert "Argon2" in rem.corrected_snippet or "bcrypt" in rem.corrected_snippet
    # Must not recommend plain SHA-256 for passwords
    assert "never plain MD5 or SHA-256" in rem.corrected_snippet or "Argon2PasswordEncoder" in rem.corrected_snippet


def test_appropriate_cwe_classifications_not_default_cwe1075(orchestrator):
    """
    Test 11: Verify appropriate classification for code-quality findings instead of automatically assigning CWE-1075.
    - Wildcard imports -> CWE-710
    - Excessive nesting -> CWE-1075
    """
    code = """
package com.example.test;

import java.util.*;
import java.io.*;

public class CleanTest {
    public int compute() {
        return 42;
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="CleanTest.java")
    report = orchestrator.analyze(submission)

    wildcard_findings = [f for f in report.findings if "Wildcard" in f.title]
    assert len(wildcard_findings) >= 1
    for wf in wildcard_findings:
        assert wf.cwe_id == "CWE-710", f"Wildcard import must be CWE-710, got: {wf.cwe_id}"


def test_return_statements_and_url_literals_no_nesting_warning(orchestrator):
    """
    Test 12: Regression test verifying that return statements, URL literals,
    string concatenation, and nested method arguments do NOT falsely trigger nesting findings.
    """
    code = """
package com.example.net;

import java.net.URI;

public class NetworkClient {
    public String buildEndpointUrl(String baseHost, String tenantId, String serviceKey) {
        // Long URL literal with parameter query strings and nested method invocations
        String url = "https://identity.vault.service.internal:8443/v2/tokens"
            + "?client_id=" + baseHost
            + "&scope=read%20write%20admin"
            + "&redirect_uri=https%3A%2F%2Fgateway.internal%2Fcallback";

        return String.format(
            "%s/%s/%s",
            url.trim().toLowerCase(),
            tenantId.replace("-", "_"),
            serviceKey.substring(0, Math.min(serviceKey.length(), 8))
        );
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="NetworkClient.java")
    report = orchestrator.analyze(submission)

    nesting_findings = [f for f in report.findings if f.cwe_id == "CWE-1075"]
    assert len(nesting_findings) == 0, f"Expected 0 nesting findings, but got: {nesting_findings}"


def test_java_wildcard_import_suggests_explicit_used_classes(orchestrator):
    """
    Test 13: Java wildcard import detection:
    - Classified as code-quality finding (AgentType.CODE_ANALYSIS, CWE-710), NOT a security finding.
    - Identifies and suggests explicit imports for classes actually used (File, IOException).
    - Does NOT provide cyclomatic-complexity / guard-clause remediation.
    """
    code = """
package com.example.storage;

import java.io.*;

public class LocalStorage {
    public boolean checkExists(String path) throws IOException {
        File file = new File("safe_dir/test.txt");
        if (!file.exists()) {
            throw new IOException("Missing file: " + file.getName());
        }
        return true;
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="LocalStorage.java")
    report = orchestrator.analyze(submission)

    wildcard_findings = [f for f in report.findings if "Wildcard" in f.title]
    assert len(wildcard_findings) == 1, "Expected 1 wildcard finding for java.io.*"

    wf = wildcard_findings[0]
    # Classified as code quality, not security
    assert wf.agent_type == AgentType.CODE_ANALYSIS
    assert wf.cwe_id == "CWE-710"
    assert wf.category == "Code Smell: Wildcard Import"

    rem = wf.remediation
    assert rem is not None
    # Must suggest explicit imports for classes actually used
    assert "import java.io.File;" in rem.corrected_snippet
    assert "import java.io.IOException;" in rem.corrected_snippet
    # Must NOT suggest unrelated guard clauses / cyclomatic complexity
    assert "guard clause" not in rem.corrected_snippet.lower()
    assert "is_valid" not in rem.corrected_snippet.lower()
    assert "@Test" in rem.unit_test_code


def test_crypto_unknown_purpose_explains_context_dependency(orchestrator):
    """
    Test 14: When hashing purpose is unknown/generic, remediation explains context-dependency:
    - Case 1: Passwords -> Argon2id or bcrypt (never plain SHA-256 or MD5)
    - Case 2: Data digests -> SHA-256 or SHA-512
    """
    code = """
package com.example.crypto;

import java.security.MessageDigest;

public class HashCalculator {
    public byte[] computePayloadDigest(byte[] rawData) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(rawData);
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="HashCalculator.java")
    report = orchestrator.analyze(submission)

    crypto_findings = [f for f in report.findings if f.cwe_id == "CWE-328"]
    assert len(crypto_findings) >= 1

    cf = crypto_findings[0]
    rem = cf.remediation
    assert rem is not None
    assert "Context-dependent" in rem.corrected_snippet
    assert "Argon2id" in rem.corrected_snippet or "bcrypt" in rem.corrected_snippet
    assert "SHA-256" in rem.corrected_snippet


def test_credential_detection_masks_secret_and_recommends_secrets_manager(orchestrator):
    """
    Test 15: Credential detection:
    - Flags CWE-798.
    - Never reproduces raw plaintext secret in evidence, original snippet, or diff.
    - Recommends environment variables AND dedicated secrets manager.
    - Explains that environment variables alone do not mitigate all secret-leakage risks.
    """
    raw_secret = "SuperSecretDbPassword12345!"
    code = f"""
package com.example.config;

public class DatabaseConfig {{
    private static final String DB_PASSWORD = "{raw_secret}";

    public String getPassword() {{
        return DB_PASSWORD;
    }}
}}
"""
    submission = CodeSubmission(code=code, language="java", filename="DatabaseConfig.java")
    report = orchestrator.analyze(submission)

    secret_findings = [f for f in report.findings if f.cwe_id == "CWE-798"]
    assert len(secret_findings) >= 1

    sf = secret_findings[0]
    # Raw secret must NEVER appear in finding evidence
    assert raw_secret not in sf.evidence
    assert "********" in sf.evidence

    rem = sf.remediation
    assert rem is not None
    # Raw secret must NEVER appear in remediation original_snippet or diff
    assert raw_secret not in rem.original_snippet
    assert raw_secret not in rem.diff

    # Recommends Secrets Manager and warns that env vars alone do not resolve all risks
    assert "Secrets Manager" in rem.corrected_snippet or "Vault" in rem.corrected_snippet
    assert "Environment variables alone" in rem.corrected_snippet or "process memory" in rem.corrected_snippet


def test_plaintext_password_storage_cwe312_detected(orchestrator):
    """
    Test 16: Cleartext storage of passwords triggers CWE-312:
    - Detects unhashed password persistence.
    - Recommends hashing with Argon2id or bcrypt before persistence.
    """
    code = """
package com.example.user;

public class RegistrationService {
    public void registerUser(String username, String plainPassword) {
        User user = new User(username);
        // Direct assignment without hashing (CWE-312)
        user.setPassword(plainPassword);
        userRepository.save(user);
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="RegistrationService.java")
    report = orchestrator.analyze(submission)

    cwe256_findings = [f for f in report.findings if f.cwe_id in ["CWE-256", "CWE-312"]]
    assert len(cwe256_findings) >= 1, f"Expected CWE-256/312 finding for plaintext password storage, got: {report.findings}"

    f = cwe256_findings[0]
    assert "Cleartext" in f.title or "Plaintext" in f.title
    assert f.severity == FindingSeverity.CRITICAL

    rem = f.remediation
    assert rem is not None
    assert "Argon2" in rem.corrected_snippet or "bcrypt" in rem.corrected_snippet
    assert "@Test" in rem.unit_test_code


def test_17_vulnerable_user_manager_lines_18_21_60_no_nesting_false_positives(orchestrator):
    """
    Test 17: VulnerableUserManager.java regression test.
    Verifies that lines 18 (db connection call), 21 (dynamic SQL query),
    and 60 (return statement / logging) DO NOT trigger false-positive
    excessive nesting findings (CWE-1075), while line 21 correctly flags SQL Injection (CWE-89).
    """
    lines = [
        "package com.example.service;",
        "",
        "import java.sql.Connection;",
        "import java.sql.DriverManager;",
        "import java.sql.Statement;",
        "import java.sql.ResultSet;",
        "import java.sql.SQLException;",
        "import java.util.logging.Logger;",
        "",
        "public class VulnerableUserManager {",
        "    private static final Logger logger = Logger.getLogger(VulnerableUserManager.class.getName());",
        "",
        "    public String getUser(String username, String password) {",
        "        String result = null;",
        "        try {",
        "            // Line 16",
        "            String dbUrl = \"jdbc:sqlite:users.db\";",
        "            Connection conn = DriverManager.getConnection(dbUrl); // Line 18",
        "            Statement stmt = conn.createStatement();",
        "            // Line 20",
        "            String query = \"SELECT * FROM users WHERE username = '\" + username + \"' AND role = 'USER'\"; // Line 21",
        "            ResultSet rs = stmt.executeQuery(query);",
        "            if (rs.next()) {",
        "                result = rs.getString(\"email\");",
        "            }",
        "        } catch (SQLException e) {",
        "            logger.warning(\"Database error: \" + e.getMessage());",
        "        }",
    ]
    # Pad lines up to line 59
    while len(lines) < 59:
        lines.append("        // Auxiliary processing line")
    # Line 60: return statement
    lines.append("        return result; // Line 60")
    lines.append("    }")
    lines.append("}")

    code = "\n".join(lines)
    submission = CodeSubmission(code=code, language="java", filename="VulnerableUserManager.java")
    report = orchestrator.analyze(submission)

    # 1. Assert NO nesting findings at lines 18, 21, or 60
    nesting_lines = [f.line_start for f in report.findings if f.cwe_id == "CWE-1075"]
    assert 18 not in nesting_lines, f"Line 18 falsely flagged for deep nesting: {report.findings}"
    assert 21 not in nesting_lines, f"Line 21 falsely flagged for deep nesting: {report.findings}"
    assert 60 not in nesting_lines, f"Line 60 falsely flagged for deep nesting: {report.findings}"
    assert len(nesting_lines) == 0, f"Expected 0 nesting findings, found at: {nesting_lines}"

    # 2. Line 21 MUST be flagged for SQL Injection (CWE-89)
    sqli = [f for f in report.findings if f.cwe_id == "CWE-89" and f.line_start == 21]
    assert len(sqli) == 1, f"Expected SQL injection finding at line 21, got: {report.findings}"


def test_18_sha1_password_hashing_detected_and_recommends_argon2id(orchestrator):
    """
    Test 18: SHA-1 used for password hashing triggers CWE-328 and recommends Argon2id or bcrypt.
    """
    code = """
package com.example.auth;

import java.security.MessageDigest;

public class Sha1Authenticator {
    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(password.getBytes());
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="Sha1Authenticator.java")
    report = orchestrator.analyze(submission)

    crypto_findings = [f for f in report.findings if f.cwe_id == "CWE-328"]
    assert len(crypto_findings) >= 1

    cf = crypto_findings[0]
    rem = cf.remediation
    assert rem is not None
    assert "Argon2" in rem.corrected_snippet or "bcrypt" in rem.corrected_snippet
    assert "never plain MD5 or SHA-256" in rem.corrected_snippet or "Argon2PasswordEncoder" in rem.corrected_snippet


def test_19_log_injection_cwe117_detected_and_sanitized(orchestrator):
    """
    Test 19: Log Injection (CWE-117) detection when unneutralized user input is logged.
    Verifies remediation neutralizes CRLF characters.
    """
    code = """
package com.example.logging;

import java.util.logging.Logger;

public class LoginTracker {
    private static final Logger logger = Logger.getLogger(LoginTracker.class.getName());

    public void recordAttempt(String username) {
        // Direct concatenation of user input into logger (CWE-117)
        logger.info("Login attempt received for user: " + username);
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="LoginTracker.java")
    report = orchestrator.analyze(submission)

    log_findings = [f for f in report.findings if f.cwe_id == "CWE-117"]
    assert len(log_findings) >= 1, f"Expected CWE-117 log injection finding, got: {report.findings}"

    f = log_findings[0]
    assert "Log Injection" in f.title or "Improper Output Neutralization" in f.title
    rem = f.remediation
    assert rem is not None
    assert "replaceAll" in rem.corrected_snippet or "replace" in rem.corrected_snippet
    assert "@Test" in rem.unit_test_code


def test_20_safe_path_resolution_and_containment_cwe22(orchestrator):
    """
    Test 20: Path traversal remediation uses safe Java NIO.2 Path resolution,
    normalization, and startsWith containment checking.
    """
    code = """
package com.example.files;

import java.io.File;
import java.io.FileInputStream;

public class DocumentViewer {
    public FileInputStream openDocument(String filename) throws Exception {
        File file = new File("/var/app/data/" + filename);
        return new FileInputStream(file);
    }
}
"""
    submission = CodeSubmission(code=code, language="java", filename="DocumentViewer.java")
    report = orchestrator.analyze(submission)

    path_findings = [f for f in report.findings if f.cwe_id == "CWE-22"]
    assert len(path_findings) >= 1

    rem = path_findings[0].remediation
    assert rem is not None
    # Must recommend safe path resolution, normalization, and containment checks
    assert "normalize()" in rem.corrected_snippet
    assert "startsWith" in rem.corrected_snippet



