# Enterprise Secure Coding Guidelines & Engineering Standards (2025 Edition)

[![Standard](https://img.shields.io/badge/Architecture-Zero%20Trust%20%7C%20Defense--in--Depth-purple.svg)]()
[![OWASP](https://img.shields.io/badge/Security-OWASP%20Top%2010%20(2025)-red.svg)](https://owasp.org/Top10/)
[![Compliance](https://img.shields.io/badge/Framework-NIST%20SP%20800--218-blue.svg)](https://csrc.nist.gov/publications/detail/sp/800-218/final)

This handbook establishes the mandatory baseline software security engineering practices enforced by **AegisAI** across all microservices, distributed backends, REST APIs, and application codebases. It provides language-agnostic requirements with targeted implementation directives for **Python** and **Java (Spring Boot / Jakarta EE)**.

---

## Table of Contents
1. [Core Architectural Principles & Zero Trust Engineering](#1-core-architectural-principles--zero-trust-engineering)
2. [Threat Modeling & Risk Quantification (STRIDE & DREAD)](#2-threat-modeling--risk-quantification-stride--dread)
3. [Input Handling, Whitelisting & Canonicalization Standards](#3-input-handling-whitelisting--canonicalization-standards)
4. [Output Encoding & Context-Aware Escaping](#4-output-encoding--context-aware-escaping)
5. [Enterprise Injection Prevention Architecture](#5-enterprise-injection-prevention-architecture)
6. [Cryptographic Engineering & Key Lifecycle Protocols](#6-cryptographic-engineering--key-lifecycle-protocols)
7. [Authentication, Session Security & Identity Protocols](#7-authentication-session-security--identity-protocols)
8. [Authorization, Multitenancy & Access Control Enforcement](#8-authorization-multitenancy--access-control-enforcement)
9. [Serialization, Deserialization & Data Integrity Defenses](#9-serialization-deserialization--data-integrity-defenses)
10. [Resilient Error Handling, Logging & Security Observability](#10-resilient-error-handling-logging--security-observability)
11. [Supply Chain Security & DevSecOps CI/CD Pipeline Gates](#11-supply-chain-security--devsecops-cicd-pipeline-gates)

---

## 1. Core Architectural Principles & Zero Trust Engineering

Modern software systems must operate under the assumption of perimeter breach. Security controls must be embedded directly into software components:

### 1.1 Zero Trust Mandate: Never Trust, Always Verify
- **No Implicit Trust Zones**: Never assume internal network microservices or internal RPC calls are secure. Every inter-service request must carry verifiable identity tokens (mTLS, signed JWT, or SPIFFE/SPIRE SVIDs).
- **Continuous Validation**: Validate credentials, authorizations, and payload schemas on every transaction, not just at session establishment.
- **Micro-segmentation**: Isolate sensitive business data domains (e.g., payment data, PII, auth services) into dedicated network subnets with strict egress filtering.

### 1.2 Defense in Depth
- Security must never rely on a single defensive gate. If perimeter WAF filtering fails, API gateway route authentication must protect the service; if API gateway authorization fails, method-level `@PreAuthorize` or policy engines must block execution; if application logic fails, database permissions and encryption at rest must limit exposure.

### 1.3 Principle of Least Privilege (PoLP)
- Applications, background workers, and database connections must run with the bare minimum OS permissions, file access rights, and database privileges required.
- Prohibit database users from possessing `SUPERUSER`, `DROP TABLE`, or schema modification rights during application runtime.

### 1.4 Fail Closed (Fail-Safe Defaults)
- When an access decision or parsing step encounters an exception, the system must immediately default to access denial.
- In financial or stateful transactions, exceptions must trigger immediate transaction rollbacks, lock release, and audit emission before returning generic error messages to the client.

### 1.5 Complete Mediation
- Every access request to every secured resource must be validated against current access policies. Never cache authorization decisions across distinct user requests unless using short-lived (e.g. 15-second) cryptographically validated claims.

---

## 2. Threat Modeling & Risk Quantification (STRIDE & DREAD)

Security analysis must begin during software design through structured threat modeling:

### 2.1 The STRIDE Threat Classification Model
| Threat Category | Property Violated | Definition | Example Code Risk |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Authenticity | Impersonating another identity or service | Forged JWT tokens with `alg: none` |
| **Tampering** | Integrity | Modifying data in transit or memory | SQL injection altering WHERE clauses |
| **Repudiation** | Non-repudiation | Inability to prove an action occurred | Missing audit logs for administrative role grants |
| **Information Disclosure** | Confidentiality | Exposing sensitive data to unauthorized parties | Stack traces with connection strings in HTTP 500 |
| **Denial of Service** | Availability | Exhausting CPU, memory, or network resources | ReDoS polynomial regex or unconstrained uploads |
| **Elevation of Privilege** | Authorization | Gaining unauthorized administrative capabilities | IDOR allowing normal user to update admin records |

### 2.2 DREAD Risk Scoring Formula
Risk severity is quantified using the standard DREAD algorithm:
$$\text{Risk Score} = \frac{\text{Damage} + \text{Reproducibility} + \text{Exploitability} + \text{Affected Users} + \text{Discoverability}}{5}$$

- **Score Range 8.0 – 10.0 (CRITICAL)**: Immediate automated CI/CD build break; requires remediation before PR merge.
- **Score Range 6.0 – 7.9 (HIGH)**: Merge blocked without explicit Application Security approval.
- **Score Range 4.0 – 5.9 (MEDIUM)**: Requires resolution within current sprint iteration.
- **Score Range 0.0 – 3.9 (LOW / INFO)**: Tracked as technical hygiene debt.

---

## 3. Input Handling, Whitelisting & Canonicalization Standards

Every external input entering an application runtime is considered untrusted and adversarial:

### 3.1 Strict Input Whitelisting (Allowlists over Denylists)
- **Positive Specification**: Define precisely what is allowed (character set, minimum length, maximum length, regex pattern, data type) rather than filtering what is forbidden.
- **Schema Enforcement**: Use declarative schema validators:
  - **Python**: Pydantic v2 models (`strict=True`, `min_length`, `max_length`, `regex`).
  - **Java**: Jakarta Bean Validation (`@NotNull`, `@Size(min=1, max=100)`, `@Pattern`, `@Email`).

### 3.2 Canonicalization Before Validation
- Attackers exploit alternative character representations (e.g., `%2e%2e%2f` for `../`, Unicode fullwidth slashes, null bytes `%00`).
- **Path Canonicalization**:
  - Python: `Path(filename).resolve()` and verify `target.is_relative_to(base_dir)`.
  - Java: `Paths.get(filename).toRealPath()` and verify `path.startsWith(baseDir)`.
- **Unicode Normalization**: Apply Unicode Normalization Form C (`NFC` or `NFKC`) prior to validating user strings against regex allowlists to prevent homograph attacks.

### 3.3 ReDoS Prevention (Regular Expression Denial of Service)
- Never compile regular expressions with nested quantifiers (e.g., `(a+)+$` or `([a-zA-Z0-9]+)*$`).
- In Python, evaluate regexes with execution timeouts or use Google's `re2` library which guarantees linear-time $O(N)$ evaluation.

---

## 4. Output Encoding & Context-Aware Escaping

Output encoding neutralizes untrusted data before it is rendered into a dynamic interpreter (HTML, JavaScript, CSS, SQL, LDAP):

### 4.1 Context-Specific Encoders
Untrusted data must be encoded according to the specific syntactic context where it will be placed:

1. **HTML Body Context**: Convert `&` $\to$ `&amp;`, `<` $\to$ `&lt;`, `>` $\to$ `&gt;`, `"` $\to$ `&quot;`, `'` $\to$ `&#x27;`.
2. **HTML Attribute Context**: Apply aggressive alphanumeric encoding; encode all non-alphanumeric characters with `&#xHH;` hex format.
3. **JavaScript Execution Context**: Never interpolate user input directly into `<script>` blocks or `eval()`. Use `JSON.stringify()` combined with Unicode escaping of `<` (`\u003c`) to prevent script breakout.
4. **CSS Context**: Restrict dynamic CSS values to strict regex-validated color codes or coordinate numbers; never allow user strings into `url(...)` properties.
5. **URL Context**: Encode query parameter components using standard percent-encoding (`urllib.parse.quote` in Python, `URLEncoder.encode` in Java).

---

## 5. Enterprise Injection Prevention Architecture

### 5.1 SQL & NoSQL Parameterization
- **Fundamental Rule**: SQL query structure and user data must never be concatenated into the same string.
- In **Python**:
  ```python
  # DB-API 2.0 Parameterized Query
  cursor.execute("SELECT id, email FROM accounts WHERE status = ? AND tier = ?", (status, tier))
  ```
- In **Java**:
  ```java
  // JDBC Parameterized PreparedStatement
  try (PreparedStatement ps = conn.prepareStatement("SELECT id, email FROM accounts WHERE status = ? AND tier = ?")) {
      ps.setString(1, status);
      ps.setString(2, tier);
      try (ResultSet rs = ps.executeQuery()) { ... }
  }
  ```

### 5.2 OS Command Execution Safety
- Prohibit shell execution (`shell=True` in Python, `sh -c` or `cmd.exe /c` in Java).
- Use array-based process creation where the executable path and arguments are passed as discrete vector elements:
  - Python: `subprocess.run(["/usr/bin/ping", "-c", "1", ip_address], shell=False, check=True)`
  - Java: `new ProcessBuilder("/usr/bin/ping", "-c", "1", ipAddress).start()`

### 5.3 XML External Entity (XXE) Prevention
- Disallow DTDs and external entity expansion on all XML factories:
  - Python: Standardize on `defusedxml` package.
  - Java: Set `FEATURE_SECURE_PROCESSING = true`, `disallow-doctype-decl = true`, and disable general/parameter external entities.

---

## 6. Cryptographic Engineering & Key Lifecycle Protocols

### 6.1 Password Storage Standards (2025 Edition)
General-purpose cryptographic hashes (MD5, SHA-1, SHA-256) are **strictly forbidden** for credential storage due to susceptibility to offline GPU/ASIC cracking.

| Algorithm | Recommended Parameters (2025 Standard) | Use Case |
| :--- | :--- | :--- |
| **Argon2id** (Primary) | Memory: 64 MB (65,536 KiB), Iterations: 3, Parallelism: 4 | Master credential storage |
| **Bcrypt** (Alternative) | Work Factor (Cost): 12 (4,096 rounds) | Legacy enterprise compatibility |
| **PBKDF2-HMAC-SHA256** | Iterations: minimum 600,000 | FIPS-140 compliance requirements |

### 6.2 Data at Rest Encryption: AES-256-GCM
- **Authenticated Encryption with Associated Data (AEAD)**: Standardize on AES-256-GCM.
- **Unique Nonce Requirement**: Generate a cryptographically secure 96-bit (12-byte) initialization vector/nonce for every encryption operation using `os.urandom(12)` or `SecureRandom.getInstanceStrong()`.
- **Nonce Reuse Catastrophe**: Never encrypt two different plaintexts with the same key and nonce combination.

### 6.3 Secure Key Management & Secret Externalization
- **Zero Secrets in Code**: Hardcoded API keys, JWT secrets, passwords, and private keys are classified as `CRITICAL` merge-blocking vulnerabilities.
- **External Secret Vaults**: Inject secrets at runtime via environment variables, HashiCorp Vault, AWS Secrets Manager, or Kubernetes Secrets.
- **Key Rotation**: Implement automated 90-day cryptographic key rotation with dual-key decryption support during transition windows.

---

## 7. Authentication, Session Security & Identity Protocols

### 7.1 Modern Session Security Standards
- **Cookie Flags**:
  - `HttpOnly = true`: Mitigates session token theft via Cross-Site Scripting (XSS).
  - `Secure = true`: Enforces transmission strictly over HTTPS/TLS.
  - `SameSite = Strict` (or `Lax` for OAuth redirect endpoints): Prevents Cross-Site Request Forgery (CSRF).
- **Session Lifecycles**: Enforce idle timeouts (15 minutes) and absolute session expiration (12 hours). Invalidate server-side session state immediately on logout.

### 7.2 JSON Web Token (JWT) Security Rules
- **Explicit Algorithm Whitelisting**: Never accept `alg: "none"`. Reject token headers specifying algorithms outside an approved whitelist (e.g. `["RS256"]` or `["HS256"]`).
- **Cryptographic Key Separation**: For asymmetric JWTs (RS256/ES256), the authorization server signs with the private key; resource servers verify with the public key.
- **Standard Claims Verification**: Mandatory verification of `exp` (expiration), `nbf` (not before), `iat` (issued at), `iss` (issuer), and `aud` (audience).

### 7.3 Brute-Force & Credential Stuffing Defenses
- Enforce token-bucket rate limiting on all login, password reset, and MFA challenge endpoints (maximum 5 attempts per IP per minute).
- Implement progressive delay (tarpitting) and account lockouts after consecutive failed attempts.

---

## 8. Authorization, Multitenancy & Access Control Enforcement

### 8.1 Insecure Direct Object Reference (IDOR) Elimination
- When fetching, updating, or deleting records by ID, always bind the database query to the authenticated subject's organization ID or user ID:
  $$\text{Query} = \text{Target ID} \land \text{Authenticated Owner ID}$$
- Never trust client-supplied account IDs, tenant IDs, or role assertions in request bodies.

### 8.2 Declarative Role & Attribute-Based Access Control
- Enforce method-level authorization:
  - Spring Boot: `@PreAuthorize("hasRole('ADMIN') or @tenantSecurity.canAccess(#tenantId)")`
  - FastAPI: `Depends(require_permissions(["billing:read"]))`

### 8.3 Server-Side Request Forgery (SSRF) Egress Defense
- For applications fetching remote URLs (webhooks, avatar importers, integrations):
  1. Validate that the scheme is strictly `https://`.
  2. Resolve the DNS hostname to an IP address before establishing the connection.
  3. Validate that the resolved IP does not belong to RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), or IPv6 equivalents.
  4. Disable automatic HTTP redirect following, or re-validate redirect destination IPs.

---

## 9. Serialization, Deserialization & Data Integrity Defenses

### 9.1 Native Deserialization Prohibition
- Native object serialization mechanisms in Python (`pickle`, `shelve`, `marshal`) and Java (`ObjectInputStream`) are fundamentally unsafe when processing data from untrusted boundaries.
- **Gadget Chains**: Deserialization of attacker-controlled payloads triggers arbitrary method execution via standard classpath libraries (e.g. Apache Commons Collections, Spring Framework, Python `__reduce__`), leading to immediate Remote Code Execution (RCE).

### 9.2 Safe Serialization Standard
- Standardize on structured data interchange formats:
  - **JSON**: Parsed with Pydantic in Python; Jackson with polymorphic typing deactivated (`mapper.deactivateDefaultTyping()`) in Java.
  - **Protocol Buffers / gRPC**: Enforces strict binary schema compilation and type safety.
- If native Java serialization is non-negotiable for legacy systems, apply Java 9+ `ObjectInputFilter` with a strict whitelist of allowed classes.

---

## 10. Resilient Error Handling, Logging & Security Observability

### 10.1 Safe Error Handling Policies
- **Catch Specific Exceptions**: Never catch generic `Exception`, `Throwable`, or write bare `except: pass`.
- **Zero Information Disclosure**: Internal database connection strings, SQL query fragments, server filesystem paths, and full stack traces must never appear in HTTP error responses to clients.
- Return standardized, generic RFC 7807 Problem Details JSON:
  ```json
  {
    "type": "https://api.example.com/errors/invalid-request",
    "title": "Invalid Request Parameter",
    "status": 400,
    "detail": "The provided input did not satisfy schema requirements.",
    "instance": "/api/v1/invoices/98213"
  }
  ```

### 10.2 Security Logging Standards & Sensitive Data Redaction
- **Mandatory Audit Events**:
  - Successful and failed authentication attempts.
  - Privilege changes, password resets, and MFA modifications.
  - Authorization rejections (access denied).
  - High-value financial transactions and administrative mutations.
- **Redaction Policy**: Filter, mask, or hash sensitive parameters before logging:
  - Passwords, credit card numbers (PAN), CVVs, authorization tokens, social security numbers, and private cryptographic keys.
- **CRLF Injection Defense**: Strip carriage return (`\r`) and line feed (`\n`) characters from log arguments to prevent log forging and SIEM log injection attacks (`CWE-117`).

---

## 11. Supply Chain Security & DevSecOps CI/CD Pipeline Gates

### 11.1 Dependency Verification & SBOM
- **Cryptographic Hash Pinning**: Pin all dependencies with SHA-256 hashes in `requirements.txt` (`--require-hashes`) or Maven lockfiles.
- **Automated CVE Scanning**: Integrate `pip-audit`, `safety`, and `dependency-check-maven` into every CI build.
- **Software Bill of Materials (SBOM)**: Generate CycloneDX or SPDX SBOM manifests on every production release build.

### 11.2 Automated Merge Gate Policy
The **AegisAI PR Summary Agent** enforces automated merge gate verdicts:
- **`APPROVED`**: Code health score $\ge 80$, cyclomatic complexity $\le 10$, and 0 Critical / High findings.
- **`CHANGES_REQUESTED`**: Code health score $< 80$ or medium architectural code smells identified.
- **`BLOCKING_SECURITY_RISK`**: Any finding classified under OWASP Top 10 (2025) as `CRITICAL` or `HIGH`.
