# AegisAI Authoritative Source & Compliance Standards Register (2025 Edition)

[![Status](https://img.shields.io/badge/Verification-Verified%20Active-brightgreen.svg)]()
[![Compliance](https://img.shields.io/badge/Standards-OWASP%20%7C%20NIST%20%7C%20CWE%20%7C%20ISO%20%7C%20PCI--DSS-blue.svg)]()
[![Taxonomy](https://img.shields.io/badge/Taxonomy-CWE%20Top%2040-orange.svg)]()

This register documents all authoritative external sources, standards bodies, official documentation URLs, compliance frameworks, and taxonomy mappings ingested into the **AegisAI RAG Knowledge Base**. Every guideline, automated security rule, AST validator check, and remediation template in the platform is strictly grounded in these verified standards.

---

## Table of Contents
1. [OWASP Top 10 (2025 Edition) Canonical Standards](#1-owasp-top-10-2025-edition-canonical-standards)
2. [Common Weakness Enumeration (CWE) Master Taxonomy](#2-common-weakness-enumeration-cwe-master-taxonomy)
3. [SEI CERT Oracle Coding Standard for Java Registry](#3-sei-cert-oracle-coding-standard-for-java-registry)
4. [Python Software Foundation (PSF) & PEP Security Specifications](#4-python-software-foundation-psf--pep-security-specifications)
5. [NIST SP 800-53 Rev. 5 Security Control Mappings](#5-nist-sp-800-53-rev-5-security-control-mappings)
6. [NIST SP 800-218 Secure Software Development Framework (SSDF)](#6-nist-sp-800-218-secure-software-development-framework-ssdf)
7. [ISO/IEC 27001:2022 & ISO/IEC 27002 Annex A Controls](#7-isoiec-270012022--isoiec-27002-annex-a-controls)
8. [PCI-DSS v4.0 Requirement 6 Software Security Standards](#8-pci-dss-v40-requirement-6-software-security-standards)
9. [MITRE ATT&CK Matrix for Enterprise Technique Mappings](#9-mitre-attck-matrix-for-enterprise-technique-mappings)
10. [Framework & Library Official Security Specifications](#10-framework--library-official-security-specifications)

---

## 1. OWASP Top 10 (2025 Edition) Canonical Standards

| Category ID | Category Name | Official OWASP Canonical URL | Status | Last Audit Date | Severity Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A01:2025** | Broken Access Control | [https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) | Active | 2026-10-16 | CRITICAL |
| **A02:2025** | Security Misconfiguration | [https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/) | Active | 2026-10-16 | HIGH |
| **A03:2025** | Software Supply Chain Failures | [https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/) | Active | 2026-10-16 | HIGH |
| **A04:2025** | Cryptographic Failures | [https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/) | Active | 2026-10-16 | CRITICAL |
| **A05:2025** | Injection | [https://owasp.org/Top10/2025/A05_2025-Injection/](https://owasp.org/Top10/2025/A05_2025-Injection/) | Active | 2026-10-16 | CRITICAL |
| **A06:2025** | Insecure Design | [https://owasp.org/Top10/2025/A06_2025-Insecure_Design/](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/) | Active | 2026-10-16 | HIGH |
| **A07:2025** | Authentication Failures | [https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/) | Active | 2026-10-16 | CRITICAL |
| **A08:2025** | Software or Data Integrity Failures | [https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/) | Active | 2026-10-16 | CRITICAL |
| **A09:2025** | Security Logging and Alerting Failures | [https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | Active | 2026-10-16 | MEDIUM |
| **A10:2025** | Mishandling of Exceptional Conditions | [https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/) | Active | 2026-10-16 | MEDIUM |

### Supporting OWASP References:
- **OWASP Cheat Sheet Series**: [https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/)
- **OWASP Application Security Verification Standard (ASVS 4.0.3)**: [https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)
- **OWASP Software Component Verification Standard (SCVS)**: [https://owasp.org/www-project-software-component-verification-standard/](https://owasp.org/www-project-software-component-verification-standard/)
- **OWASP Java Spring Boot Security Cheat Sheet**: [https://cheatsheetseries.owasp.org/cheatsheets/Spring_Security_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Spring_Security_Cheat_Sheet.html)
- **OWASP Python Security Cheat Sheet**: [https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)

---

## 2. Common Weakness Enumeration (CWE) Master Taxonomy

The following 36 Common Weakness Enumerations are formally indexed and recognized by the AegisAI rule evaluation engine:

| CWE ID | Weakness Name | Canonical Definition URL | Primary Category | Typical Vulnerable Pattern |
| :--- | :--- | :--- | :--- | :--- |
| **CWE-22** | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | [https://cwe.mitre.org/data/definitions/22.html](https://cwe.mitre.org/data/definitions/22.html) | A01:2025 | Concatenating user filenames into `open()` or `new File()` |
| **CWE-78** | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html) | A05:2025 | `subprocess.Popen(..., shell=True)` or `Runtime.getRuntime().exec()` |
| **CWE-79** | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | [https://cwe.mitre.org/data/definitions/79.html](https://cwe.mitre.org/data/definitions/79.html) | A05:2025 | Rendering unescaped user strings in HTML templates |
| **CWE-89** | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | [https://cwe.mitre.org/data/definitions/89.html](https://cwe.mitre.org/data/definitions/89.html) | A05:2025 | `cursor.execute(f"SELECT ... {input}")` or JDBC raw concatenation |
| **CWE-90** | Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') | [https://cwe.mitre.org/data/definitions/90.html](https://cwe.mitre.org/data/definitions/90.html) | A05:2025 | Unescaped user credentials formatted into JNDI search filters |
| **CWE-94** | Improper Control of Generation of Code ('Code Injection') | [https://cwe.mitre.org/data/definitions/94.html](https://cwe.mitre.org/data/definitions/94.html) | A08:2025 | `eval()`, `exec()`, or template engine string rendering |
| **CWE-117** | Improper Output Handling for Logs ('Log Injection' / 'CRLF Injection') | [https://cwe.mitre.org/data/definitions/117.html](https://cwe.mitre.org/data/definitions/117.html) | A09:2025 | Writing unescaped `\r\n` characters into application loggers |
| **CWE-200** | Exposure of Sensitive Information to an Unauthorized Actor | [https://cwe.mitre.org/data/definitions/200.html](https://cwe.mitre.org/data/definitions/200.html) | A02:2025 | Returning verbose internal model fields in REST responses |
| **CWE-215** | Information Exposure Through Debug Information | [https://cwe.mitre.org/data/definitions/215.html](https://cwe.mitre.org/data/definitions/215.html) | A02:2025 | `debug=True` in production Flask, FastAPI, or Django |
| **CWE-287** | Improper Authentication | [https://cwe.mitre.org/data/definitions/287.html](https://cwe.mitre.org/data/definitions/287.html) | A07:2025 | Missing authentication checks on mutating API routes |
| **CWE-307** | Improper Restriction of Excessive Authentication Attempts | [https://cwe.mitre.org/data/definitions/307.html](https://cwe.mitre.org/data/definitions/307.html) | A06:2025 | Absence of rate limiting filters on `/login` or `/reset-password` |
| **CWE-326** | Inadequate Encryption Strength | [https://cwe.mitre.org/data/definitions/326.html](https://cwe.mitre.org/data/definitions/326.html) | A04:2025 | Using RSA keys < 2048 bits or DES/3DES 56-bit keys |
| **CWE-327** | Use of a Broken or Risky Cryptographic Algorithm | [https://cwe.mitre.org/data/definitions/327.html](https://cwe.mitre.org/data/definitions/327.html) | A04:2025 | MD5, SHA-1, RC4, or AES in Electronic Codebook (ECB) mode |
| **CWE-328** | Use of Weak Hash | [https://cwe.mitre.org/data/definitions/328.html](https://cwe.mitre.org/data/definitions/328.html) | A04:2025 | Hashing user passwords with plain unsalted SHA-256 or MD5 |
| **CWE-329** | Generation of Predictable IV with CBC Mode | [https://cwe.mitre.org/data/definitions/329.html](https://cwe.mitre.org/data/definitions/329.html) | A04:2025 | Static zero-byte Initialization Vector in symmetric encryption |
| **CWE-330** | Use of Insufficiently Random Values | [https://cwe.mitre.org/data/definitions/330.html](https://cwe.mitre.org/data/definitions/330.html) | A04:2025 | Using pseudo-random generators for cryptographic keys |
| **CWE-338** | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | [https://cwe.mitre.org/data/definitions/338.html](https://cwe.mitre.org/data/definitions/338.html) | A04:2025 | `random.random()` or `new Random()` for session tokens |
| **CWE-345** | Insufficient Verification of Data Authenticity | [https://cwe.mitre.org/data/definitions/345.html](https://cwe.mitre.org/data/definitions/345.html) | A07:2025 | Accepting unverified signatures or tokens across boundaries |
| **CWE-347** | Improper Verification of Cryptographic Signature | [https://cwe.mitre.org/data/definitions/347.html](https://cwe.mitre.org/data/definitions/347.html) | A07:2025 | `jwt.decode(..., verify=False)` or accepting `alg: none` |
| **CWE-352** | Cross-Site Request Forgery (CSRF) | [https://cwe.mitre.org/data/definitions/352.html](https://cwe.mitre.org/data/definitions/352.html) | A01:2025 | Disabling CSRF protection in cookie-authenticated web sessions |
| **CWE-390** | Detection of Error Condition Without Action | [https://cwe.mitre.org/data/definitions/390.html](https://cwe.mitre.org/data/definitions/390.html) | A10:2025 | Empty `except:` or `catch (Exception e) {}` blocks |
| **CWE-400** | Uncontrolled Resource Consumption | [https://cwe.mitre.org/data/definitions/400.html](https://cwe.mitre.org/data/definitions/400.html) | A06:2025 | Unbounded file uploads, infinite regex backtracking (ReDoS) |
| **CWE-404** | Improper Resource Shutdown or Release | [https://cwe.mitre.org/data/definitions/404.html](https://cwe.mitre.org/data/definitions/404.html) | A10:2025 | Missing connection closure outside `try-with-resources` |
| **CWE-434** | Unrestricted Upload of File with Dangerous Type | [https://cwe.mitre.org/data/definitions/434.html](https://cwe.mitre.org/data/definitions/434.html) | A01:2025 | Uploading executable scripts (.py, .jsp, .sh) to web roots |
| **CWE-502** | Deserialization of Untrusted Data | [https://cwe.mitre.org/data/definitions/502.html](https://cwe.mitre.org/data/definitions/502.html) | A08:2025 | `pickle.loads()`, `yaml.load()` without SafeLoader, `ObjectInputStream` |
| **CWE-532** | Insertion of Sensitive Information into Log File | [https://cwe.mitre.org/data/definitions/532.html](https://cwe.mitre.org/data/definitions/532.html) | A09:2025 | `logger.info(f"Password: {password}")` or logging JWT tokens |
| **CWE-611** | Improper Restriction of XML External Entity Reference ('XXE') | [https://cwe.mitre.org/data/definitions/611.html](https://cwe.mitre.org/data/definitions/611.html) | A05:2025 | Parsing XML without disabling DTDs or external entities |
| **CWE-639** | Authorization Bypass Through User-Controlled Key ('IDOR') | [https://cwe.mitre.org/data/definitions/639.html](https://cwe.mitre.org/data/definitions/639.html) | A01:2025 | Accessing database records directly via `{id}` without ownership checks |
| **CWE-755** | Improper Handling of Exceptional Conditions | [https://cwe.mitre.org/data/definitions/755.html](https://cwe.mitre.org/data/definitions/755.html) | A10:2025 | Masking transaction or permission errors with generic handlers |
| **CWE-798** | Use of Hard-coded Credentials | [https://cwe.mitre.org/data/definitions/798.html](https://cwe.mitre.org/data/definitions/798.html) | A07:2025 | Static API keys, database passwords, or JWT secrets in code |
| **CWE-862** | Missing Authorization | [https://cwe.mitre.org/data/definitions/862.html](https://cwe.mitre.org/data/definitions/862.html) | A01:2025 | Missing `@PreAuthorize` or authentication dependencies on admin routes |
| **CWE-918** | Server-Side Request Forgery ('SSRF') | [https://cwe.mitre.org/data/definitions/918.html](https://cwe.mitre.org/data/definitions/918.html) | A01:2025 | Fetching arbitrary user-provided URLs without egress filtering |
| **CWE-942** | Permissive Cross-Domain Policy with Untrusted Domains ('CORS') | [https://cwe.mitre.org/data/definitions/942.html](https://cwe.mitre.org/data/definitions/942.html) | A02:2025 | `allow_origins=["*"]` combined with `allow_credentials=True` |
| **CWE-1059** | Incomplete Documentation of Security Vulnerabilities | [https://cwe.mitre.org/data/definitions/1059.html](https://cwe.mitre.org/data/definitions/1059.html) | A06:2025 | Architectural design flaws and unvalidated assumptions |
| **CWE-1104** | Use of Unmaintained Third-Party Components | [https://cwe.mitre.org/data/definitions/1104.html](https://cwe.mitre.org/data/definitions/1104.html) | A03:2025 | Using abandoned libraries with unpatched security advisories |
| **CWE-1395** | Dependency on Vulnerable Third-Party Component | [https://cwe.mitre.org/data/definitions/1395.html](https://cwe.mitre.org/data/definitions/1395.html) | A03:2025 | Packages with known CVSS >= 7.0 CVE records |

---

## 3. SEI CERT Oracle Coding Standard for Java Registry

The SEI CERT Java Coding Standard provides formal rules to ensure the security, reliability, and safety of Java applications.

| CERT Rule | Standard Title | Canonical URL | Rule Description | Compliance Check in AegisAI |
| :--- | :--- | :--- | :--- | :--- |
| **IDS00-J** | Prevent SQL Injection | [https://wiki.sei.cmu.edu/confluence/display/java/IDS00-J.+Prevent+SQL+injection](https://wiki.sei.cmu.edu/confluence/display/java/IDS00-J.+Prevent+SQL+injection) | Never concatenate untrusted strings into JDBC or JPA queries. | PreparedStatement enforcement |
| **IDS01-J** | Normalize strings before validating them | [https://wiki.sei.cmu.edu/confluence/display/java/IDS01-J.+Normalize+strings+before+validating+them](https://wiki.sei.cmu.edu/confluence/display/java/IDS01-J.+Normalize+strings+before+validating+them) | Use `java.text.Normalizer` prior to checking character whitelists. | Unicode Normalization check |
| **IDS07-J** | Sanitize untrusted data passed to Runtime.exec() | [https://wiki.sei.cmu.edu/confluence/display/java/IDS07-J.+Sanitize+untrusted+data+passed+to+the+Runtime.exec%28%29+method](https://wiki.sei.cmu.edu/confluence/display/java/IDS07-J.+Sanitize+untrusted+data+passed+to+the+Runtime.exec%28%29+method) | Prohibit raw shell strings; use `ProcessBuilder` with argument arrays. | ProcessBuilder validation |
| **IDS16-J** | Prevent XML External Entity (XXE) Injection | [https://wiki.sei.cmu.edu/confluence/display/java/IDS16-J.+Prevent+XML+External+Entity+Injection](https://wiki.sei.cmu.edu/confluence/display/java/IDS16-J.+Prevent+XML+External+Entity+Injection) | Set `disallow-doctype-decl` to true on all XML factory builders. | XXE feature flag verification |
| **FIO16-J** | Canonicalize path names before validation | [https://wiki.sei.cmu.edu/confluence/display/java/FIO16-J.+Canonicalize+path+names+before+validating+them](https://wiki.sei.cmu.edu/confluence/display/java/FIO16-J.+Canonicalize+path+names+before+validating+them) | Call `Path.toRealPath()` or `Path.normalize()` and verify `startsWith()`. | Path traversal resolution |
| **SER00-J** | Enable serialization filters | [https://wiki.sei.cmu.edu/confluence/display/java/SER00-J.+Enable+serialization+filters](https://wiki.sei.cmu.edu/confluence/display/java/SER00-J.+Enable+serialization+filters) | Apply `ObjectInputFilter` on all `ObjectInputStream` instances. | Serialization filter check |
| **SEC01-J** | Do not grant excessive privileges | [https://wiki.sei.cmu.edu/confluence/display/java/SEC01-J.+Do+not+grant+excessive+privileges](https://wiki.sei.cmu.edu/confluence/display/java/SEC01-J.+Do+not+grant+excessive+privileges) | Restrict JVM runtime capabilities and service account permissions. | Least privilege enforcement |
| **SEC06-J** | Do not rely on code that can be tampered with | [https://wiki.sei.cmu.edu/confluence/display/java/SEC06-J.+Do+not+rely+on+code+that+can+be+tampered+with](https://wiki.sei.cmu.edu/confluence/display/java/SEC06-J.+Do+not+rely+on+code+that+can+be+tampered+with) | Use final classes and defensive copying for mutable references. | Immutability analysis |
| **ERR00-J** | Do not suppress or ignore checked exceptions | [https://wiki.sei.cmu.edu/confluence/display/java/ERR00-J.+Do+not+suppress+or+ignore+checked+exceptions](https://wiki.sei.cmu.edu/confluence/display/java/ERR00-J.+Do+not+suppress+or+ignore+checked+exceptions) | Never leave catch blocks empty; log with SLF4J and diagnostic context. | Empty catch block detector |
| **ERR08-J** | Do not catch NullPointerException or RuntimeException | [https://wiki.sei.cmu.edu/confluence/display/java/ERR08-J.+Do+not+catch+NullPointerException+or+any+of+its+ancestors](https://wiki.sei.cmu.edu/confluence/display/java/ERR08-J.+Do+not+catch+NullPointerException+or+any+of+its+ancestors) | Catch specific application exceptions rather than generic `Throwable`. | Exception hierarchy check |
| **MSC02-J** | Generate strong random numbers | [https://wiki.sei.cmu.edu/confluence/display/java/MSC02-J.+Generate+strong+random+numbers](https://wiki.sei.cmu.edu/confluence/display/java/MSC02-J.+Generate+strong+random+numbers) | Use `SecureRandom.getInstanceStrong()` instead of `java.util.Random`. | SecureRandom verification |
| **MSC61-J** | Do not log unvetted sensitive information | [https://wiki.sei.cmu.edu/confluence/display/java/MSC61-J.+Do+not+log+unvetted+sensitive+information](https://wiki.sei.cmu.edu/confluence/display/java/MSC61-J.+Do+not+log+unvetted+sensitive+information) | Strip CRLF characters and mask passwords/credentials in logs. | Sensitive data redaction |

---

## 4. Python Software Foundation (PSF) & PEP Security Specifications

| Specification | Title | URL | Key Security Mandate |
| :--- | :--- | :--- | :--- |
| **PEP 506** | Adding A Secrets Module To The Standard Library | [https://peps.python.org/pep-0506/](https://peps.python.org/pep-0506/) | Mandatory use of `secrets` for tokens, session IDs, and salts. |
| **PEP 675** | Arbitrary Literal String Type | [https://peps.python.org/pep-675/](https://peps.python.org/pep-675/) | Static type safety (`LiteralString`) preventing SQL & command injection. |
| **PEP 484** | Type Hints | [https://peps.python.org/pep-0484/](https://peps.python.org/pep-0484/) | Strict type checking to prevent type confusion vulnerabilities. |
| **PEP 557** | Data Classes | [https://peps.python.org/pep-0557/](https://peps.python.org/pep-0557/) | Immutable data transfer structures with `frozen=True`. |
| **Python AST Module** | Abstract Syntax Tree Processing | [https://docs.python.org/3/library/ast.html](https://docs.python.org/3/library/ast.html) | Safe syntax parsing without code execution or dynamic import. |
| **PSF Security Warnings** | Python Security Considerations | [https://docs.python.org/3/library/security_warnings.html](https://docs.python.org/3/library/security_warnings.html) | Guidance on unsafe pickle, tarfile extraction, and SSL context. |
| **PyPI Audit Standards** | Python Packaging Advisory Database | [https://github.com/pypa/advisory-database](https://github.com/pypa/advisory-database) | Vulnerability database powering `pip-audit` checks. |

---

## 5. NIST SP 800-53 Rev. 5 Security Control Mappings

AegisAI automated findings directly map to the National Institute of Standards and Technology (NIST) Special Publication 800-53 (Revision 5) security controls:

| NIST Control | Control Title | Mapped OWASP 2025 Category | Enforcement Mechanism |
| :--- | :--- | :--- | :--- |
| **AC-3** | Access Enforcement | A01:2025 (Broken Access Control) | Role-based `@PreAuthorize` and ownership authorization validation. |
| **AC-6** | Least Privilege | A01:2025 / A02:2025 | Restricting service permissions, directory bounds, and database roles. |
| **AU-2** | Event Logging | A09:2025 (Logging Failures) | Generating immutable audit trails for authentication and security events. |
| **AU-9** | Protection of Audit Information | A09:2025 (Logging Failures) | Preventing log tampering via CRLF sanitization and credential masking. |
| **IA-2** | Identification and Authentication | A07:2025 (Auth Failures) | MFA enforcement, session lifecycle control, and password hashing standards. |
| **IA-5** | Authenticator Management | A04:2025 / A07:2025 | Argon2id/Bcrypt password storage, forbidding hardcoded credentials. |
| **SC-8** | Transmission Confidentiality | A04:2025 (Cryptographic Failures) | Mandatory TLS 1.3 encryption and HSTS header enforcement. |
| **SC-12** | Cryptographic Key Establishment | A04:2025 (Cryptographic Failures) | External vault management (HashiCorp Vault / AWS KMS) for secrets. |
| **SC-13** | Cryptographic Protection | A04:2025 (Cryptographic Failures) | Enforcing AES-256-GCM AEAD authenticated symmetric encryption. |
| **SC-28** | Protection of Information at Rest | A04:2025 (Cryptographic Failures) | Database field-level encryption with unique nonces. |
| **SI-3** | Malicious Code Protection | A03:2025 (Supply Chain Failures) | Dependency hash checking and automated CVE scanning. |
| **SI-10** | Information Input Validation | A05:2025 (Injection) | Parameterized query placeholders and schema-enforced parsers. |
| **SI-11** | Error Handling | A10:2025 (Exceptional Conditions) | Generic client error responses, diagnostic logging without leaking internals. |

---

## 6. NIST SP 800-218 Secure Software Development Framework (SSDF)

The Secure Software Development Framework (SSDF) defines core activities across the software development lifecycle:

| SSDF Practice | Description | Platform Implementation |
| :--- | :--- | :--- |
| **PO.1** | Define Security Requirements for Software | Grounding reviews in OWASP Top 10 (2025) and CWE Top 25 taxonomies. |
| **PO.3** | Protect Software Development Environments | Enforcing secret externalization and blocking hardcoded tokens in git commits. |
| **PS.1** | Protect All Forms of Code from Unauthorized Access | Principle of Least Privilege access controls and audit logging. |
| **PW.1** | Design Software to Meet Security Requirements | Detecting architectural anti-patterns, God classes, and missing rate limits. |
| **PW.4** | Reuse Existing, Well-Secured Software | Recommending proven security libraries (`bcrypt`, `secrets`, `defusedxml`, `Bucket4j`). |
| **PW.5** | Create Source Code by Adhering to Secure Coding Practices | Generating unified diff remediations and automated unit regression tests. |
| **PW.8** | Review and/or Analyze Human-Readable Code | Multi-agent automated code review and AST complexity analysis. |
| **RV.1** | Identify and Confirm Vulnerabilities on Ongoing Basis | Continuous automated PR merge gate scanning and health scoring. |

---

## 7. ISO/IEC 27001:2022 & ISO/IEC 27002 Annex A Controls

| Annex A Control | Control Title | AegisAI Verification Strategy |
| :--- | :--- | :--- |
| **A.8.25** | Secure Development Life Cycle | Automated pre-commit and CI/CD code review gates enforcing passing scores. |
| **A.8.26** | Application Security Requirements | Identification of missing authentication, authorization, and rate limiting. |
| **A.8.27** | Secure System Architecture and Engineering | Detecting monolithic anti-patterns, cyclomatic complexity > 10, deep nesting. |
| **A.8.28** | Secure Coding | Verifying parameterized SQL, safe deserialization, and output sanitization. |
| **A.8.29** | Security Testing in Development | Automated regression test code generation for every identified finding. |
| **A.8.30** | Outsourced Development | Standardized review scoring ensuring third-party submissions meet thresholds. |

---

## 8. PCI-DSS v4.0 Requirement 6 Software Security Standards

Payment Card Industry Data Security Standard (PCI-DSS v4.0) mandates rigorous defensive controls for applications processing cardholder data:

| PCI-DSS Req | Requirement Mandate | Relevant CWEs |
| :--- | :--- | :--- |
| **Req 6.2.4** | Software engineering techniques to prevent common software attacks | CWE-89 (SQLi), CWE-78 (OS Command), CWE-22 (Path Traversal), CWE-79 (XSS) |
| **Req 6.3.1** | Security vulnerabilities identified and managed across development | CWE-1104, CWE-1395 (Dependency vulnerabilities) |
| **Req 6.3.2** | Software inventory maintained including all bespoke and third-party libraries | Software Bill of Materials (SBOM) generation |
| **Req 6.4.1** | Public-facing web applications protected against attacks | Rate limiting, CORS origin restrictions, security headers |
| **Req 6.5.1** | Injection flaws addressed through parameterization | Prepared statements, ORM parameter bindings |
| **Req 6.5.3** | Cryptographic failures prevented through strong ciphers | AES-256-GCM, TLS 1.3, Argon2id/Bcrypt password hashing |

---

## 9. MITRE ATT&CK Matrix for Enterprise Technique Mappings

AegisAI links vulnerability findings to adversary tactics, techniques, and procedures (TTPs):

| ATT&CK ID | Technique Name | Mapped Vulnerability | Adversary Objective |
| :--- | :--- | :--- | :--- |
| **T1190** | Exploit Public-Facing Application | SQLi (CWE-89), XXE (CWE-611), RCE | Initial Access via perimeter web servers. |
| **T1059** | Command and Scripting Interpreter | Command Injection (CWE-78), eval (CWE-94) | Execution of arbitrary system shell binaries. |
| **T1078** | Valid Accounts | Hardcoded Credentials (CWE-798), IDOR | Persistence & Defense Evasion with stolen keys. |
| **T1055** | Process Injection | Unsafe Deserialization (CWE-502) | Defense Evasion and privilege escalation via RCE. |
| **T1552** | Unsecured Credentials | Sensitive Data in Logs (CWE-532), Hardcoded Keys | Credential Access from code repositories and logs. |
| **T1003** | OS Credential Dumping | Path Traversal (`/etc/shadow`, `CWE-22`) | Exfiltration of operating system password hashes. |

---

## 10. Framework & Library Official Security Specifications

### Java Ecosystem:
- **Oracle Java SE Secure Coding Guidelines**: [https://www.oracle.com/java/technologies/javase/seccodeguide.html](https://www.oracle.com/java/technologies/javase/seccodeguide.html)
- **Spring Security 6.x Reference Documentation**: [https://docs.spring.io/spring-security/reference/](https://docs.spring.io/spring-security/reference/)
- **Jakarta EE 10 Security Specification**: [https://jakarta.ee/specifications/security/3.0/](https://jakarta.ee/specifications/security/3.0/)
- **Jackson Databind Security Advisories**: [https://github.com/FasterXML/jackson-databind/wiki/Security-Alerts](https://github.com/FasterXML/jackson-databind/wiki/Security-Alerts)
- **Bucket4j Rate Limiting**: [https://bucket4j.com/](https://bucket4j.com/)

### Python Ecosystem:
- **FastAPI Security Documentation**: [https://fastapi.tiangolo.com/tutorial/security/](https://fastapi.tiangolo.com/tutorial/security/)
- **Flask Security Considerations**: [https://flask.palletsprojects.com/en/latest/security/](https://flask.palletsprojects.com/en/latest/security/)
- **Django Security Model & Protection**: [https://docs.djangoproject.com/en/stable/topics/security/](https://docs.djangoproject.com/en/stable/topics/security/)
- **Cryptography (hazmat) Documentation**: [https://cryptography.io/en/latest/](https://cryptography.io/en/latest/)
- **DefusedXML Library**: [https://github.com/tiran/defusedxml](https://github.com/tiran/defusedxml)
