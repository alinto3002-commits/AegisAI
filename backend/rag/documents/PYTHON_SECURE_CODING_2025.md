# Python Secure Coding Master Guide (2025 Edition)

[![OWASP Top 10](https://img.shields.io/badge/Security-OWASP%20Top%2010%20(2025)-red.svg)](https://owasp.org/Top10/)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI%20%7C%20Flask%20%7C%20Django-009688.svg)](https://fastapi.tiangolo.com)
[![PEP 506](https://img.shields.io/badge/Standard-PEP%20506%20Secrets-purple.svg)](https://peps.python.org/pep-0506/)

This document represents the authoritative, comprehensive secure coding standard for Python applications, microservices, and web frameworks (FastAPI, Flask, Django). It aligns with the **OWASP Top 10 (2025 Edition)** taxonomy, the **CWE Top 25 Most Dangerous Software Weaknesses**, and official Python Security Guidelines.

---

## Table of Contents
1. [Core Defensive Principles & Python Runtime Security](#1-core-defensive-principles--python-runtime-security)
2. [OWASP Top 10 (2025) Python Threat Defenses & Code Patterns](#2-owasp-top-10-2025-python-threat-defenses--code-patterns)
   - [A01:2025 — Broken Access Control (CWE-22, CWE-862, CWE-639, CWE-918)](#a012025--broken-access-control-in-python)
   - [A02:2025 — Security Misconfiguration (CWE-16, CWE-942, CWE-215)](#a022025--security-misconfiguration-in-python)
   - [A03:2025 — Software Supply Chain Failures (CWE-1104, CWE-1395)](#a032025--software-supply-chain-failures-in-python)
   - [A04:2025 — Cryptographic Failures (CWE-327, CWE-328, CWE-329, CWE-338)](#a042025--cryptographic-failures-in-python)
   - [A05:2025 — Injection (CWE-89, CWE-78, CWE-611, CWE-94)](#a052025--injection-in-python-sql-command-xxe-ssti)
   - [A06:2025 — Insecure Design (CWE-1059, CWE-307)](#a062025--insecure-design-in-python)
   - [A07:2025 — Authentication Failures (CWE-798, CWE-347, CWE-287)](#a072025--authentication-failures-in-python)
   - [A08:2025 — Software or Data Integrity Failures (CWE-502, CWE-94)](#a082025--software-or-data-integrity-failures-in-python)
   - [A09:2025 — Security Logging and Alerting Failures (CWE-532, CWE-117)](#a092025--security-logging-and-alerting-failures-in-python)
   - [A10:2025 — Mishandling of Exceptional Conditions (CWE-755, CWE-390)](#a102025--mishandling-of-exceptional-conditions-in-python)
3. [Python Web Framework Hardening (FastAPI, Flask, Django)](#3-python-web-framework-hardening)
4. [Python Static Analysis & AST Considerations](#4-python-static-analysis--ast-considerations)
5. [Automated Verification & CI/CD Security Gates](#5-automated-verification--cicd-security-gates)

---

## 1. Core Defensive Principles & Python Runtime Security

Python applications must implement strict defense-in-depth security controls:

- **Input Validation via Strong Typing**: Use Pydantic v2 schemas and type annotations to enforce runtime validation on all external inputs before business logic executes.
- **Zero Raw Dynamic Code Execution**: Prohibit `eval()`, `exec()`, `compile()`, and `__import__()` with user-supplied data under all circumstances.
- **Prohibit Untrusted Deserialization**: Disallow Python's native `pickle`, `shelve`, and `marshal` for IPC or untrusted network input. Standardize on JSON, MessagePack, or Protocol Buffers.
- **Fail Securely on Exceptions**: Catch specific exception types. Never write bare `except:` or `except Exception: pass` that suppresses authorization or database transaction failures.
- **Cryptographic Separation**: Use `secrets` for security-sensitive tokens and session identifiers. Restrict the `random` module strictly to non-cryptographic simulation.

---

## 2. OWASP Top 10 (2025) Python Threat Defenses & Code Patterns

### A01:2025 — Broken Access Control in Python
**CWE Mappings:** `CWE-22` (Path Traversal), `CWE-862` (Missing Authorization), `CWE-639` (IDOR), `CWE-918` (SSRF)

#### Pattern 1: Path Traversal & Arbitrary File Access
Directly concatenating user filenames into filesystem operations allows directory escape via `../`.

```python
# ❌ VULNERABLE: Direct string interpolation into file paths
from fastapi import FastAPI
app = FastAPI()

@app.get("/download")
def download_file(filename: str):
    with open(f"/var/data/uploads/{filename}", "rb") as f:
        return f.read()
```

```python
# ✅ SECURE: Canonical path resolution with boundary containment check
from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends

BASE_STORAGE = Path("/var/data/uploads").resolve()
app = FastAPI()

@app.get("/download")
def download_file(filename: str):
    target_path = (BASE_STORAGE / filename).resolve()
    if not target_path.is_relative_to(BASE_STORAGE) or not target_path.exists():
        raise HTTPException(status_code=403, detail="Access denied: invalid file path")
    return target_path.read_bytes()
```

#### Pattern 2: Server-Side Request Forgery (SSRF)
Allowing user-controlled URLs to be queried by internal HTTP clients permits attackers to exfiltrate AWS instance metadata (`169.254.169.254`) or probe internal cluster networks.

```python
# ❌ VULNERABLE: Direct request to arbitrary user-supplied URL
import requests

def fetch_webhook(url: str):
    return requests.get(url, timeout=5).text
```

```python
# ✅ SECURE: Strict scheme validation, domain allowlisting, and private IP rejection
import ipaddress
import socket
from urllib.parse import urlparse
import requests

ALLOWED_DOMAINS = {"api.partner.com", "hooks.slack.com"}

def fetch_webhook_safe(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid URL scheme; must be HTTP/HTTPS")
    
    if parsed.hostname not in ALLOWED_DOMAINS:
        # Check IP to prevent SSRF against loopback / RFC 1918 addresses
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise SecurityError("Access to internal networks is forbidden")
            
    response = requests.get(url, timeout=3, allow_redirects=False)
    return response.text
```

---

### A02:2025 — Security Misconfiguration in Python
**CWE Mappings:** `CWE-16` (Security Misconfiguration), `CWE-942` (Permissive CORS), `CWE-215` (Information Exposure via Debug Mode)

#### Pattern 1: Debug Mode Enabled in Production
Running Flask, Django, or FastAPI with `debug=True` in production exposes interactive web debuggers (e.g. Werkzeug debugger with PIN console execution) and full stack traces containing secrets.

```python
# ❌ VULNERABLE: Debug mode enabled in production
from flask import Flask
app = Flask(__name__)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

```python
# ✅ SECURE: Debug disabled, production WSGI/ASGI runner, environment configuration
import os
from flask import Flask

app = Flask(__name__)
DEBUG = os.getenv("FLASK_ENV") == "development"

if __name__ == "__main__":
    # In production, execute through Gunicorn or Uvicorn without debug
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", 5000)), debug=DEBUG)
```

#### Pattern 2: Wildcard CORS with Credentials
```python
# ❌ VULNERABLE: Wildcard CORS with credentials enabled
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
```

```python
# ✅ SECURE: Explicit origins and restricted HTTP methods
import os
from fastapi.middleware.cors import CORSMiddleware

ORIGINS = [os.getenv("FRONTEND_ORIGIN", "https://app.company.com")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

---

### A03:2025 — Software Supply Chain Failures in Python
**CWE Mappings:** `CWE-1104` (Unmaintained Dependencies), `CWE-1395` (Vulnerable Third-Party Packages)

#### Pattern: Hash-Pinned Requirements & Vulnerability Auditing
Unpinned `requirements.txt` files allow upstream typosquatting or compromised releases to execute malicious code during container builds.

```text
# ❌ VULNERABLE: Unpinned requirements.txt
requests
pyyaml
cryptography
```

```text
# ✅ SECURE: Pinned versions with cryptographic sha256 hashes
requests==2.31.0 --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f
pyyaml==6.0.1 --hash=sha256:4aa91a90d93be8068315d81a4b6417339b8a5437f0b71ad5c2901c6760d22170
cryptography==42.0.5 --hash=sha256:6e1875150993096b1b5e5de2806587cba1b22e1b12b542456e54148ce2cf36bb
```
Verify pipeline integrity using: `pip-audit --require-hashes -r requirements.txt`.

---

### A04:2025 — Cryptographic Failures in Python
**CWE Mappings:** `CWE-327` (Broken Algorithms), `CWE-328` (Weak Hashing), `CWE-338` (Insecure PRNG)

#### Pattern 1: Weak Password Hashing with MD5 / SHA-1
```python
# ❌ VULNERABLE: Plain MD5 or SHA256 for passwords
import hashlib

def hash_user_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
```

```python
# ✅ SECURE: Adaptive hashing with Argon2id or Bcrypt
import bcrypt

def hash_user_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_user_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
```

#### Pattern 2: Cryptographic Randomness (Secrets vs Random)
```python
# ❌ VULNERABLE: Mersenne Twister (random module) is completely predictable
import random
session_token = hex(random.getrandbits(128))
```

```python
# ✅ SECURE: Cryptographically secure entropy via PEP 506 secrets
import secrets
session_token = secrets.token_urlsafe(32)
api_key = secrets.token_hex(32)
```

---

### A05:2025 — Injection in Python (SQL, Command, XXE, SSTI)
**CWE Mappings:** `CWE-89` (SQLi), `CWE-78` (Command Injection), `CWE-611` (XXE), `CWE-94` (SSTI)

#### Pattern 1: SQL Injection via Formatted Strings
```python
# ❌ VULNERABLE: String formatting into SQL query
import sqlite3

def get_user_records(cursor, username: str):
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchall()
```

```python
# ✅ SECURE: Parameterized placeholder binding (DB-API 2.0)
import sqlite3

def get_user_records(cursor, username: str):
    cursor.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
    return cursor.fetchall()
```

#### Pattern 2: OS Command Injection via Subprocess
```python
# ❌ VULNERABLE: shell=True with user concatenation
import subprocess

def ping_host(host: str):
    subprocess.Popen(f"ping -c 1 {host}", shell=True)
```

```python
# ✅ SECURE: shell=False with argument vector and IP validation
import ipaddress
import subprocess

def ping_host(host: str) -> str:
    # Strictly validate that host is a valid IP address
    ip = ipaddress.ip_address(host)
    result = subprocess.run(
        ["ping", "-c", "1", str(ip)],
        shell=False,
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout
```

#### Pattern 3: XML External Entity (XXE) Prevention
```python
# ❌ VULNERABLE: Standard xml.etree resolves entities
import xml.etree.ElementTree as ET
tree = ET.fromstring(user_xml_data)
```

```python
# ✅ SECURE: DefusedXML blocks entity bombs and DTD resolution
import defusedxml.ElementTree as SafeET
tree = SafeET.fromstring(user_xml_data)
```

---

### A06:2025 — Insecure Design in Python
**CWE Mappings:** `CWE-1059` (Insecure Design), `CWE-307` (Missing Rate Limiting)

#### Pattern: Endpoint Rate Limiting with SlowAPI
```python
# ✅ SECURE: SlowAPI rate limiting on sensitive routes
from fastapi import FastAPI, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/auth/login")
@limiter.limit("5/minute")
def login(request: Request):
    return {"status": "authenticated"}
```

---

### A07:2025 — Authentication Failures in Python
**CWE Mappings:** `CWE-798` (Hardcoded Secrets), `CWE-347` (JWT Signature Bypass)

#### Pattern 1: Hardcoded Secrets vs Environment Variables
```python
# ❌ VULNERABLE: Secret keys hardcoded in script
JWT_SECRET = "my_super_secret_production_key_12345"
DATABASE_URL = "postgres://admin:password123@db.prod.internal:5432/main"
```

```python
# ✅ SECURE: Pydantic BaseSettings loading from environment
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    jwt_secret: str
    database_url: str
    token_expire_minutes: int = 30

    class Config:
        env_file = ".env"

settings = Settings()
```

#### Pattern 2: Flawed JWT Verification
```python
# ❌ VULNERABLE: Disabled signature verification or algorithm confusion
import jwt
payload = jwt.decode(token, options={"verify_signature": False})
```

```python
# ✅ SECURE: Enforce HMAC-SHA256 signature and algorithms whitelist
import jwt

def verify_token(token: str, secret: str) -> dict:
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        options={"require": ["exp", "sub", "iat"]}
    )
```

---

### A08:2025 — Software or Data Integrity Failures in Python
**CWE Mappings:** `CWE-502` (Untrusted Deserialization), `CWE-94` (Code Injection)

#### Pattern: Insecure Deserialization via Pickle & YAML
`pickle.loads()` reconstructs Python objects using arbitrary callable invocations (`__reduce__`), enabling immediate Remote Code Execution (RCE).

```python
# ❌ VULNERABLE: Deserializing untrusted byte streams with pickle
import pickle
data = pickle.loads(client_raw_bytes)

# ❌ VULNERABLE: Unsafe PyYAML load
import yaml
config = yaml.load(user_yaml_text) # Loads arbitrary Python objects!
```

```python
# ✅ SECURE: Pydantic JSON validation and yaml.safe_load
import yaml
from pydantic import BaseModel

class UserProfile(BaseModel):
    user_id: int
    name: str
    email: str

# Safe JSON parsing
profile = UserProfile.model_validate_json(client_raw_bytes)

# Safe YAML parsing
safe_config = yaml.safe_load(user_yaml_text)
```

---

### A09:2025 — Security Logging and Alerting Failures in Python
**CWE Mappings:** `CWE-532` (Credentials in Logs), `CWE-117` (Log Injection)

#### Pattern: Sanitizing Log Outputs and Redacting PII
```python
# ❌ VULNERABLE: Logging raw passwords and unsanitized newlines
import logging
logging.info(f"User login failed: {username} with password {password}")
```

```python
# ✅ SECURE: Sanitize CRLF characters and omit secret fields
import logging
logger = logging.getLogger("security")

def log_auth_failure(username: str, client_ip: str):
    clean_username = username.replace("\r", "").replace("\n", "")
    logger.warning("Auth failure for user=%s from ip=%s", clean_username, client_ip)
```

---

### A10:2025 — Mishandling of Exceptional Conditions in Python
**CWE Mappings:** `CWE-755` (Improper Exception Handling), `CWE-390` (Silent Error Suppression)

#### Pattern: Bare Except and Swallowing Critical Errors
```python
# ❌ VULNERABLE: Bare except masks database crashes and authorization errors
try:
    process_withdrawal(account_id, amount)
except:
    pass
```

```python
# ✅ SECURE: Specific exception handling, rollback, and logging
import logging
logger = logging.getLogger(__name__)

try:
    process_withdrawal(account_id, amount)
except (InsufficientBalanceError, AccountLockedError) as err:
    logger.warning("Withdrawal rejected for account %s: %s", account_id, err)
    raise HTTPException(status_code=400, detail=str(err))
except DatabaseConnectionError as err:
    logger.error("Database unavailable during withdrawal: %s", err, exc_info=True)
    db.session.rollback()
    raise HTTPException(status_code=503, detail="Service temporarily unavailable")
```

---

## 3. Python Web Framework Hardening

### FastAPI Production Security Checklist
- [x] Configure trusted hosts middleware (`TrustedHostMiddleware`).
- [x] Enforce SSL redirect (`HTTPSRedirectMiddleware`) in production.
- [x] Set security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`.
- [x] Disable automatic interactive docs (`/docs`, `/redoc`) in public production environments.

---

## 4. Python Static Analysis & AST Considerations

AegisAI utilizes Python's built-in `ast.parse` module to analyze syntax and calculate cyclomatic complexity. Note that AST static analysis:
- **Never executes submitted code**: AST checks compile syntax trees without invoking `eval` or imports.
- **Enforces limits**: Maximum line count and nesting thresholds are enforced to prevent resource exhaustion attacks.

---

## 5. Automated Verification & CI/CD Security Gates

- **Quality Score Minimum**: 80/100
- **Zero Critical / High Findings**: Merge gate triggers `BLOCKING_SECURITY_RISK` if any critical vulnerability is identified.
- **Dependency Audit**: `pip-audit` must run cleanly with 0 known CVEs.

---

## 6. FastAPI Enterprise Security Architecture

Modern Python web APIs using FastAPI require declarative security dependency injection:

### 6.1 Role-Based Access Control via Security Dependencies
```python
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, token: str = Depends(oauth2_scheme)) -> dict:
        try:
            payload = jwt.decode(
                token,
                JWT_PUBLIC_KEY,
                algorithms=["RS256"],
                options={"require": ["exp", "sub", "roles"]}
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_roles = payload.get("roles", [])
        if not any(role in self.allowed_roles for role in user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for current user role"
            )
        return payload

require_admin = RoleChecker(["admin", "superadmin"])
require_auditor = RoleChecker(["auditor", "admin"])

@app.delete("/api/tenants/{tenant_id}", dependencies=[Depends(require_admin)])
def delete_tenant(tenant_id: int):
    return {"status": "tenant deleted"}
```

---

## 7. SQLAlchemy 2.0 Secure Query Recipes

### 7.1 Dynamic Sorting SQL Injection Prevention in SQLAlchemy
Passing unvalidated user strings into `.order_by()` in SQLAlchemy creates SQL injection vulnerabilities (`CWE-89`).

```python
# ❌ VULNERABLE: Direct string into order_by() allows SQL injection
@app.get("/items")
def get_items(sort_column: str, db: Session = Depends(get_db)):
    # If sort_column is "(SELECT CASE WHEN (1=1) THEN ...)", SQLi executes!
    stmt = select(Item).order_by(text(sort_column))
    return db.execute(stmt).scalars().all()

# ✅ SECURE: Whitelist lookup mapping to ORM Column attributes
ALLOWED_SORT_COLUMNS = {
    "name": Item.name,
    "price": Item.price,
    "created_at": Item.created_at,
}

@app.get("/items")
def get_items(sort_by: str = "created_at", descending: bool = False, db: Session = Depends(get_db)):
    column = ALLOWED_SORT_COLUMNS.get(sort_by)
    if column is None:
        raise HTTPException(status_code=400, detail=f"Invalid sort column: {sort_by}")
    
    order = column.desc() if descending else column.asc()
    stmt = select(Item).order_by(order)
    return db.execute(stmt).scalars().all()
```

---

## 8. Celery & Background Worker Security

### 8.1 Preventing RCE in Asynchronous Task Deserialization
By default, legacy Celery configurations utilized `pickle` to serialize task messages. If an attacker gains write access to Redis or RabbitMQ, they can push arbitrary pickled payloads resulting in Remote Code Execution on all worker nodes.

```python
# ❌ VULNERABLE: Celery configuration allowing pickle
CELERY_ACCEPT_CONTENT = ["pickle", "json"]
CELERY_TASK_SERIALIZER = "pickle"
CELERY_RESULT_SERIALIZER = "pickle"

# ✅ SECURE: Strict JSON-only task serialization
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"
CELERY_ENABLE_UTC = True
# Enforce TLS encryption for Redis broker:
CELERY_BROKER_USE_SSL = {
    "ssl_cert_reqs": ssl.CERT_REQUIRED,
    "ssl_ca_certs": "/etc/ssl/certs/redis-ca.pem",
}
```

---

## 9. Automated Pytest Security Test Suite Recipes

### 9.1 IDOR Prevention Unit Test
```python
import pytest
from fastapi.testclient import TestClient

def test_user_cannot_access_other_user_invoice(client: TestClient, user_token: str, victim_invoice_id: int):
    # Attempting to fetch another user's invoice must return 404 or 403, never 200
    headers = {"Authorization": f"Bearer {user_token}"}
    response = client.get(f"/api/invoices/{victim_invoice_id}", headers=headers)
    assert response.status_code in (403, 404)
    assert "victim_sensitive_data" not in response.text

def test_sql_injection_payload_returns_422_or_safe_empty(client: TestClient, user_token: str):
    headers = {"Authorization": f"Bearer {user_token}"}
    payload = {"username": "admin' OR 1=1 --"}
    response = client.post("/api/users/lookup", json=payload, headers=headers)
    # The parameterized backend treats the payload literally; no unauthorized records returned
    data = response.json()
    assert len(data.get("results", [])) == 0
```

