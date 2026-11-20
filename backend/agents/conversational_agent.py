import os
import json
import logging
import urllib.request
from typing import List, Dict, Any, Optional

from backend.agents.base_agent import BaseAgent
from backend.models.schemas import ChatResponse, KnowledgeSearchResult
from backend.rag.retriever import SecureCodingRAGRetriever
from backend.config import GEMINI_API_KEY

logger = logging.getLogger(__name__)

class ConversationalCodeAssistant(BaseAgent):
    """
    Agent 5: Conversational Code Assistant
    RAG-powered conversational assistant grounded in the secure coding knowledge base.
    Allows developers to ask follow-up questions, request deeper explanations,
    or explore best-practice patterns for Python and Java.
    """

    def __init__(self):
        super().__init__(
            name="Conversational Code Assistant",
            description="RAG-powered conversational assistant for follow-up code review Q&A.",
        )
        self.retriever = SecureCodingRAGRetriever()

    def _call_gemini_api(self, prompt: str) -> Optional[str]:
        """Calls Google Gemini API with grounded context. Falls back gracefully on network error or timeout."""
        api_key = os.getenv("GEMINI_API_KEY", "") or GEMINI_API_KEY
        if not api_key:
            return None

        # Confirmed supported models on Google API
        models_to_try = [
            "gemini-3.5-flash-lite",
            "gemini-3.5-flash",
        ]
        for model in models_to_try:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
                payload = json.dumps({
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 800}
                }).encode("utf-8")

                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=15) as response:
                    if response.status == 200:
                        data = json.loads(response.read().decode("utf-8"))
                        candidates = data.get("candidates", [])
                        if candidates:
                            parts = candidates[0].get("content", {}).get("parts", [])
                            if parts:
                                return parts[0].get("text", "").strip()
            except Exception as e:
                err_str = str(e).lower()
                logger.info(f"Gemini API attempt with {model} failed: {e}. Trying fallback.")
                if "no such host" in err_str or "getaddrinfo failed" in err_str:
                    break
                continue
        return None

    def run(
        self,
        query: str,
        code_context: Optional[str] = None,
        language: str = "python",
        findings_context: Optional[List[Dict[str, Any]]] = None,
        history: Optional[List[Dict[str, str]]] = None,
    ) -> ChatResponse:
        # Detect if query asks for both or specific language
        q_lower = query.lower()
        asks_java = ("java" in q_lower and "javascript" not in q_lower)
        asks_python = ("python" in q_lower)
        asks_both = (asks_java and asks_python) or ("both" in q_lower)

        effective_lang = language
        if asks_both:
            effective_lang = "both"
        elif asks_java:
            effective_lang = "java"
        elif asks_python:
            effective_lang = "python"

        # 1. Retrieve grounded knowledge base documents
        retrieval_lang = "java" if effective_lang == "java" else "python"
        sources: List[KnowledgeSearchResult] = self.retriever.retrieve_for_chat(
            user_query=query,
            code_context=code_context,
            language=retrieval_lang,
            top_k=3,
        )

        # 2. Try Gemini API first
        gemini_answer = None
        if os.getenv("GEMINI_API_KEY", "") or GEMINI_API_KEY:
            is_general = self._is_general_programming_query(q_lower)

            if effective_lang == "both":
                lang_instruction = (
                    "The developer is asking about BOTH PYTHON and JAVA. "
                    "Provide clear, runnable code examples and explanations for BOTH languages."
                )
            elif effective_lang == "java":
                lang_instruction = (
                    "The developer is asking about JAVA. "
                    "Provide clear, runnable Java code examples and Java best practices."
                )
            else:
                lang_instruction = (
                    "The developer is asking about PYTHON. "
                    "Provide clear, runnable Python code examples and Python best practices."
                )

            # For general how-to questions, do not force unrelated OWASP code smell context
            if is_general or not sources or "smell" in (sources[0].title or "").lower():
                guidelines_section = ""
            else:
                sources_summary = "\n".join([f"- {s.title}: {s.content}" for s in sources[:2]])
                guidelines_section = f"\nRelevant Security Guidelines:\n{sources_summary}\n"

            code_ctx_section = ""
            if code_context and len(code_context.strip()) > 10:
                code_ctx_section = f"\nActive Code Context:\n```{effective_lang}\n{code_context[:1200]}\n```\n"

            gemini_prompt = f"""You are AegisAI's expert code review and programming assistant.
Help the developer with their programming or security question.

Developer Question: {query}
Language: {effective_lang.upper()}
{lang_instruction}
{code_ctx_section}{guidelines_section}
Instructions:
1. Provide a direct, technically accurate explanation.
2. Show clean, runnable code examples with proper markdown code blocks (```python, ```java).
3. If the question asks for both or compares them, show both Python and Java.
4. Include practical tips and best practices.
5. Keep the formatting clean and concise.
"""
            gemini_answer = self._call_gemini_api(gemini_prompt)

        # 3. Formulate grounded explanation (Gemini if available, otherwise local RAG)
        if gemini_answer:
            answer = gemini_answer
        else:
            answer = self._generate_answer(query, sources, code_context, effective_lang, findings_context)

        # 4. Formulate smart suggested follow-up questions
        suggested_followups = self._generate_followups(query, sources)

        return ChatResponse(
            answer=answer,
            sources=sources,
            suggested_followups=suggested_followups,
        )

    # Java secure code examples used when Gemini is offline
    _JAVA_EXAMPLES = {
        "sql": {
            "title": "SQL Injection Prevention — Java PreparedStatement",
            "vulnerable": (
                'Statement stmt = conn.createStatement();\n'
                'ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);'
            ),
            "secure": (
                'PreparedStatement ps = conn.prepareStatement(\n'
                '    "SELECT * FROM users WHERE id = ?");\n'
                'ps.setInt(1, userId);\n'
                'ResultSet rs = ps.executeQuery();'
            ),
            "guidelines": [
                "Always use `PreparedStatement` with `?` placeholders — never concatenate user input into SQL.",
                "Use an ORM (Hibernate / JPA) with named parameters for a higher-level alternative.",
                "Apply least-privilege DB accounts so a breach limits blast radius.",
            ],
        },
        "command": {
            "title": "Command Injection Prevention — Java ProcessBuilder",
            "vulnerable": (
                'Runtime.getRuntime().exec("ls -la " + userInput);'
            ),
            "secure": (
                'ProcessBuilder pb = new ProcessBuilder(\n'
                '    "ls", "-la", sanitizedPath);\n'
                'pb.redirectErrorStream(true);\n'
                'Process p = pb.start();'
            ),
            "guidelines": [
                "Use `ProcessBuilder` with a List of arguments to avoid shell interpretation.",
                "Never pass user input directly to `Runtime.exec()` or shell commands.",
                "Whitelist acceptable input values before passing to any OS command.",
            ],
        },
        "deserialization": {
            "title": "Insecure Deserialization Prevention — Java ObjectInputFilter",
            "vulnerable": (
                'ObjectInputStream ois = new ObjectInputStream(inputStream);\n'
                'Object obj = ois.readObject();  // unsafe — allows arbitrary classes'
            ),
            "secure": (
                'ObjectInputStream ois = new ObjectInputStream(inputStream);\n'
                'ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(\n'
                '    "com.myapp.dto.*;java.base/*;!*"));\n'
                'MyDto obj = (MyDto) ois.readObject();'
            ),
            "guidelines": [
                "Use `ObjectInputFilter` to whitelist only trusted classes during deserialization.",
                "Prefer JSON (Jackson/Gson) or Protobuf over Java serialization for data exchange.",
                "Never deserialize data from untrusted sources without strict class filtering.",
            ],
        },
        "path": {
            "title": "Path Traversal Prevention — Java Canonical Path Validation",
            "vulnerable": (
                'File f = new File(baseDir, userInput);\n'
                'InputStream is = new FileInputStream(f);  // traversal risk'
            ),
            "secure": (
                'File f = new File(baseDir, userInput);\n'
                'String canonical = f.getCanonicalPath();\n'
                'if (!canonical.startsWith(baseDir.getCanonicalPath() + File.separator)) {\n'
                '    throw new SecurityException("Path traversal detected");\n'
                '}\n'
                'InputStream is = new FileInputStream(f);'
            ),
            "guidelines": [
                "Always call `getCanonicalPath()` and validate the result starts with your allowed base directory.",
                "Use `java.nio.file.Path.normalize()` and `startsWith()` for a modern alternative.",
                "Reject any path containing `..` segments before resolving.",
            ],
        },
        "secret": {
            "title": "Hardcoded Secrets Prevention — Java Environment Variables",
            "vulnerable": (
                'String dbPassword = "hunter2";  // hardcoded secret'
            ),
            "secure": (
                'String dbPassword = System.getenv("DB_PASSWORD");\n'
                'if (dbPassword == null || dbPassword.isBlank()) {\n'
                '    throw new IllegalStateException("DB_PASSWORD env var not set");\n'
                '}'
            ),
            "guidelines": [
                "Load secrets from environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).",
                "Never commit credentials to source control — use `.gitignore` and pre-commit secret scanning.",
                "Rotate secrets immediately if they are ever exposed.",
            ],
        },
        "function": {
            "title": "How to Create a Java Method / Function",
            "answer": """### ☕ How to Create a Java Function (Method)

In Java, functions are defined as **methods** inside a class.

#### ✅ Complete Java Example:
```java
public class Calculator {

    // 1. Static method with parameters and a return value
    public static int add(int a, int b) {
        return a + b;
    }

    // 2. Void method (performs an action, returns nothing)
    public static void greet(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Name cannot be empty");
        }
        System.out.println("Hello, " + name + "!");
    }

    // 3. Instance method (called on an object instance)
    public double multiply(double x, double y) {
        return x * y;
    }

    public static void main(String[] args) {
        greet("Alice");
        int sum = add(10, 20);
        System.out.println("Sum: " + sum); // Output: Sum: 30
    }
}
```

#### 🛡️ Best Practices:
- **Visibility:** Use `private` for internal helper methods, `public` only for external APIs.
- **Fail Fast:** Validate input parameters at the beginning of the method.
- **Single Responsibility:** Keep methods focused on one task (ideally under 30 lines).
- **Naming:** Follow `camelCase` for method names (e.g., `calculateTotal`).
""",
        },
        "class": {
            "title": "How to Create a Java Class",
            "answer": """### ☕ How to Create a Java Class

A Java class encapsulates state (fields) and behavior (methods).

#### ✅ Java Class Example:
```java
public class UserAccount {
    // 1. Private fields (Encapsulation)
    private String username;
    private double balance;

    // 2. Constructor
    public UserAccount(String username, double initialBalance) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        this.username = username;
        this.balance = Math.max(0.0, initialBalance);
    }

    // 3. Getter methods
    public String getUsername() { return username; }
    public double getBalance() { return balance; }

    // 4. Business method
    public void deposit(double amount) {
        if (amount <= 0) throw new IllegalArgumentException("Deposit must be positive");
        this.balance += amount;
    }
}
```

#### 🛡️ Best Practices:
- Keep fields `private` and provide getters/setters as needed.
- Validate arguments inside the constructor to ensure object invariants.
""",
        },
        "package": {
            "title": "How to Create a Java Package",
            "answer": """### ☕ How to Create a Java Package

A package organizes related classes into a namespace and avoids naming conflicts.

#### ✅ 1. Package Declaration (first line of Java file):
```java
package com.myapp.security;

public class TokenValidator {
    public static boolean isValid(String token) {
        return token != null && token.length() >= 32;
    }
}
```

#### ✅ 2. Directory Structure matches the package name:
```
src/
└── com/
    └── myapp/
        └── security/
            └── TokenValidator.java
```

#### ✅ 3. Importing the package into another file:
```java
package com.myapp.controllers;

import com.myapp.security.TokenValidator;

public class AuthController {
    public void handleLogin(String token) {
        if (TokenValidator.isValid(token)) {
            System.out.println("Authorized");
        }
    }
}
```
""",
        },
        "loop": {
            "title": "How to Use Loops in Java",
            "answer": """### ☕ Loops in Java

#### ✅ Standard `for` loop:
```java
for (int i = 0; i < 5; i++) {
    System.out.println(i);
}
```

#### ✅ Enhanced `for-each` loop (arrays / collections):
```java
String[] languages = {"Python", "Java", "TypeScript"};
for (String lang : languages) {
    System.out.println(lang);
}
```

#### ✅ `while` loop:
```java
int count = 0;
while (count < 3) {
    System.out.println("Count: " + count);
    count++;
}
```
""",
        },
        "default": {
            "title": "Java Secure Coding — OWASP Top 10 (2025) Quick Reference",
            "vulnerable": (
                '// ❌ Unsafe: concatenated SQL, raw exec, hardcoded secret\n'
                'stmt.executeQuery("SELECT * FROM users WHERE id = " + id);\n'
                'Runtime.getRuntime().exec("cmd " + userInput);\n'
                'String secret = "hardcoded_password";'
            ),
            "secure": (
                '// ✅ Safe: PreparedStatement, ProcessBuilder, env secret\n'
                'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n'
                'ps.setInt(1, id);\n'
                '\n'
                'new ProcessBuilder("cmd", sanitizedArg).start();\n'
                '\n'
                'String secret = System.getenv("MY_SECRET");'
            ),
            "guidelines": [
                "SQL Injection: Use `PreparedStatement` with `?` placeholders.",
                "Command Injection: Use `ProcessBuilder` with a list of arguments.",
                "Deserialization: Apply `ObjectInputFilter` to whitelist safe classes.",
                "Path Traversal: Validate `getCanonicalPath()` against a trusted base directory.",
                "Secrets: Load from environment variables or a secrets manager — never hardcode.",
                "Refer to OWASP Top 10 (2025) for the full secure coding standard.",
            ],
        },
    }

    # Python built-in answers for common queries (Gemini offline fallback)
    _PYTHON_ANSWERS = {
        "function": {
            "title": "How to Create a Python Function",
            "answer": """\
### 🐍 How to Create a Python Function

Use the `def` keyword followed by the function name and parentheses.

#### ✅ Basic Function:
```python
def greet(name: str) -> str:
    \"\"\"Returns a greeting message.\"\"\"
    return f"Hello, {name}!"

# Call it
print(greet("Alice"))  # Hello, Alice!
```

#### ✅ Function with Default Arguments:
```python
def power(base: int, exp: int = 2) -> int:
    \"\"\"Returns base raised to exp (default: squared).\"\"\"
    return base ** exp

print(power(3))    # 9
print(power(3, 3)) # 27
```

#### ✅ Function with *args and **kwargs:
```python
def summarize(*args, **kwargs):
    print("Positional:", args)
    print("Keyword:", kwargs)

summarize(1, 2, 3, name="Alice", role="admin")
```

#### 🛡️ Secure Coding Tips:
- Always validate inputs at the top of the function (fail fast).
- Use type hints (`str`, `int`, `list`) for clarity and static analysis.
- Keep functions short and focused (Single Responsibility Principle).
- Avoid mutable default arguments — use `None` instead of `[]`.
""",
        },
        "class": {
            "title": "How to Create a Python Class",
            "answer": """\
### 🐍 How to Create a Python Class

Use the `class` keyword. The `__init__` method is the constructor.

#### ✅ Basic Class:
```python
class BankAccount:
    def __init__(self, owner: str, balance: float = 0.0):
        self.owner = owner
        self._balance = balance  # protected attribute

    def deposit(self, amount: float) -> None:
        if amount <= 0:
            raise ValueError("Deposit amount must be positive.")
        self._balance += amount

    def get_balance(self) -> float:
        return self._balance

    def __repr__(self) -> str:
        return f"BankAccount(owner={self.owner!r})"

# Usage
acc = BankAccount("Alice", 100.0)
acc.deposit(50)
print(acc.get_balance())  # 150.0
```

#### 🛡️ Secure Coding Tips:
- Use `_name` for protected and `__name` for private attributes.
- Validate all inputs in `__init__` and setter methods.
- Prefer `@property` over public attributes to enforce encapsulation.
""",
        },
        "package": {
            "title": "How to Create a Python Package / Module",
            "answer": """\
### 🐍 How to Create a Python Package

A **module** is a single `.py` file. A **package** is a folder with an `__init__.py` file.

#### ✅ Package Structure:
```
mypackage/
├── __init__.py        # marks folder as a package
├── utils.py
└── models.py
```

#### ✅ `__init__.py` example:
```python
# mypackage/__init__.py
from .utils import helper_function
from .models import UserModel

__all__ = ["helper_function", "UserModel"]
```

#### ✅ Importing from your package:
```python
from mypackage import helper_function
from mypackage.models import UserModel
```

#### 🛡️ Secure Coding Tips:
- Use `__all__` to explicitly control what is exported.
- Never use wildcard imports (`from module import *`) in production code.
- Keep sensitive logic in private modules (prefix with `_`).
""",
        },
        "loop": {
            "title": "How to Use Loops in Python",
            "answer": """\
### 🐍 Loops in Python

#### ✅ `for` loop:
```python
fruits = ["apple", "banana", "cherry"]
for fruit in fruits:
    print(fruit)

# Range-based
for i in range(5):
    print(i)  # 0 1 2 3 4
```

#### ✅ `while` loop:
```python
count = 0
while count < 3:
    print(count)
    count += 1
```

#### ✅ List Comprehension (Pythonic):
```python
squares = [x ** 2 for x in range(10)]
```

#### 🛡️ Secure Coding Tips:
- Always ensure `while` loops have a reachable exit condition to prevent infinite loops (DoS risk).
- Limit iteration over untrusted external data with a max-count guard.
""",
        },
        "sql": {
            "title": "SQL Injection Prevention — Python Parameterized Queries",
            "answer": """\
### 🐍 SQL Injection Prevention in Python

#### ⚠️ Vulnerable (Never do this):
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
```

#### ✅ Secure — Parameterized Query:
```python
import sqlite3

conn = sqlite3.connect("app.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
rows = cursor.fetchall()
```

#### ✅ With psycopg2 (PostgreSQL):
```python
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
```

#### 🛡️ Remediation Guidelines:
- Always use `?` (sqlite3) or `%s` (psycopg2) placeholders — never f-strings or `.format()` in SQL.
- Use an ORM (SQLAlchemy) for a higher-level safe alternative.
- Apply least-privilege DB roles.
""",
        },
        "secret": {
            "title": "Safe Secret Storage in Python",
            "answer": """\
### 🐍 Safe Secret Storage in Python

#### ⚠️ Vulnerable (Never hardcode):
```python
API_KEY = "sk-abc123hardcoded"
DB_PASSWORD = "hunter2"
```

#### ✅ Secure — Environment Variables:
```python
import os

api_key = os.getenv("API_KEY")
if not api_key:
    raise RuntimeError("API_KEY environment variable not set.")
```

#### ✅ Using `python-dotenv` for local dev:
```python
from dotenv import load_dotenv
import os

load_dotenv()  # loads from .env file
db_password = os.getenv("DB_PASSWORD")
```

#### 🛡️ Remediation Guidelines:
- Add `.env` to `.gitignore` — never commit it.
- Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) in production.
- Rotate secrets immediately if ever exposed.
""",
        },
        "command": {
            "title": "Command Injection Prevention in Python",
            "answer": """\
### 🐍 Command Injection Prevention in Python

#### ⚠️ Vulnerable:
```python
import os
os.system("ls " + user_input)
```

#### ✅ Secure — subprocess with list:
```python
import subprocess

result = subprocess.run(
    ["ls", "-la", sanitized_path],
    capture_output=True, text=True, timeout=10
)
print(result.stdout)
```

#### 🛡️ Remediation Guidelines:
- Never pass `shell=True` with user-controlled input.
- Always pass arguments as a **list**, not a string.
- Validate and whitelist input before passing to any OS command.
""",
        },

        "default": {
            "title": "Python Secure Coding — General Guidance",
            "answer": """\
### 🐍 Python Secure Coding — OWASP Top 10 (2025) Quick Reference

#### ✅ Key Secure Coding Practices in Python:

```python
# 1. Parameterized SQL — never f-strings in queries
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# 2. Safe subprocess — use list, never shell=True with user input
subprocess.run(["ls", "-la", path], capture_output=True)

# 3. Secrets from environment — never hardcode
import os
secret = os.getenv("MY_SECRET")

# 4. Input validation — fail fast
def process(data: str) -> str:
    if not data or len(data) > 500:
        raise ValueError("Invalid input")
    return data.strip()

# 5. Safe deserialization — prefer json over pickle
import json
obj = json.loads(untrusted_string)  # safe
# obj = pickle.loads(data)          # NEVER with untrusted data
```

#### 🛡️ OWASP Top 10 (2025) Reminders:
- **A03** Injection: Use parameterized queries and subprocess lists.
- **A02** Cryptographic Failures: Use `secrets` module, not `random`.
- **A05** Security Misconfiguration: Validate all env vars at startup.
- **A08** Insecure Deserialization: Avoid `pickle` with untrusted data.
""",
        },
    }

    def _get_java_example(self, q_lower: str) -> dict:
        """Select the most relevant Java example block for the query."""
        if any(k in q_lower for k in ("function", "def ", "method", "func")):
            return self._JAVA_EXAMPLES["function"]
        if any(k in q_lower for k in ("class", "object", "oop")):
            return self._JAVA_EXAMPLES["class"]
        if any(k in q_lower for k in ("package", "module", "namespace")):
            return self._JAVA_EXAMPLES["package"]
        if any(k in q_lower for k in ("loop", "for ", "while", "iterate", "range")):
            return self._JAVA_EXAMPLES["loop"]
        if any(k in q_lower for k in ("sql", "injection", "query", "database", "preparedstatement")):
            return self._JAVA_EXAMPLES["sql"]
        if any(k in q_lower for k in ("command", "exec", "processbuilder", "runtime", "shell", "os")):
            return self._JAVA_EXAMPLES["command"]
        if any(k in q_lower for k in ("deserializ", "pickle", "serial", "objectinput")):
            return self._JAVA_EXAMPLES["deserialization"]
        if any(k in q_lower for k in ("path", "traversal", "file", "directory", "zipslip")):
            return self._JAVA_EXAMPLES["path"]
        if any(k in q_lower for k in ("secret", "password", "credential", "hardcod", "api key")):
            return self._JAVA_EXAMPLES["secret"]
        return self._JAVA_EXAMPLES["default"]

    def _get_python_answer(self, q_lower: str) -> dict:
        """Select the most relevant Python answer for the query."""
        if any(k in q_lower for k in ("function", "def ", "method", "func")):
            return self._PYTHON_ANSWERS["function"]
        if any(k in q_lower for k in ("class", "object", "oop", "__init__")):
            return self._PYTHON_ANSWERS["class"]
        if any(k in q_lower for k in ("package", "module", "import", "__init__", "pip")):
            return self._PYTHON_ANSWERS["package"]
        if any(k in q_lower for k in ("loop", "for ", "while", "iterate", "range")):
            return self._PYTHON_ANSWERS["loop"]
        if any(k in q_lower for k in ("sql", "injection", "query", "database", "sqlite", "psycopg")):
            return self._PYTHON_ANSWERS["sql"]
        if any(k in q_lower for k in ("secret", "password", "credential", "hardcod", "api key", "dotenv")):
            return self._PYTHON_ANSWERS["secret"]
        if any(k in q_lower for k in ("command", "exec", "subprocess", "shell", "os.system")):
            return self._PYTHON_ANSWERS["command"]
        return self._PYTHON_ANSWERS["default"]

    def _is_general_programming_query(self, q_lower: str) -> bool:
        """Returns True if the query is a general how-to programming question (not security-specific)."""
        how_to_words = ("how to", "how do", "how can", "what is", "what are", "explain", "create", "make", "write", "define", "show me", "example")
        general_topics = ("function", "class", "method", "loop", "package", "module", "variable", "list", "dict", "array", "string", "integer", "type", "import", "syntax", "object", "print")
        has_how_to = any(w in q_lower for w in how_to_words)
        has_general_topic = any(t in q_lower for t in general_topics)
        return has_how_to and has_general_topic

    def _generate_answer(
        self,
        query: str,
        sources: List[KnowledgeSearchResult],
        code_context: Optional[str],
        language: str,
        findings: Optional[List[Dict[str, Any]]],
    ) -> str:
        q_lower = query.lower()

        # Check if the query is asking about a specific finding or line
        matching_finding = None
        if findings:
            for f in findings:
                title = f.get("title", "").lower()
                line = str(f.get("line_start", ""))
                if (line and f"line {line}" in q_lower) or any(w in q_lower for w in title.split()[:3]):
                    matching_finding = f
                    break

        if matching_finding:
            rem = matching_finding.get("remediation", {})
            return f"""### 🛡️ Analysis for: **{matching_finding.get('title')}**
- **Severity:** `{matching_finding.get('severity')}`
- **Standards:** `{matching_finding.get('owasp_category', 'OWASP Top 10 (2025)')}` | `{matching_finding.get('cwe_id', '')}`
- **Line Location:** Line {matching_finding.get('line_start')}

#### 💡 Why This Is A Risk:
{matching_finding.get('description')}

#### 🛠️ Recommended Remediation:
```diff
{rem.get('diff', 'See remediation tab')}
```

#### ✅ Secure Replacement Code:
```{language}
{rem.get('corrected_snippet', '// Use parameterized query or safe API')}
```

#### 📚 Grounded Knowledge Base Reference:
{sources[0].content if sources else 'Follow standard OWASP 2025 defensive coding practices.'}
"""

        # --- Dual-language inline answer (Python + Java) ---
        if language == "both":
            py_ans = self._get_python_answer(q_lower)["answer"]
            java_ex = self._get_java_example(q_lower)
            if "answer" in java_ex:
                java_ans = java_ex["answer"]
            else:
                guidelines_md = "\n".join(f"- {g}" for g in java_ex["guidelines"])
                java_ans = f"""### ☕ {java_ex['title']}

#### ⚠️ Vulnerable Java Pattern to Avoid:
```java
{java_ex['vulnerable']}
```

#### ✅ Secure Java Implementation:
```java
{java_ex['secure']}
```

#### 🛡️ Remediation Guidelines:
{guidelines_md}"""
            return f"""{py_ans}

---

{java_ans}"""

        # --- Java-specific inline answer (Gemini offline fallback) ---
        if language == "java":
            ex = self._get_java_example(q_lower)
            if "answer" in ex:
                return ex["answer"]
            guidelines_md = "\n".join(f"- {g}" for g in ex["guidelines"])
            top_ref = f"\n\n#### 📚 OWASP Reference:\n{sources[0].content}" if sources else ""
            return f"""### ☕ {ex['title']}

#### ⚠️ Vulnerable Java Pattern to Avoid:
```java
{ex['vulnerable']}
```

#### ✅ Secure Java Implementation:
```java
{ex['secure']}
```

#### 🛡️ Remediation Guidelines:
{guidelines_md}{top_ref}
"""

        # --- Python-specific inline answer (Gemini offline fallback) ---
        if language == "python":
            # Use built-in answer for general programming questions
            # OR for security questions where RAG top result is irrelevant
            py = self._get_python_answer(q_lower)
            rag_irrelevant = not sources or (
                sources and "smell" in sources[0].title.lower()
                and not any(k in q_lower for k in ("smell", "long method", "refactor", "code quality"))
            )
            if self._is_general_programming_query(q_lower) or rag_irrelevant:
                top_ref = f"\n\n#### 📚 OWASP Reference:\n{sources[0].content}" if sources and not rag_irrelevant else ""
                return py["answer"] + top_ref

        # General RAG query answer using top source (Python / other)
        if sources:
            top_doc = sources[0]

            raw_doc = None
            indexer_docs = getattr(getattr(self.retriever.store, "fallback_indexer", None), "documents", [])
            for d in indexer_docs:
                if d.get("id") == top_doc.id or d.get("title") == top_doc.title:
                    raw_doc = d
                    break

            lines = [
                f"### 📘 {top_doc.title}",
                f"**Category:** `{top_doc.category}` | **Standard:** `{top_doc.owasp_id or 'General'}` | `{top_doc.cwe_id or ''}`\n",
                f"{top_doc.content}\n",
            ]

            if raw_doc:
                vuln_ex = raw_doc.get("vulnerable_example")
                sec_ex = raw_doc.get("secure_example")
                guidelines = raw_doc.get("remediation_guidelines")

                if vuln_ex:
                    lines.append(f"#### ⚠️ Vulnerable Pattern to Avoid:\n```{language}\n{vuln_ex.strip()}\n```\n")
                if sec_ex:
                    lines.append(f"#### 🎯 Secure Implementation Pattern ({language.capitalize()}):\n```{language}\n{sec_ex.strip()}\n```\n")
                if guidelines and isinstance(guidelines, list):
                    lines.append("#### 🛡️ Remediation Guidelines:")
                    for g in guidelines:
                        lines.append(f"- {g}")
            else:
                lines.append(f"#### 🎯 Defensive Engineering Recommendation ({language.capitalize()}):")
                lines.append("- Apply defense-in-depth principles and parameterized APIs to strictly enforce type safety.")
                lines.append("- Refer to the official OWASP Top 10 (2025 Edition) secure coding standards.")

            return "\n".join(lines)

        # Fallback response
        return (
            f"Here is expert guidance regarding '{query}': "
            f"Always apply defense-in-depth, input validation, and parameterized APIs to prevent vulnerabilities."
        )

    def _generate_followups(self, query: str, sources: List[KnowledgeSearchResult]) -> List[str]:
        q_lower = query.lower()
        if "sql" in q_lower or "injection" in q_lower:
            return [
                "How do prepared statements prevent SQL injection under the hood?",
                "What is the difference between SQL injection and NoSQL injection?",
                "How can I safely pass dynamic table names in database queries?",
            ]
        elif "secret" in q_lower or "auth" in q_lower or "password" in q_lower:
            return [
                "How should I structure environment variables in Docker/Kubernetes?",
                "What is the best hashing algorithm for user passwords in 2025?",
                "How can I set up automated secret scanning in Git pre-commit hooks?",
            ]
        elif "pickle" in q_lower or "deserialization" in q_lower:
            return [
                "Why is Python pickle capable of Remote Code Execution (RCE)?",
                "How can I safely serialize Python dataclasses to JSON?",
                "How does Java ObjectInputFilter protect against gadget chains?",
            ]
        else:
            return [
                "Can you show a secure refactoring example for this issue?",
                "What are the relevant OWASP Top 10 (2025) compliance guidelines?",
                "How can we add automated CI/CD security tests to catch this early?",
            ]
