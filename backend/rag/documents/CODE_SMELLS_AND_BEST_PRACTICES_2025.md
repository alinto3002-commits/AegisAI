# Code Smells, Architecture Metrics & Refactoring Handbook (2025 Edition)

[![Clean Code](https://img.shields.io/badge/Architecture-SOLID%20%7C%20Clean%20Code-brightgreen.svg)]()
[![Complexity](https://img.shields.io/badge/Metrics-Cyclomatic%20%26%20Cognitive-blue.svg)]()
[![Refactoring](https://img.shields.io/badge/Practices-Martin%20Fowler%20Patterns-orange.svg)]()

This handbook outlines the software quality standards, architectural anti-patterns, complexity limits, and refactoring strategies enforced by the **AegisAI Code Analysis Agent**. Code maintainability directly impacts application security: convoluted, deeply nested, or monolithic code obscures critical authorization bypasses, memory leaks, and input validation vulnerabilities.

---

## Table of Contents
1. [Software Complexity Metrics (Cyclomatic vs. Cognitive)](#1-software-complexity-metrics-cyclomatic-vs-cognitive)
2. [Top 10 Code Smells & Refactoring Catalog](#2-top-10-code-smells--refactoring-catalog)
   - [Smell 1: High Cyclomatic Complexity (McCabe > 10)](#smell-1-high-cyclomatic-complexity-mccabe--10)
   - [Smell 2: God Class / Monolithic Controller Anti-Pattern](#smell-2-god-class--monolithic-controller-anti-pattern)
   - [Smell 3: Long Method / Giant Action (> 50 Lines)](#smell-3-long-method--giant-action--50-lines)
   - [Smell 4: Deep Nesting / The Arrow Anti-Pattern (> 3 Levels)](#smell-4-deep-nesting--the-arrow-anti-pattern--3-levels)
   - [Smell 5: Primitive Obsession & Weak Domain Typing](#smell-5-primitive-obsession--weak-domain-typing)
   - [Smell 6: Long Parameter Lists (> 4 Parameters)](#smell-6-long-parameter-lists--4-parameters)
   - [Smell 7: Feature Envy & Inappropriate Intimacy](#smell-7-feature-envy--inappropriate-intimacy)
   - [Smell 8: Shotgun Surgery & Divergent Change](#smell-8-shotgun-surgery--divergent-change)
   - [Smell 9: Dead Code, Unused Imports & Ghost Variables](#smell-9-dead-code-unused-imports--ghost-variables)
   - [Smell 10: Silent Failure & Exception Swallowing](#smell-10-silent-failure--exception-swallowing)
3. [SOLID Principles in Modern Python and Java](#3-solid-principles-in-modern-python-and-java)
4. [Refactoring Strategies for High-Risk Modules](#4-refactoring-strategies-for-high-risk-modules)
5. [Automated Code Quality Thresholds in AegisAI](#5-automated-code-quality-thresholds-in-aegisai)

---

## 1. Software Complexity Metrics (Cyclomatic vs. Cognitive)

### 1.1 Cyclomatic Complexity (McCabe Metric)
Cyclomatic complexity measures the number of linearly independent execution paths through a program's source code:
$$M = E - N + 2P$$
Where $E$ is the number of edges, $N$ is the number of nodes, and $P$ is the number of connected components.

In practical AST parsing, complexity increments by +1 for every decision branch:
- Conditionals: `if`, `elif`, `else if`, `ternary operator (?:)`
- Loops: `for`, `while`, `do-while`
- Exception Handlers: `catch`, `except`
- Logical Operators: `and`, `or`, `&&`, `||`
- Switch/Pattern Cases: `case`, `match`

| Cyclomatic Score | Risk Evaluation | Action Mandate |
| :--- | :--- | :--- |
| **1 – 5** | Low Risk | Clean, easily maintainable and fully testable. |
| **6 – 10** | Moderate Risk | Acceptable; ensure 100% unit test branch coverage. |
| **11 – 20** | High Risk | **FLAGGED**: Difficult to test, high bug density; refactoring required. |
| **> 20** | Very High / Untestable | **BLOCKED**: Must be decomposed into modular sub-functions. |

### 1.2 Cognitive Complexity
While Cyclomatic complexity measures how hard code is to test, **Cognitive Complexity** measures how hard code is to understand by human engineers. It penalizes nested structures (nesting increments complexity exponentially) and discounts clean functional idioms (e.g., standard fluent streams or list comprehensions).

---

## 2. Top 10 Code Smells & Refactoring Catalog

### Smell 1: High Cyclomatic Complexity (McCabe > 10)
- **Problem**: Giant multi-branch branching structures (`if-elif-elif...` or deep `switch` statements) where edge-case authorization checks can be easily bypassed.
- **Refactoring Solution**: Replace Conditionals with Polymorphism or the Strategy Pattern.

```python
# ❌ VULNERABLE / SMELL: Cyclomatic Complexity = 14
def calculate_discount(customer_type, cart_total, promo_code, loyalty_tier):
    discount = 0.0
    if customer_type == "VIP":
        if cart_total > 500:
            if loyalty_tier == "GOLD":
                discount = 0.30
            elif loyalty_tier == "SILVER":
                discount = 0.20
            else:
                discount = 0.15
        elif cart_total > 100:
            discount = 0.10
    elif customer_type == "WHOLESALE":
        if promo_code == "BULK2025":
            discount = 0.25
        else:
            discount = 0.18
    elif customer_type == "STANDARD":
        if promo_code == "WELCOME":
            discount = 0.05
    return discount
```

```python
# ✅ REFACTORED: Strategy Pattern with Lookup Dispatch (Complexity = 2)
from typing import Callable, Dict

DISCOUNT_STRATEGIES: Dict[str, Callable[[float, str, str], float]] = {
    "VIP": lambda total, promo, tier: 0.30 if tier == "GOLD" and total > 500 else 0.15,
    "WHOLESALE": lambda total, promo, tier: 0.25 if promo == "BULK2025" else 0.18,
    "STANDARD": lambda total, promo, tier: 0.05 if promo == "WELCOME" else 0.0,
}

def calculate_discount(customer_type: str, cart_total: float, promo_code: str, loyalty_tier: str) -> float:
    strategy = DISCOUNT_STRATEGIES.get(customer_type, lambda *args: 0.0)
    return strategy(cart_total, promo_code, loyalty_tier)
```

---

### Smell 2: God Class / Monolithic Controller Anti-Pattern
- **Problem**: A single class handles database queries, HTTP presentation, authentication, PDF generation, email dispatch, and business calculations (> 300 lines of code or > 15 public methods).
- **Security Impact**: Breaking changes in one feature inadvertently introduce vulnerabilities in unrelated auth or payment handlers.
- **Refactoring Solution**: Extract specialized service delegates conforming to the Single Responsibility Principle (SRP).

```java
// ❌ SMELL: God Class handling everything in one controller
public class AccountController {
    public void registerUser() { /* DB query, hashing, email dispatch */ }
    public void generateInvoicePdf() { /* PDF rendering logic */ }
    public void processPayment() { /* Stripe API call */ }
    public void resetPassword() { /* Token generation and SMTP */ }
    public void auditAdminAction() { /* Database logging */ }
}

// ✅ REFACTORED: Separated by Single Responsibility Principle
public class RegistrationController { private final UserService userService; }
public class InvoiceController { private final InvoicePdfService invoicePdfService; }
public class PaymentController { private final PaymentGatewayService paymentService; }
```

---

### Smell 3: Long Method / Giant Action (> 50 Lines)
- **Problem**: Monolithic methods doing multiple sequential tasks in one long block of code.
- **Security Impact**: Resource variables (file handles, database connections, locks) remain open across long execution scopes, creating resource exhaustion vulnerabilities.
- **Refactoring Solution**: Extract Method refactoring to create cohesive, self-documenting subroutines.

---

### Smell 4: Deep Nesting / The Arrow Anti-Pattern (> 3 Levels)
- **Problem**: Code shaped like a sideways arrow `>` due to excessive indentation (`if` inside `for` inside `if` inside `try`).
- **Refactoring Solution**: Invert conditionals and apply **Guard Clauses (Early Return)**.

```python
# ❌ SMELL: Deep Nesting (Level 4)
def approve_transfer(account, recipient, amount, user):
    if user is not None:
        if user.is_authenticated:
            if not account.is_frozen:
                if account.balance >= amount:
                    if recipient.is_verified:
                        account.balance -= amount
                        recipient.balance += amount
                        return True
    return False

# ✅ REFACTORED: Flat Guard Clauses (Indentation Level 1)
def approve_transfer(account, recipient, amount, user) -> bool:
    if not user or not user.is_authenticated:
        raise PermissionError("Unauthenticated transfer request")
    if account.is_frozen:
        raise AccountFrozenError("Originating account is locked")
    if account.balance < amount:
        raise InsufficientFundsError("Insufficient account balance")
    if not recipient.is_verified:
        raise InvalidRecipientError("Recipient is unverified")
        
    account.balance -= amount
    recipient.balance += amount
    return True
```

---

### Smell 5: Primitive Obsession & Weak Domain Typing
- **Problem**: Using basic primitives (`str`, `int`, `dict`) to represent domain entities (e.g., using `String` for an email, currency, SSN, or user ID).
- **Security Impact**: Inviting SQL injection, XSS, and boundary errors because strings are not guaranteed to be valid domain models.
- **Refactoring Solution**: Use strongly typed Value Objects:
  - Python: Pydantic models or frozen dataclasses.
  - Java: Java Records (`public record EmailAddress(String value) { ... }`).

---

### Smell 6: Long Parameter Lists (> 4 Parameters)
- **Problem**: Methods requiring 5 to 10 separate arguments (`updateUser(id, name, email, phone, role, status, tier, dept, flag)`).
- **Security Impact**: Easy to transpose parameters (e.g., passing `role` into `status`), bypassing security constraints without compilation errors.
- **Refactoring Solution**: Introduce Parameter Object or the Builder Pattern.

```java
// ❌ SMELL: Easy to mix up parameters of same type
public void createUser(String name, String email, String role, String tenantId, boolean isActive, boolean isMfaEnabled) { ... }

// ✅ REFACTORED: Encapsulated Command DTO
public record CreateUserCommand(
    String name,
    EmailAddress email,
    UserRole role,
    TenantId tenantId,
    boolean isActive,
    boolean isMfaEnabled
) {}

public void createUser(CreateUserCommand command) { ... }
```

---

### Smell 7: Feature Envy & Inappropriate Intimacy
- **Problem**: A method in Class A spends more time accessing getters, properties, and internal state of Class B than its own data.
- **Security Impact**: Breaks encapsulation; internal access control rules of Class B are bypassed.
- **Refactoring Solution**: Apply **Move Method** refactoring so the logic resides inside the class owning the data ("Tell, Don't Ask").

---

### Smell 8: Shotgun Surgery & Divergent Change
- **Problem**: Modifying a single business rule requires editing 15 different source files across controllers, services, and models.
- **Security Impact**: Developers inevitably miss updating one file, leaving inconsistent authorization or validation logic.
- **Refactoring Solution**: Consolidate cohesive domain logic into unified service modules.

---

### Smell 9: Dead Code, Unused Imports & Ghost Variables
- **Problem**: Modules, functions, and variables that are imported or declared but never referenced in active execution paths.
- **Security Impact**: Increases attack surface, leads to dependency bloat (CVE exposure), and confuses security reviewers.
- **Refactoring Solution**: Automated removal via AST static analyzers (`ruff check --select F401` in Python; SonarQube in Java).

---

### Smell 10: Silent Failure & Exception Swallowing
- **Problem**: `catch (Exception e) {}` or bare `except: pass` masking runtime failures.
- **Security Impact**: The application continues execution in an invalid, corrupted, or unauthenticated state ("fail open").
- **Refactoring Solution**: Catch specific exception types, log diagnostic details, clean up state, and fail closed.

### Smell 11: Missing Docstrings and Code Documentation (CWE-1078)
- **Problem**: Public functions, classes, and APIs declared without docstrings or structured documentation (CWE-1078).
- **Maintainability & Security Impact**: Undocumented parameters and side-effects obscure authorization constraints, boundary assumptions, and expected input types, leading callers into insecure integration mistakes.
- **Refactoring Solution**: Document all functions according to PEP 257 (Python) with Args, Returns, and Raises sections, or Javadoc (Java) with @param, @return, and @throws annotations.


---

## 3. SOLID Principles in Modern Python and Java

| Principle | Core Mandate | Security Implication |
| :--- | :--- | :--- |
| **Single Responsibility (SRP)** | A class should have one, and only one, reason to change. | Isolates critical security routines (auth, encryption) from presentation logic. |
| **Open/Closed (OCP)** | Software entities should be open for extension, but closed for modification. | New authentication strategies can be added without modifying existing tested core validators. |
| **Liskov Substitution (LSP)** | Subtypes must be substitutable for their base types. | Subclasses cannot weaken security constraints established in parent classes. |
| **Interface Segregation (ISP)** | Clients should not be forced to depend on methods they do not use. | Limits interface surface area, reducing privilege leakage. |
| **Dependency Inversion (DIP)** | Depend upon abstractions, not concretions. | Allows easy swapping of mock dependencies during automated security testing. |

---

## 4. Refactoring Strategies for High-Risk Modules

When refactoring legacy codebases with high cyclomatic complexity:
1. **Establish Regression Safety Net**: Write automated unit tests covering all existing boundary paths prior to refactoring.
2. **Decompose Incrementally**: Extract one helper function or guard clause at a time; verify tests pass after each step.
3. **Isolate Security Boundaries**: Decouple database access and external HTTP calls from pure business validation logic.

---

## 5. Automated Code Quality Thresholds in AegisAI

The **AegisAI Code Analysis Agent** enforces the following strict automated thresholds:

| Metric | Target / Clean | Warning Threshold | Blocking Violation |
| :--- | :--- | :--- | :--- |
| **Cyclomatic Complexity** | $\le 6$ | $7 - 10$ | $> 10$ |
| **Method Line Count** | $\le 30$ lines | $31 - 50$ lines | $> 50$ lines |
| **Class Line Count** | $\le 200$ lines | $201 - 300$ lines | $> 300$ lines |
| **Nesting Depth** | $\le 2$ levels | $3$ levels | $\ge 4$ levels |
| **Method Parameters** | $\le 3$ params | $4$ params | $\ge 5$ params |
| **Unused Imports** | 0 | $\ge 1$ | Flagged as hygiene defect |
