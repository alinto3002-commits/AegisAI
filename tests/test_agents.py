import pytest
from backend.agents.code_analysis_agent import CodeAnalysisAgent
from backend.agents.security_agent import SecurityVulnerabilityAgent
from backend.agents.remediation_agent import RemediationAgent
from backend.agents.pr_summary_agent import PRSummaryAgent
from backend.agents.orchestrator import MultiAgentOrchestrator
from backend.models.schemas import CodeSubmission, FindingSeverity

def test_code_analysis_agent_smells():
    code_with_smells = """
from math import *
import unused_module_name

def very_long_function():
    # line 1
    # line 2
    # line 3
    # line 4
    # line 5
    # line 6
    # line 7
    # line 8
    # line 9
    # line 10
    # line 11
    # line 12
    # line 13
    # line 14
    # line 15
    # line 16
    # line 17
    # line 18
    # line 19
    # line 20
    # line 21
    # line 22
    # line 23
    # line 24
    # line 25
    # line 26
    # line 27
    # line 28
    # line 29
    # line 30
    # line 31
    # line 32
    # line 33
    # line 34
    # line 35
    # line 36
    # line 37
    # line 38
    return True
"""
    agent = CodeAnalysisAgent()
    findings = agent.run(code_with_smells, language="python")
    categories = [f.category for f in findings]

    assert any("Wildcard" in f.title or "Namespace" in f.category for f in findings)
    assert any("Long Method" in f.category for f in findings)
    assert any("Dead Code" in f.category or "unused_module_name" in f.title for f in findings)

def test_security_agent_owasp_2025_detection():
    vulnerable_code = """
import os
import hashlib
import pickle
import sqlite3

API_KEY = "ghp_abcdef1234567890abcdef1234567890"

def unsafe_query(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    conn = sqlite3.connect("app.db")
    conn.execute(query)

def unsafe_hash(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def unsafe_exec(cmd):
    os.system("echo " + cmd)

def unsafe_file(name):
    try:
        with open("/var/uploads/" + name, "rb") as f:
            return pickle.loads(f.read())
    except:
        pass
"""
    agent = SecurityVulnerabilityAgent()
    findings = agent.run(vulnerable_code, language="python")

    owasp_cats = [f.owasp_category for f in findings if f.owasp_category]

    # Verify key OWASP 2025 categories detected
    assert any("A04:2025" in cat for cat in owasp_cats)  # Cryptographic Failures (MD5)
    assert any("A05:2025" in cat for cat in owasp_cats)  # Injection (SQLi / Command)
    assert any("A07:2025" in cat for cat in owasp_cats)  # Authentication Failures (Hardcoded Secret)
    assert any("A08:2025" in cat for cat in owasp_cats)  # Software or Data Integrity Failures (Pickle)
    assert any("A10:2025" in cat for cat in owasp_cats)  # Mishandling Exceptional Conditions (Bare except)

    severities = [f.severity for f in findings]
    assert FindingSeverity.CRITICAL in severities

def test_remediation_agent():
    sec_agent = SecurityVulnerabilityAgent()
    rem_agent = RemediationAgent()

    code = 'cursor.execute(f"SELECT * FROM users WHERE username = \'{user}\'")'
    findings = sec_agent.run(code, language="python")
    assert len(findings) > 0

    remediated = rem_agent.run(findings, code, language="python")
    first = remediated[0]
    assert first.remediation is not None
    assert first.remediation.corrected_snippet != ""
    assert "parameterized" in first.remediation.corrected_snippet.lower() or "?" in first.remediation.corrected_snippet
    assert first.remediation.diff != ""
    assert first.remediation.unit_test_code is not None

def test_pr_summary_agent_scoring():
    sec_agent = SecurityVulnerabilityAgent()
    pr_agent = PRSummaryAgent()

    vulnerable_code = 'API_SECRET = "AKIA1234567890123456"\nos.system("ping " + host)'
    findings = sec_agent.run(vulnerable_code, language="python")

    summary = pr_agent.run(findings, filename="service.py", language="python", loc=2)
    assert summary.health_score < 60
    assert summary.verdict == "BLOCKING_SECURITY_RISK"
    assert "Critical" in summary.risk_level or "High" in summary.risk_level

def test_multi_agent_orchestrator_end_to_end():
    orchestrator = MultiAgentOrchestrator()
    clean_code = """
import os

def add_numbers(a: int, b: int) -> int:
    \"\"\"Adds two numbers safely.\"\"\"
    return a + b
"""
    sub = CodeSubmission(code=clean_code, language="python", filename="clean.py")
    report = orchestrator.analyze(sub)

    assert report.health_score >= 90
    assert report.verdict == "APPROVED"
    assert report.severity_counts["CRITICAL"] == 0
    assert report.severity_counts["HIGH"] == 0
    assert len(report.agent_execution_times) >= 4

def test_orchestrator_syntax_error_finding():
    orchestrator = MultiAgentOrchestrator()
    broken_code = "def invalid_syntax(x)\n    return x + 1\n"
    sub = CodeSubmission(code=broken_code, language="python", filename="broken.py")
    report = orchestrator.analyze(sub)

    assert report.health_score == 0
    assert report.verdict == "BLOCKING_SECURITY_RISK"
    assert report.severity_counts["CRITICAL"] == 1
    # Verify that the syntax error finding is populated!
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.severity == FindingSeverity.CRITICAL
    assert "Syntax Error" in finding.title
    assert finding.line_start == 1 or finding.line_start == 2
    assert finding.remediation is not None
    assert finding.remediation.unit_test_code is not None

