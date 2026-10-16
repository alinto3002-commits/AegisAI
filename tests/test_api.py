import pytest
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "OWASP Top 10 (2025)" in data["owasp_standard"]

def test_api_validate_endpoint():
    res = client.post("/api/validate", json={
        "code": "def hello():\n    return 'world'\n",
        "language": "python",
        "filename": "hello.py"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["is_valid"] is True
    assert data["line_count"] == 2

def test_api_analyze_endpoint():
    vulnerable_py = """
import sqlite3

def get_user(name):
    conn = sqlite3.connect("test.db")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    conn.execute(query)
"""
    res = client.post("/api/analyze", json={
        "code": vulnerable_py,
        "language": "python",
        "filename": "vuln.py"
    })
    assert res.status_code == 200
    data = res.json()
    assert "findings" in data
    assert data["health_score"] < 100
    assert len(data["findings"]) > 0

def test_api_chat_endpoint():
    res = client.post("/api/chat", json={
        "query": "How do I prevent SQL injection?",
        "language": "python",
    })
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert len(data["sources"]) > 0

def test_api_kb_search_endpoint():
    res = client.get("/api/kb/search?q=Authentication&limit=3")
    assert res.status_code == 200
    results = res.json()
    assert len(results) > 0

def test_api_export_endpoints():
    # Run analysis first
    res = client.post("/api/analyze", json={
        "code": "print('hello world')",
        "language": "python",
        "filename": "main.py"
    })
    report_data = res.json()

    # Test JSON export
    res_json = client.post("/api/export/json", json=report_data)
    assert res_json.status_code == 200
    assert res_json.headers["content-type"] == "application/json"

    # Test Markdown export
    res_md = client.post("/api/export/markdown", json=report_data)
    assert res_md.status_code == 200
    assert "text/markdown" in res_md.headers["content-type"]

    # Test PDF export
    res_pdf = client.post("/api/export/pdf", json=report_data)
    assert res_pdf.status_code == 200
    assert "application/pdf" in res_pdf.headers["content-type"]
    assert len(res_pdf.content) > 1000
