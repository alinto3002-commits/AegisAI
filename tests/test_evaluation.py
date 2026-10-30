import pytest
import json
from pathlib import Path

from backend.agents.orchestrator import MultiAgentOrchestrator
from backend.models.schemas import CodeSubmission
from evaluation.evaluate import run_evaluation

def test_authservice_findings():
    """Verify that AuthService.java produces the exact expected findings matching the presentation benchmark."""
    sample_file = Path("evaluation/samples/java/AuthService.java")
    assert sample_file.exists()

    code = sample_file.read_text(encoding="utf-8")
    orchestrator = MultiAgentOrchestrator()
    report = orchestrator.analyze(CodeSubmission(code=code, language="java", filename="AuthService.java"))

    # Assert findings count and telemetry details
    assert len(report.findings) >= 6
    cwe_set = {f.cwe_id for f in report.findings if f.cwe_id}
    assert "CWE-328" in cwe_set  # Weak SHA-1 hash
    assert "CWE-338" in cwe_set  # Weak java.util.Random PRNG
    assert "CWE-327" in cwe_set  # ECB cipher mode
    assert "CWE-798" in cwe_set  # Hardcoded JWT & AES keys

    # Verify execution details are populated
    assert len(report.execution_details) >= 2
    sec_agent_detail = next(d for d in report.execution_details if "Security" in d.agent_name)
    assert len(sec_agent_detail.tools) >= 2
    assert len(sec_agent_detail.knowledge_sections_used) >= 3

def test_evaluation_pipeline_produces_artifacts():
    """Test that running the evaluation produces summary.csv and report.md."""
    run_evaluation()
    results_dir = Path("evaluation/results")
    assert (results_dir / "summary.csv").exists()
    assert (results_dir / "report.md").exists()

    # Verify CSV has valid header
    csv_text = (results_dir / "summary.csv").read_text(encoding="utf-8")
    assert "mode,agent,language,issues,found,recall" in csv_text
    assert "tools only" in csv_text
    assert "full" in csv_text
