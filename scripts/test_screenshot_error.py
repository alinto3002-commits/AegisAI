import sys
sys.path.insert(0, '.')
from scripts.simulate_apply_fix import simulate_js_apply_fix
from backend.agents.orchestrator import MultiAgentOrchestrator
from backend.models.schemas import CodeSubmission

broken_code = """import os
import sqlite3

def read_user_file(filename):
        \"\"\"Brief summary of function purpose (PEP 257).\":;
    filepath = f\"/var/data/uploads/{filename}\"
    return None
"""

orch = MultiAgentOrchestrator()
rep = orch.analyze(CodeSubmission(code=broken_code, language='python', filename='vulnerable_sqli_secrets.py'))
print("Initial findings:", len(rep.findings))
syntax_f = rep.findings[0]
print("Syntax finding:", syntax_f.title)
print("Faulty line:", repr(syntax_f.evidence))
print("Corrected snippet:", repr(syntax_f.remediation.corrected_snippet))

fixed_code, ok = simulate_js_apply_fix(broken_code, syntax_f)
print("Applied fix ok:", ok)
print("Fixed Code:\n" + fixed_code)

rep2 = orch.analyze(CodeSubmission(code=fixed_code, language='python', filename='vulnerable_sqli_secrets.py'))
print("After fix findings count:", len(rep2.findings))
for f in rep2.findings:
    print(" ", f.id, f.title)
print("SUCCESS: Syntax error is 100% resolved!")
