import sys
sys.path.insert(0, '.')
from backend.agents.orchestrator import MultiAgentOrchestrator
from backend.models.schemas import CodeSubmission

test_cases = [
    "impot sqllite3\n",
    "import sqllite3\nx = sqlite3.connect(':memory:')\n",
    "deff compute_suum(a, b):\n    return a + b\n",
    "from math impot sqrtt\nprint(sqrt(4))\n"
]

orch = MultiAgentOrchestrator()
for code in test_cases:
    print('------------------------------------')
    print('Input code:\n' + code)
    rep = orch.analyze(CodeSubmission(code=code, language='python', filename='test.py'))
    for f in rep.findings:
        print(' Finding:', f.id, '-', f.title)
        print(' Evidence:', repr(f.evidence))
        print(' Corrected:', repr(f.remediation.corrected_snippet if f.remediation else None))
