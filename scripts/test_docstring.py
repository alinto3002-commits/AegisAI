import sys
sys.path.insert(0, '.')
from backend.agents.orchestrator import MultiAgentOrchestrator
from backend.models.schemas import CodeSubmission

orch = MultiAgentOrchestrator()
code = open('backend/test_samples/python/vulnerable_sqli_secrets.py').read()
new_code = code.replace(
    'def authenticate_user(username, password):',
    'def authenticate_user(username, password):\n    """Authenticate user."""'
)
new_code = new_code.replace(
    'def read_user_file(filename):',
    'def read_user_file(filename):\n    """Read file."""'
)
rep = orch.analyze(CodeSubmission(code=new_code, language='python', filename='vulnerable_sqli_secrets.py'))
print('Docstring findings:', [f.title for f in rep.findings if 'docstring' in f.title.lower()])
print('Total findings:', len(rep.findings))
