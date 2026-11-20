import sys
sys.path.insert(0, '.')
from backend.agents.conversational_agent import ConversationalCodeAssistant

assistant = ConversationalCodeAssistant()
resp = assistant.run(
    query="How do I prevent SQL injection in Python with SQLite?",
    code_context="query = f'SELECT * FROM users WHERE username = {username}'\ncursor.execute(query)",
    language="python"
)
print("=== GEMINI ASSISTANT RESPONSE ===")
print(resp.answer)
print("=== SOURCES ===")
for s in resp.sources:
    print(f"- {s.title} ({s.owasp_id})")
print("=== FOLLOW-UPS ===")
for q in resp.suggested_followups:
    print(f"- {q}")
