import pytest
from backend.rag.vector_store import SecureCodingVectorStore
from backend.rag.retriever import SecureCodingRAGRetriever
from backend.agents.conversational_agent import ConversationalCodeAssistant

def test_vector_store_retrieval():
    store = SecureCodingVectorStore()
    stats = store.get_stats()
    assert stats["total_documents"] >= 10

    results = store.query("SQL injection database prepared statements", top_k=3)
    assert len(results) > 0
    top = results[0]
    assert top.relevance_score > 0
    assert any("SQL" in r.title or "Injection" in r.title for r in results)

def test_rag_retriever_context_for_finding():
    retriever = SecureCodingRAGRetriever()
    results = retriever.retrieve_for_finding(
        title="SQL Injection via Formatted String",
        category="Injection",
        owasp_id="A05:2025",
        cwe_id="CWE-89",
        language="python"
    )
    assert len(results) > 0
    assert any("SQL" in r.title or "A05" in str(r.owasp_id) for r in results)

def test_conversational_code_assistant():
    assistant = ConversationalCodeAssistant()
    response = assistant.run(
        query="Why is string concatenation in SQL queries dangerous?",
        code_context="cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        language="python",
    )
    assert response.answer != ""
    assert len(response.sources) > 0
    assert len(response.suggested_followups) > 0
