import logging
from typing import List, Dict, Any, Optional
from backend.rag.vector_store import SecureCodingVectorStore
from backend.models.schemas import KnowledgeSearchResult

logger = logging.getLogger(__name__)

class SecureCodingRAGRetriever:
    """
    RAG Retriever for the Secure Coding Knowledge Base.
    Retrieves grounded context for remediation generation and conversational Q&A.
    """

    def __init__(self):
        self.store = SecureCodingVectorStore()

    def search(self, query: str, top_k: int = 4) -> List[KnowledgeSearchResult]:
        """Direct semantic search against indexed OWASP 2025 & secure guidelines."""
        return self.store.query(query, top_k=top_k)

    def retrieve_for_finding(
        self,
        title: str,
        category: str,
        owasp_id: Optional[str] = None,
        cwe_id: Optional[str] = None,
        language: str = "general",
    ) -> List[KnowledgeSearchResult]:
        """Retrieves targeted remediation guidelines matching a specific finding."""
        query_terms = [title, category]
        if owasp_id:
            query_terms.append(owasp_id)
        if cwe_id:
            query_terms.append(cwe_id)
        if language and language != "general":
            query_terms.append(language)

        query = " ".join(query_terms)
        return self.store.query(query, top_k=2)

    def retrieve_for_chat(
        self,
        user_query: str,
        code_context: Optional[str] = None,
        language: str = "python",
        top_k: int = 3,
    ) -> List[KnowledgeSearchResult]:
        """Retrieves context specifically for conversational assistant queries."""
        # Combine query with relevant code keywords if available
        search_prompt = user_query
        if code_context:
            first_few_lines = " ".join(code_context.splitlines()[:10])
            search_prompt += f" {language} {first_few_lines[:150]}"

        return self.store.query(search_prompt, top_k=top_k)
