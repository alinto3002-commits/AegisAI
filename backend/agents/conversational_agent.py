import os
import json
import logging
import urllib.request
from typing import List, Dict, Any, Optional

from backend.agents.base_agent import BaseAgent
from backend.models.schemas import ChatResponse, KnowledgeSearchResult
from backend.rag.retriever import SecureCodingRAGRetriever
from backend.config import GEMINI_API_KEY

logger = logging.getLogger(__name__)

class ConversationalCodeAssistant(BaseAgent):
    """
    Agent 5: Conversational Code Assistant
    RAG-powered conversational assistant grounded in the secure coding knowledge base.
    Allows developers to ask follow-up questions, request deeper explanations,
    or explore best-practice patterns for Python and Java.
    """

    def __init__(self):
        super().__init__(
            name="Conversational Code Assistant",
            description="RAG-powered conversational assistant for follow-up code review Q&A.",
        )
        self.retriever = SecureCodingRAGRetriever()

    def _call_gemini_api(self, prompt: str) -> Optional[str]:
        """Calls Google Gemini API with grounded context. Falls back gracefully on network error or timeout."""
        api_key = os.getenv("GEMINI_API_KEY", "") or GEMINI_API_KEY
        if not api_key:
            return None

        # Priority order of supported models on Google API
        models_to_try = [
            "gemini-3.8-flash",
            "gemini-3-flash-preview",
            "gemini-flash-latest",
            "gemini-2.5-flash-lite",
            "gemini-pro-latest",
        ]
        for model in models_to_try:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
                payload = json.dumps({
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024}
                }).encode("utf-8")

                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=4) as response:
                    if response.status == 200:
                        data = json.loads(response.read().decode("utf-8"))
                        candidates = data.get("candidates", [])
                        if candidates:
                            parts = candidates[0].get("content", {}).get("parts", [])
                            if parts:
                                return parts[0].get("text", "").strip()
            except Exception as e:
                err_str = str(e).lower()
                logger.info(f"Gemini API attempt with {model} failed: {e}. Trying fallback.")
                if "no such host" in err_str or "getaddrinfo failed" in err_str or "10054" in err_str or "timed out" in err_str:
                    break
                continue
        return None

    def run(
        self,
        query: str,
        code_context: Optional[str] = None,
        language: str = "python",
        findings_context: Optional[List[Dict[str, Any]]] = None,
        history: Optional[List[Dict[str, str]]] = None,
    ) -> ChatResponse:
        # 1. Retrieve grounded knowledge base documents
        sources: List[KnowledgeSearchResult] = self.retriever.retrieve_for_chat(
            user_query=query,
            code_context=code_context,
            language=language,
            top_k=3,
        )

        # 2. Try Gemini API first with grounded RAG context
        gemini_answer = None
        if os.getenv("GEMINI_API_KEY", "") or GEMINI_API_KEY:
            sources_summary = "\n".join([f"- {s.title} ({s.owasp_id or ''} {s.cwe_id or ''}): {s.content}" for s in sources])
            gemini_prompt = f"""You are AegisAI's expert code review and application security assistant.
Answer the developer's question grounded in the latest OWASP Top 10 (2025 Edition) and secure coding standards.

Developer Question: {query}
Target Programming Language: {language}

Active Code Context:
```{language}
{(code_context or "No active code provided")[:1500]}
```

Grounded OWASP / Security Guidelines:
{sources_summary}

Instructions:
1. Provide a direct, technically rigorous explanation.
2. If relevant, show secure replacement code and explain why it prevents the vulnerability.
3. Be concise and format with clear markdown headings and code blocks.
"""
            gemini_answer = self._call_gemini_api(gemini_prompt)

        # 3. Formulate grounded explanation (Gemini if available, otherwise local RAG)
        if gemini_answer:
            answer = gemini_answer
        else:
            answer = self._generate_answer(query, sources, code_context, language, findings_context)

        # 4. Formulate smart suggested follow-up questions
        suggested_followups = self._generate_followups(query, sources)

        return ChatResponse(
            answer=answer,
            sources=sources,
            suggested_followups=suggested_followups,
        )

    def _generate_answer(
        self,
        query: str,
        sources: List[KnowledgeSearchResult],
        code_context: Optional[str],
        language: str,
        findings: Optional[List[Dict[str, Any]]],
    ) -> str:
        q_lower = query.lower()

        # Check if the query is asking about a specific finding or line
        matching_finding = None
        if findings:
            for f in findings:
                title = f.get("title", "").lower()
                cwe = f.get("cwe_id", "").lower()
                category = f.get("category", "").lower()
                line = str(f.get("line_start", ""))
                if (line and f"line {line}" in q_lower) or any(w in q_lower for w in title.split()[:3]):
                    matching_finding = f
                    break

        if matching_finding:
            rem = matching_finding.get("remediation", {})
            return f"""### 🛡️ Analysis for: **{matching_finding.get('title')}**
- **Severity:** `{matching_finding.get('severity')}`
- **Standards:** `{matching_finding.get('owasp_category', 'OWASP Top 10 (2025)')}` | `{matching_finding.get('cwe_id', '')}`
- **Line Location:** Line {matching_finding.get('line_start')}

#### 💡 Why This Is A Risk:
{matching_finding.get('description')}

#### 🛠️ Recommended Remediation:
```diff
{rem.get('diff', 'See remediation tab')}
```

#### ✅ Secure Replacement Code:
```{language}
{rem.get('corrected_snippet', '# Use parameterized query or safe API')}
```

#### 📚 Grounded Knowledge Base Reference:
{sources[0].content if sources else 'Follow standard OWASP 2025 defensive coding practices.'}
"""

        # General RAG query answer using top source
        if sources:
            top_doc = sources[0]

            # Find matching source document to extract code examples if present
            raw_doc = None
            indexer_docs = getattr(getattr(self.retriever.store, "fallback_indexer", None), "documents", [])
            for d in indexer_docs:
                if d.get("id") == top_doc.id or d.get("title") == top_doc.title:
                    raw_doc = d
                    break

            lines = [
                f"### 📘 {top_doc.title}",
                f"**Category:** `{top_doc.category}` | **Standard:** `{top_doc.owasp_id or 'General'}` | `{top_doc.cwe_id or ''}`\n",
                f"{top_doc.content}\n",
            ]

            if raw_doc:
                vuln_ex = raw_doc.get("vulnerable_example")
                sec_ex = raw_doc.get("secure_example")
                guidelines = raw_doc.get("remediation_guidelines")

                if vuln_ex:
                    lines.append(f"#### ⚠️ Vulnerable Pattern to Avoid:\n```{language}\n{vuln_ex.strip()}\n```\n")
                if sec_ex:
                    lines.append(f"#### 🎯 Secure Implementation Pattern ({language.capitalize()}):\n```{language}\n{sec_ex.strip()}\n```\n")
                if guidelines and isinstance(guidelines, list):
                    lines.append("#### 🛡️ Remediation Guidelines:")
                    for g in guidelines:
                        lines.append(f"- {g}")
            else:
                lines.append(f"#### 🎯 Defensive Engineering Recommendation ({language.capitalize()}):")
                lines.append("- Apply defense-in-depth principles and parameterized APIs to strictly enforce type safety.")
                lines.append("- Refer to the official OWASP Top 10 (2025 Edition) secure coding standards.")

            return "\n".join(lines)

        # Fallback response
        return (
            f"Here is expert guidance regarding '{query}': "
            f"Always apply defense-in-depth, input validation, and parameterized APIs to prevent vulnerabilities."
        )

    def _generate_followups(self, query: str, sources: List[KnowledgeSearchResult]) -> List[str]:
        q_lower = query.lower()
        if "sql" in q_lower or "injection" in q_lower:
            return [
                "How do prepared statements prevent SQL injection under the hood?",
                "What is the difference between SQL injection and NoSQL injection?",
                "How can I safely pass dynamic table names in database queries?",
            ]
        elif "secret" in q_lower or "auth" in q_lower or "password" in q_lower:
            return [
                "How should I structure environment variables in Docker/Kubernetes?",
                "What is the best hashing algorithm for user passwords in 2025?",
                "How can I set up automated secret scanning in Git pre-commit hooks?",
            ]
        elif "pickle" in q_lower or "deserialization" in q_lower:
            return [
                "Why is Python pickle capable of Remote Code Execution (RCE)?",
                "How can I safely serialize Python dataclasses to JSON?",
                "How does Java ObjectInputFilter protect against gadget chains?",
            ]
        else:
            return [
                "Can you show a secure refactoring example for this issue?",
                "What are the relevant OWASP Top 10 (2025) compliance guidelines?",
                "How can we add automated CI/CD security tests to catch this early?",
            ]
