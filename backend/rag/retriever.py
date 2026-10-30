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
        code_context: Optional[str] = None,
    ) -> List[KnowledgeSearchResult]:
        """
        Retrieves targeted remediation guidelines matching a specific finding.
        Guarantees that every query includes language, exact finding type,
        CWE identifier, category, and relevant source-code context.
        Applies relevance filtering to reject unrelated documents.
        """
        query_terms = []
        if language and language != "general":
            query_terms.append(f"Language: {language}")
        query_terms.append(f"Finding Type: {title}")
        if cwe_id:
            query_terms.append(f"CWE: {cwe_id}")
        if category:
            query_parts_cat = category.replace("OWASP 2025", "").strip()
            query_terms.append(f"Category: {query_parts_cat}")
        if owasp_id:
            query_terms.append(f"OWASP: {owasp_id}")
        if code_context:
            from backend.agents.security_agent import mask_secret_literal
            sanitized_context = mask_secret_literal(code_context.strip())
            ctx_summary = " ".join([l.strip() for l in sanitized_context.splitlines() if l.strip()][:3])
            query_terms.append(f"Context: {ctx_summary[:120]}")

        query = " ".join(query_terms)
        raw_results = self.store.query(query, top_k=10)

        # Relevance filtering: reject unrelated research metrics, background text, or cross-domain noise
        filtered = []
        title_lower = title.lower()
        cwe_str = (cwe_id or "").upper()
        code_lower = (code_context or "").lower()

        # Specific domain flags
        is_prng = "338" in cwe_str or "prng" in title_lower or "random" in title_lower
        is_hash = "328" in cwe_str or "hash" in title_lower or "md5" in title_lower or "sha" in title_lower
        is_pwd_hash = is_hash and ("password" in title_lower or any(k in code_lower for k in ["pass", "pwd", "auth", "credential", "login", "user_pass"]))
        is_data_hash = is_hash and not is_pwd_hash and any(k in f"{title_lower} {code_lower}" for k in ["checksum", "crc", "file", "integrity", "content", "payload", "digest"])
        is_ecb = "327" in cwe_str or "ecb" in title_lower or "cipher" in title_lower or "aes" in title_lower
        is_secret = "798" in cwe_str or "secret" in title_lower or "credential" in title_lower or "api key" in title_lower
        is_jwt = "347" in cwe_str or ("jwt" in title_lower and "hardcoded" not in title_lower)
        is_throws = "398" in cwe_str or "throws exception" in title_lower or "exception handling" in title_lower
        is_wildcard = "710" in cwe_str or "wildcard" in title_lower
        is_docstring = "1078" in cwe_str or "docstring" in title_lower or "missing documentation" in title_lower

        unrelated_titles = {
            "background", "mapped cwes", "references", "overview", "sources",
            "document index", "table of contents", "workflow"
        }

        for doc in raw_results:
            d_title_lower = doc.title.lower()
            d_content_lower = doc.content.lower()
            d_full = f"{d_title_lower} {d_content_lower}"
            d_cwe = (doc.cwe_id or "").upper()

            # Reject research metrics and generic architectural notes
            if any(term in d_title_lower for term in ["$p@", "precision at rank", "recall at rank", "architecture guide", "evaluation engine"]):
                continue
            if d_title_lower in unrelated_titles:
                continue

            # Reject language mismatch (e.g. Python doc for Java finding or vice-versa)
            if language in ("java", "python") and doc.language not in ("general", language, None, ""):
                continue

            # PRNG filtering: reject password hashing, ciphers, SQL
            if is_prng:
                if any(k in d_title_lower for k in ["bcrypt", "argon2", "password", "cipher", "injection"]):
                    continue
                if not any(k in d_full for k in ["securerandom", "random", "prng", "cwe-338"]):
                    continue

            # MD5/SHA-1 password hashing: reject PRNG, ciphers, SQL
            if is_pwd_hash:
                if any(k in d_title_lower for k in ["prng", "random", "cipher", "injection"]):
                    continue
                if not any(k in d_full for k in ["argon2", "bcrypt", "password", "cwe-328", "hash"]):
                    continue

            # MD5/SHA-1 data integrity: reject PRNG, ciphers
            if is_data_hash:
                if any(k in d_title_lower for k in ["prng", "random", "argon2", "bcrypt", "injection"]):
                    continue

            # AES/ECB: reject password hashing, PRNG, SQL
            if is_ecb:
                if any(k in d_title_lower for k in ["password", "argon2", "bcrypt", "prng", "random", "injection"]):
                    continue
                if not any(k in d_full for k in ["aes", "cipher", "gcm", "cwe-327", "encryption"]):
                    continue

            # Hardcoded secrets: reject SQL, injection, deserialization
            if is_secret:
                if any(k in d_title_lower for k in ["sql", "injection", "deserialization", "pickle"]):
                    continue
                if not any(k in d_full for k in ["secret", "vault", "credential", "cwe-798", "environment", "api_key"]):
                    continue

            # Generic throws Exception: reject research metrics, crypto, SQL
            if is_throws:
                if any(k in d_title_lower for k in ["sql", "injection", "cryptographic", "cipher", "hash"]):
                    continue
                if not any(k in d_full for k in ["exception", "throws", "cwe-398", "catch"]):
                    continue

            # JWT algorithm configuration: reject SQL, command injection, path traversal
            if is_jwt:
                if any(k in d_title_lower for k in ["sql", "traversal", "command", "pickle"]):
                    continue
                if not any(k in d_full for k in ["jwt", "jjwt", "cwe-347", "token", "nimbus"]):
                    continue

            # Wildcard imports: reject cyclomatic complexity or nesting
            if is_wildcard:
                if any(k in d_full for k in ["cyclomatic", "nesting", "cwe-1075"]):
                    continue

            # Missing Docstrings / Documentation: reject all unrelated security vulnerability categories (A01-A10, SQL, etc.)
            if is_docstring:
                if any(k in d_title_lower for k in ["a0", "a1", "owasp", "sql", "injection", "cryptographic", "hash", "secret", "traversal", "pickle", "deserialization", "cwe-532", "cwe-1059"]):
                    continue
                if not any(k in d_full for k in ["docstring", "documentation", "pep 257", "pep-257", "javadoc", "cwe-1078", "smell-04", "smell"]):
                    continue

            filtered.append(doc)

        # Ensure exact curated guideline is surfaced at top rank
        target_map = {
            ("java", "CWE-338"): "JAVA-SEC-10",
            ("java", "CWE-328"): "JAVA-SEC-09",
            ("java", "CWE-327"): "JAVA-SEC-11",
            ("java", "CWE-798"): "JAVA-SEC-16",
            ("java", "CWE-347"): "JAVA-SEC-17",
            ("java", "CWE-398"): "JAVA-SEC-21",
            ("java", "CWE-1078"): "SMELL-04",
            ("python", "CWE-338"): "PY-SEC-12",
            ("python", "CWE-328"): "PY-SEC-11",
            ("python", "CWE-327"): "PY-SEC-13",
            ("python", "CWE-798"): "PY-SEC-17",
            ("python", "CWE-347"): "PY-SEC-18",
            ("python", "CWE-1078"): "SMELL-04",
        }

        target_id = target_map.get((language, cwe_str))
        if target_id:
            # If target_id is not already the top result, fetch it from store and prioritize it
            if not (filtered and filtered[0].id == target_id):
                for candidate in self.store.fallback_indexer.documents:
                    if candidate.get("id") == target_id:
                        curated = KnowledgeSearchResult(
                            id=candidate.get("id"),
                            title=candidate.get("title", ""),
                            category=candidate.get("category", "General"),
                            owasp_id=candidate.get("owasp_id"),
                            cwe_id=candidate.get("cwe_id"),
                            language=candidate.get("language", language),
                            content=candidate.get("content", ""),
                            relevance_score=1.0,
                        )
                        filtered = [f for f in filtered if f.id != target_id]
                        filtered.insert(0, curated)
                        break

        return filtered[:2]

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
