# Secure Coding Knowledge Base (RAG Documents)

This directory contains the authoritative knowledge documents indexed into the **AegisAI** ChromaDB vector store and semantic search engine.

---

## Document Index

| File | Scope & Content | Target Languages |
| :--- | :--- | :--- |
| [`OWASP_TOP_10_2025_NOTES.md`](OWASP_TOP_10_2025_NOTES.md) | Official OWASP Top 10:2025 categories, score tables, descriptions, prevention rules, attack scenarios, and references downloaded directly from `https://owasp.org/Top10/2025/`. | General / Polyglot |
| [`PYTHON_SECURE_CODING_2025.md`](PYTHON_SECURE_CODING_2025.md) | High-impact Python security practices, AST static analysis considerations, OWASP 2025 Python code patterns (vulnerable vs secure diffs). | Python |
| [`JAVA_SECURE_CODING_2025.md`](JAVA_SECURE_CODING_2025.md) | Enterprise Java (Spring Boot, Jakarta EE) secure coding standards, PreparedStatement, Spring Security, XXE mitigation, and serialization defenses. | Java |
| [`CODE_SMELLS_AND_BEST_PRACTICES_2025.md`](CODE_SMELLS_AND_BEST_PRACTICES_2025.md) | Architectural code smells, cyclomatic complexity limits (>10), God classes, long methods, deep nesting, and clean refactoring patterns. | Python, Java |
| [`SECURE_CODING_GUIDELINES_2025.md`](SECURE_CODING_GUIDELINES_2025.md) | Master defense-in-depth security principles: Zero Trust, input validation, cryptography, session management, and logging. | General |
| [`SOURCE_REGISTER.md`](SOURCE_REGISTER.md) | Provenance tracking, canonical URLs, last verified dates, and CWE taxonomy mappings. | General |
| [`RAG_ARCHITECTURE_GUIDE.md`](RAG_ARCHITECTURE_GUIDE.md) | System architecture guide for document chunking, ChromaDB vector indexing, and multi-agent retrieval. | Architecture |

---

## Ingesting & Re-indexing

Run the ingestion script to rebuild the ChromaDB collection in `knowledge_base/chroma_db/`:
```bash
python backend/rag/seed_knowledge_base.py
```
