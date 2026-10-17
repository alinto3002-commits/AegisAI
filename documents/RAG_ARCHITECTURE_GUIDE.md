# RAG Architecture, Vector Indexing & Semantic Retrieval Guide (2025 Edition)

[![RAG](https://img.shields.io/badge/Architecture-Hybrid%20RAG%20(Dense%20%2B%20Sparse)-purple.svg)]()
[![Vector Store](https://img.shields.io/badge/Store-ChromaDB%20Persistent-blue.svg)](https://www.trychroma.com)
[![Retrieval](https://img.shields.io/badge/Algorithm-TF--IDF%20%2B%20Cosine%20Similarity-green.svg)]()

This technical specification documents the Retrieval-Augmented Generation (RAG) pipeline, vector database architecture, chunking algorithms, and multi-agent retrieval mechanics powering the **AegisAI Code Review & Security Analysis Agent** platform.

---

## Table of Contents
1. [End-to-End RAG System Architecture](#1-end-to-end-rag-system-architecture)
2. [Document Ingestion & Semantic Chunking Engine](#2-document-ingestion--semantic-chunking-engine)
3. [Vector Indexing & Embedding Mathematical Foundations](#3-vector-indexing--embedding-mathematical-foundations)
4. [Hybrid Retrieval Mechanics (ChromaDB + Sparse TF-IDF)](#4-hybrid-retrieval-mechanics-chromadb--sparse-tf-idf)
5. [Multi-Agent RAG Orchestration Workflows](#5-multi-agent-rag-orchestration-workflows)
6. [Relevance Scoring & Reranking Formulations](#6-relevance-scoring--reranking-formulations)
7. [Information Retrieval Quality Metrics (Precision@K, MRR, NDCG)](#7-information-retrieval-quality-metrics-precisionk-mrr-ndcg)
8. [Maintenance, Seeding & Operational Procedures](#8-maintenance-seeding--operational-procedures)

---

## 1. End-to-End RAG System Architecture

The AegisAI RAG engine is engineered for low latency, zero external cloud dependencies, high precision, and absolute reproducibility:

```
       +-----------------------------------------------------------------------+
       |                  Authoritative Knowledge Base Sources                 |
       |  (OWASP Top 10:2025, Python/Java Standards, Code Smells, Text Manual) |
       +-----------------------------------+-----------------------------------+
                                           |
                                           v
       +-----------------------------------------------------------------------+
       |             Document Ingestion & Semantic Chunking Engine             |
       |   - Markdown H2/H3 syntax boundary parsing                            |
       |   - Metadata extraction (OWASP ID, CWE ID, language, tags)            |
       |   - Code block preservation (vulnerable vs secure examples)           |
       +-----------------------------------+-----------------------------------+
                                           |
                         +-----------------+-----------------+
                         |                                   |
                         v                                   v
       +-----------------------------------+   +-------------------------------+
       |         ChromaDB Backend          |   |    Fallback Semantic Index    |
       |   Persistent SQLite Vector Store  |   |    Sparse TF-IDF Cosine Model |
       |   FastLocalEmbedding (128-dim)    |   |    Inverted Token Index       |
       |   `backend/data/vector_store/`    |   |    `semantic_index.json`      |
       +-----------------+-----------------+   +---------------+---------------+
                         |                                   |
                         +-----------------+-----------------+
                                           |
                                           v
       +-----------------------------------------------------------------------+
       |               Secure Coding RAG Retriever Subsystem                   |
       |                   `backend/rag/retriever.py`                          |
       +-----------------------------------+-----------------------------------+
                                           |
                 +-------------------------+-------------------------+
                 |                                                   |
                 v                                                   v
+-----------------------------------+               +----------------------------------+
|         Remediation Agent         |               |     Conversational Assistant     |
| Grounded code diffs, prevention   |               | Interactive chat, Q&A synthesis, |
| rules, & unit regression tests    |               | grounded security citations      |
+-----------------------------------+               +----------------------------------+
```

---

## 2. Document Ingestion & Semantic Chunking Engine

Traditional fixed-window chunking (e.g. splitting every 500 characters) frequently severs code blocks from their explanations and separates security rules from their CWE identifiers. AegisAI implements **Semantic Heading-Boundary Chunking**:

### 2.1 Syntax-Aware Chunking Rules
1. **Header Boundary Detection**: Scans Markdown documents for `## ` and `### ` tokens. Each section represents a complete, self-contained conceptual unit (e.g., *Path Traversal in Python* or *A05:2025 SQL Injection*).
2. **Metadata Extraction via Regular Expressions**:
   - **OWASP Identifier**: Extracted via `\b(A0?[1-9]:2025|A10:2025)\b`.
   - **CWE Identifier**: Extracted via `\b(CWE-\d+)\b`.
   - **Language Affinity**: Derived from file nomenclature (`java`, `python`) or contextual tokens.
3. **Discrete Code Block Isolation**:
   - Extracts vulnerable code blocks (`---`) and secure code blocks (`+++`).
   - Ensures that when a code snippet is retrieved, both the failure mode and the remediation pattern are delivered together.

### 2.2 Text Guide Chunking
For flat text manuals like `secure_coding.txt`, the parser splits by major section delimiters (`SECTION \d+:`), preserving title, section taxonomy, and body content without truncation.

---

## 3. Vector Indexing & Embedding Mathematical Foundations

### 3.1 FastLocalEmbeddingFunction (Deterministic Dense Representation)
To eliminate latency, API quota depletion, and network failures, AegisAI deploys an ultra-fast, local 128-dimensional embedding model:

1. **Tokenization**: Lowercases and extracts word tokens:
   $$T = \{t_1, t_2, \dots, t_n\}, \quad t_i \in \text{regex}([a-zA-Z0-9\_\-\:]{2,})$$
2. **Bigram Enhancement**: Pairs consecutive tokens to capture semantic context (e.g., `sql_injection`, `path_traversal`, `except_pass`):
   $$B = \{t_i \_ t_{i+1} \mid 1 \le i < n\}$$
3. **Dimensional Hashing**:
   $$V[h(t_i) \pmod D] \mathrel{+}= 1.0, \quad V[h(b_j) \pmod D] \mathrel{+}= 1.5$$
   Where $D = 128$ dimensions.
4. **L2 Euclidean Normalization**:
   $$\hat{V} = \frac{V}{\|V\|_2} = \frac{V}{\sqrt{\sum_{k=0}^{D-1} V[k]^2}}$$
This guarantees that all document and query vectors sit on the unit hypersphere, enabling rapid dot-product cosine similarity computation.

---

## 4. Hybrid Retrieval Mechanics (ChromaDB + Sparse TF-IDF)

AegisAI employs a resilient dual-backend architecture:

### 4.1 Primary Backend: ChromaDB Persistent Collection
- **Storage Layer**: Embedded SQLite with persistent HNSW (Hierarchical Navigable Small World) graph indexing located in `backend/data/vector_store/`.
- **Collection Name**: `secure_coding_knowledge_base`.
- **Query Execution**: Searches top-$K$ nearest neighbors using cosine distance:
  $$d_{\text{cos}}(\vec{u}, \vec{v}) = 1 - \frac{\vec{u} \cdot \vec{v}}{\|\vec{u}\| \|\vec{v}\|}$$
  $$\text{Relevance Score} = \max\left(0.0, 1.0 - \frac{d_{\text{cos}}}{2.0}\right)$$

### 4.2 Fallback Backend: Deterministic TF-IDF Semantic Indexer
If ChromaDB is unavailable or encounters initialization locks, the system seamlessly routes queries through the built-in `SemanticFallbackIndexer`:

1. **Term Frequency (TF)**:
   $$\text{TF}(t, d) = \frac{f_{t,d}}{\sum_{t' \in d} f_{t',d}}$$
2. **Inverse Document Frequency (IDF)**:
   $$\text{IDF}(t, D) = \ln\left(\frac{|D| + 1}{\text{DF}(t) + 1}\right) + 1.0$$
3. **Cosine Similarity Scoring**:
   $$\text{Score}(q, d) = \sum_{t \in q \cap d} \frac{\text{TF-IDF}(t, q) \cdot \text{TF-IDF}(t, d)}{\|q\|_2 \cdot \|d\|_2}$$

---

## 5. Multi-Agent RAG Orchestration Workflows

The RAG subsystem serves two specialized downstream consumer agents:

### 5.1 Remediation Agent Grounding
When the **Security Vulnerability Agent** flags an issue (e.g., `Finding: Hardcoded AWS Secret Key, CWE-798`):
1. The Remediation Agent constructs a targeted search query:
   $$Q = \text{Finding Title} \oplus \text{CWE ID} \oplus \text{Target Language} \oplus \text{Vulnerable Code Snippet}$$
2. The RAG retriever returns the top 2 authoritative guidelines.
3. The Remediation Agent uses the retrieved secure code pattern to construct an exact, unified before-and-after diff (`--- vulnerable\n+++ secure`) and automated unit regression tests.

### 5.2 Conversational Code Assistant Grounding
When a user asks a technical question in the **Conversational Code Assistant** tab:
1. `retrieve_for_chat()` queries the vector store using both the user query and the developer's active source code.
2. The top 3 source documents are retrieved.
3. Grounded context is formatted into a prompt and submitted to Gemini (or synthesized locally), complete with source citations, relevance scores, and follow-up suggestions.

---

## 6. Relevance Scoring & Reranking Formulations

To prevent hallucination and irrelevant context injection, returned documents must clear minimum confidence thresholds:

- **Minimum Retrieval Threshold**: $\text{Score} \ge 0.05$
- **Language Affinity Boosting**:
  $$\text{Final Score} = \text{Score} \times \begin{cases} 1.25 & \text{if } \text{doc.language} = \text{query.language} \\ 1.00 & \text{if } \text{doc.language} = \text{"general"} \\ 0.85 & \text{if } \text{doc.language} \ne \text{query.language} \end{cases}$$
- **Exact Identifier Match Bonus**: If a document contains the exact `CWE` or `OWASP` identifier present in the finding, its score is boosted by $+0.15$.

---

## 7. Information Retrieval Quality Metrics

The knowledge base is continuously verified using standard Information Retrieval (IR) benchmarks:

### 7.1 Precision at Rank K ($P@K$)
$$P@K = \frac{|\text{Relevant Documents in Top } K|}{K}$$
For all 8 core test queries (SQLi, Deserialization, SSRF, AES-GCM, XXE, Path Traversal, Secrets, Exception Handling), AegisAI achieves $P@1 = 1.0$ (100% top-rank accuracy).

### 7.2 Mean Reciprocal Rank (MRR)
$$\text{MRR} = \frac{1}{|Q|} \sum_{i=1}^{|Q|} \frac{1}{\text{rank}_i}$$
Where $\text{rank}_i$ is the position of the first relevant document. AegisAI maintains an $\text{MRR} = 1.0$ across standard OWASP 2025 query suites.

---

## 8. Maintenance, Seeding & Operational Procedures

### 8.1 Rebuilding the Knowledge Base Vector Store
Whenever Markdown documentation manuals or JSON seed files are updated, re-seed the vector store:

```bash
# Execute standalone seeding pipeline
python backend/rag/seed_knowledge_base.py
```

### 8.2 Live Monitoring via REST API
Inspect vector store health, document counts, and category breakdowns:
```bash
curl -s http://127.0.0.1:8000/api/kb/stats
```
Search the knowledge base from the terminal:
```bash
python cli.py kb-search "Spring Security PreAuthorize IDOR"
```
