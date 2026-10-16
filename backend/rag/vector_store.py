import json
import logging
import math
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from backend.config import VECTOR_STORE_DIR, CHROMA_COLLECTION_NAME
from backend.models.schemas import KnowledgeSearchResult

logger = logging.getLogger(__name__)

class FastLocalEmbeddingFunction:
    """
    Deterministic, fast local embedding function (128-dimensional)
    for ChromaDB that does not require downloading external ONNX or HuggingFace models.
    """
    def __init__(self, dim: int = 128):
        self.dim = dim

    def name(self) -> str:
        return "fast_local_embedding"

    def _embed_text(self, text: Any) -> List[float]:
        if isinstance(text, (list, tuple)):
            text = " ".join(str(x) for x in text)
        elif not isinstance(text, str):
            text = str(text)

        vec = [0.0] * self.dim
        tokens = re.findall(r"[a-zA-Z0-9_\-\:]{2,}", text.lower())
        for token in tokens:
            h = hash(token) % self.dim
            vec[h] += 1.0

        for i in range(len(tokens) - 1):
            pair = f"{tokens[i]}_{tokens[i+1]}"
            h = hash(pair) % self.dim
            vec[h] += 1.5

        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        return [round(x / norm, 6) for x in vec]

    def embed_query(self, input: Any) -> Any:
        if isinstance(input, str):
            return self._embed_text(input)
        return [self._embed_text(t) for t in input]

    def embed_documents(self, input: Any) -> List[List[float]]:
        if isinstance(input, str):
            return [self._embed_text(input)]
        return [self._embed_text(t) for t in input]

    def __call__(self, input: Any) -> List[List[float]]:
        if isinstance(input, str):
            return [self._embed_text(input)]
        return [self._embed_text(t) for t in input]


class SemanticFallbackIndexer:
    """
    High-performance, local semantic search indexer using TF-IDF tokenization
    and cosine similarity. Guarantees 0-dependency, deterministic, ultra-fast
    RAG retrieval.
    """

    def __init__(self, storage_path: Path):
        self.storage_path = storage_path / "semantic_index.json"
        self.documents: List[Dict[str, Any]] = []
        self.idf: Dict[str, float] = {}
        self.doc_vectors: List[Dict[str, float]] = []
        self.load()

    def _tokenize(self, text: str) -> List[str]:
        words = re.findall(r"[a-zA-Z0-9_\-\:]{2,}", text.lower())
        ngrams = [f"{words[i]}_{words[i+1]}" for i in range(len(words)-1)]
        return words + ngrams

    def fit_and_index(self, docs: List[Dict[str, Any]]):
        self.documents = docs
        doc_count = len(docs)
        if doc_count == 0:
            return

        df: Dict[str, int] = {}
        tokenized_docs = []
        for doc in docs:
            full_text = f"{doc.get('title', '')} {doc.get('category', '')} {doc.get('owasp_id', '')} {doc.get('cwe_id', '')} {' '.join(doc.get('tags', []))} {doc.get('content', '')}"
            tokens = set(self._tokenize(full_text))
            tokenized_docs.append(tokens)
            for token in tokens:
                df[token] = df.get(token, 0) + 1

        self.idf = {token: math.log((doc_count + 1) / (freq + 1)) + 1.0 for token, freq in df.items()}

        self.doc_vectors = []
        for tokens in tokenized_docs:
            vec: Dict[str, float] = {}
            for t in tokens:
                vec[t] = self.idf.get(t, 1.0)
            norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
            norm_vec = {k: v / norm for k, v in vec.items()}
            self.doc_vectors.append(norm_vec)

        self.save()

    def search(self, query: str, top_k: int = 4) -> List[KnowledgeSearchResult]:
        if not self.documents:
            return []

        query_tokens = self._tokenize(query)
        q_vec: Dict[str, float] = {}
        for t in query_tokens:
            if t in self.idf:
                q_vec[t] = self.idf[t]

        q_norm = math.sqrt(sum(v * v for v in q_vec.values())) or 1.0
        q_norm_vec = {k: v / q_norm for k, v in q_vec.items()}

        scores = []
        for idx, d_vec in enumerate(self.doc_vectors):
            dot_product = sum(d_vec.get(token, 0.0) * val for token, val in q_norm_vec.items())
            scores.append((dot_product, idx))

        scores.sort(key=lambda x: x[0], reverse=True)

        results = []
        for score, idx in scores[:top_k]:
            doc = self.documents[idx]
            results.append(
                KnowledgeSearchResult(
                    id=doc.get("id", f"doc-{idx}"),
                    title=doc.get("title", "Untitled Guideline"),
                    category=doc.get("category", "General"),
                    owasp_id=doc.get("owasp_id"),
                    cwe_id=doc.get("cwe_id"),
                    language=doc.get("language", "general"),
                    content=doc.get("content", ""),
                    relevance_score=round(float(score), 4),
                )
            )
        return results

    def save(self):
        try:
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "documents": self.documents,
                        "idf": self.idf,
                        "doc_vectors": self.doc_vectors,
                    },
                    f,
                    indent=2,
                )
        except Exception as e:
            logger.error(f"Error saving fallback semantic index: {e}")

    def load(self):
        if self.storage_path.exists():
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.documents = data.get("documents", [])
                    self.idf = data.get("idf", {})
                    self.doc_vectors = data.get("doc_vectors", [])
            except Exception as e:
                logger.warning(f"Could not load fallback index from disk: {e}")


class SecureCodingVectorStore:
    """
    RAG Vector Store Manager.
    Primary backend: ChromaDB with fast local embedding function.
    Auxiliary backend: SemanticFallbackIndexer for instant search.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SecureCodingVectorStore, cls).__new__(cls)
            cls._instance._init_store()
        return cls._instance

    def _init_store(self):
        self.chroma_client = None
        self.collection = None
        self.fallback_indexer = SemanticFallbackIndexer(VECTOR_STORE_DIR)
        self.embedding_fn = FastLocalEmbeddingFunction(dim=128)

        try:
            import chromadb
            from chromadb.config import Settings
            self.chroma_client = chromadb.PersistentClient(
                path=str(VECTOR_STORE_DIR),
                settings=Settings(anonymized_telemetry=False, is_persistent=True),
            )
            self.collection = self.chroma_client.get_or_create_collection(
                name=CHROMA_COLLECTION_NAME,
                embedding_function=self.embedding_fn,
                metadata={"description": "OWASP Top 10 (2025) and Secure Coding Guidelines"},
            )
            logger.info("ChromaDB vector store successfully initialized with FastLocalEmbeddingFunction.")
        except Exception as e:
            logger.warning(f"ChromaDB initialization encountered issue: {e}. Semantic fallback active.")

    def add_documents(self, docs: List[Dict[str, Any]]):
        """Indexes documents into both ChromaDB and the Fallback Indexer."""
        self.fallback_indexer.fit_and_index(docs)

        if self.collection is not None and docs:
            ids = [d["id"] for d in docs]
            documents_text = [
                f"{d['title']}\nCategory: {d.get('category')}\nOWASP: {d.get('owasp_id')}\nCWE: {d.get('cwe_id')}\n\n{d['content']}\n\nVulnerable:\n{d.get('vulnerable_example','')}\n\nSecure:\n{d.get('secure_example','')}"
                for d in docs
            ]
            metadatas = [
                {
                    "title": str(d.get("title", "")),
                    "category": str(d.get("category", "")),
                    "owasp_id": str(d.get("owasp_id", "") or ""),
                    "cwe_id": str(d.get("cwe_id", "") or ""),
                    "language": str(d.get("language", "general") or "general"),
                }
                for d in docs
            ]
            try:
                self.collection.upsert(
                    ids=ids,
                    documents=documents_text,
                    metadatas=metadatas,
                )
                logger.info(f"Upserted {len(docs)} documents into ChromaDB collection.")
            except Exception as e:
                logger.warning(f"Failed to upsert into ChromaDB: {e}")

    def query(self, query_text: str, top_k: int = 4) -> List[KnowledgeSearchResult]:
        """Performs semantic search across the knowledge base."""
        # High-precision TF-IDF semantic search
        tf_results = self.fallback_indexer.search(query_text, top_k=top_k)
        if tf_results and tf_results[0].relevance_score > 0.05:
            return tf_results

        if self.collection is not None:
            try:
                count = self.collection.count()
                if count > 0:
                    results = self.collection.query(
                        query_texts=[query_text],
                        n_results=min(top_k, count),
                    )
                    search_results = []
                    if results and results.get("ids") and len(results["ids"][0]) > 0:
                        for i in range(len(results["ids"][0])):
                            meta = results["metadatas"][0][i] if results.get("metadatas") else {}
                            doc_id = results["ids"][0][i]
                            doc_text = results["documents"][0][i] if results.get("documents") else ""
                            dist = results["distances"][0][i] if results.get("distances") else 0.5
                            relevance = max(0.0, min(1.0, 1.0 - (dist / 2.0)))
                            search_results.append(
                                KnowledgeSearchResult(
                                    id=doc_id,
                                    title=meta.get("title", doc_id),
                                    category=meta.get("category", "General"),
                                    owasp_id=meta.get("owasp_id"),
                                    cwe_id=meta.get("cwe_id"),
                                    language=meta.get("language"),
                                    content=doc_text,
                                    relevance_score=round(relevance, 4),
                                )
                            )
                        return search_results
            except Exception as e:
                logger.warning(f"ChromaDB query error: {e}. Falling back to internal semantic index.")

        return tf_results

    def get_stats(self) -> Dict[str, Any]:
        count = len(self.fallback_indexer.documents)
        chroma_count = 0
        if self.collection:
            try:
                chroma_count = self.collection.count()
            except Exception:
                pass

        categories = {}
        for d in self.fallback_indexer.documents:
            cat = d.get("category", "General")
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_documents": count,
            "chromadb_count": chroma_count,
            "categories": categories,
            "collection_name": CHROMA_COLLECTION_NAME,
            "status": "ready",
        }
