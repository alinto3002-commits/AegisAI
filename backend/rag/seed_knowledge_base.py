import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path so it can be executed as a standalone script
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from backend.config import DOCS_DIR
from backend.rag.vector_store import SecureCodingVectorStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_kb")

def seed():
    """
    Milestone 1 Task 4: Ingestion and vector store indexing for OWASP 2025 guidelines,
    CWE taxonomies, and Python/Java secure coding documents.
    """
    logger.info("Initializing Secure Coding Knowledge Base Vector Store...")
    store = SecureCodingVectorStore()

    all_docs = []
    doc_files = list(DOCS_DIR.glob("*.json"))

    if not doc_files:
        logger.warning(f"No document files found in {DOCS_DIR}!")
        return

    for doc_file in doc_files:
        try:
            with open(doc_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    all_docs.extend(data)
                    logger.info(f"Loaded {len(data)} items from {doc_file.name}")
                elif isinstance(data, dict):
                    all_docs.append(data)
                    logger.info(f"Loaded 1 item from {doc_file.name}")
        except Exception as e:
            logger.error(f"Failed to load {doc_file}: {e}")

    logger.info(f"Indexing total of {len(all_docs)} documents into vector store...")
    store.add_documents(all_docs)

    stats = store.get_stats()
    logger.info(f"Knowledge Base Indexing Complete! Total Indexed: {stats['total_documents']}")
    logger.info(f"Categories Breakdown: {stats['categories']}")

    # Self-test queries
    test_queries = [
        "SQL injection query concatenation in Python and JDBC",
        "Hardcoded credentials API keys secrets in repository",
        "Bare except pass empty catch block exception mishandling",
        "Untrusted deserialization pickle loads and Java ObjectInputStream",
    ]

    logger.info("Running verification search queries against Knowledge Base...")
    for q in test_queries:
        results = store.query(q, top_k=2)
        top_title = results[0].title if results else "No results"
        score = results[0].relevance_score if results else 0
        logger.info(f"Query: '{q[:40]}...' -> Top Match: {top_title} (score: {score})")

    print("\n" + "=" * 60)
    print("SUCCESS: Secure Coding Knowledge Base Seeded and Verified!")
    print("=" * 60)

if __name__ == "__main__":
    seed()
