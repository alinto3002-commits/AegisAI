import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
DATA_DIR = BASE_DIR / "data"
VECTOR_STORE_DIR = DATA_DIR / "vector_store"
ROOT_DOCS_DIR = PROJECT_ROOT / "documents"
RAG_DOCS_DIR = BASE_DIR / "rag" / "documents"
DOCS_DIR = ROOT_DOCS_DIR if ROOT_DOCS_DIR.exists() else RAG_DOCS_DIR
SECURE_CODING_TXT = PROJECT_ROOT / "secure_coding.txt"
SEED_DATA_DIR = DATA_DIR / "seed_data"
SAMPLES_DIR = BASE_DIR / "test_samples"

# Load .env file
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
VECTOR_STORE_DIR.mkdir(parents=True, exist_ok=True)
RAG_DOCS_DIR.mkdir(parents=True, exist_ok=True)
if ROOT_DOCS_DIR.exists():
    ROOT_DOCS_DIR.mkdir(parents=True, exist_ok=True)

# Application Settings
APP_NAME = "AI Code Review & Security Analysis Agent"
APP_VERSION = "1.0.0"
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 8000))

# LLM & Embedding Settings:
# NOTE: GEMINI_API_KEY is used EXCLUSIVELY for the interactive Conversational Code Assistant (Chatbot).
# All code scanning, AST parsing, OWASP security rules, remediation diffs, and RAG vector store indexing
# run 100% locally and deterministically with zero external LLM dependencies or token consumption.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
USE_FALLBACK_EMBEDDINGS = True

# Vector Store Settings
CHROMA_COLLECTION_NAME = "secure_coding_knowledge_base"
TOP_K_RETRIEVAL = 4
