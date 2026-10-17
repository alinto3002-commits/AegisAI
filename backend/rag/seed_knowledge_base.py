import json
import logging
import re
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

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

from backend.config import DOCS_DIR, RAG_DOCS_DIR, SECURE_CODING_TXT, ROOT_DOCS_DIR, SEED_DATA_DIR
from backend.rag.vector_store import SecureCodingVectorStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_kb")


def extract_code_blocks(text: str) -> tuple[Optional[str], Optional[str]]:
    """Extracts vulnerable and secure code blocks from markdown content."""
    vuln_code = None
    sec_code = None

    # Match code blocks with preceding comments or labels
    blocks = re.findall(r"```(?:java|python|xml|text)?\n([\s\S]*?)```", text)
    for b in blocks:
        b_lower = b.lower()
        if "vulnerable" in b_lower or "❌" in b_lower:
            if not vuln_code:
                vuln_code = b.strip()
        elif "secure" in b_lower or "✅" in b_lower:
            if not sec_code:
                sec_code = b.strip()

    return vuln_code, sec_code


def parse_markdown_document(filepath: Path) -> List[Dict[str, Any]]:
    """Parses markdown document into structured knowledge base items chunked by headers."""
    if not filepath.exists():
        return []

    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception as e:
        logger.warning(f"Could not read {filepath}: {e}")
        return []

    chunks: List[Dict[str, Any]] = []
    filename_lower = filepath.stem.lower()

    # Determine default language based on filename
    default_lang = "general"
    if "java" in filename_lower:
        default_lang = "java"
    elif "python" in filename_lower:
        default_lang = "python"

    # Split document by headers (### or ##)
    sections = re.split(r"\n(?=#{2,3}\s+)", content)

    for idx, sec in enumerate(sections):
        sec = sec.strip()
        if not sec or len(sec) < 50:
            continue

        lines = sec.splitlines()
        header_line = lines[0].strip()
        title = re.sub(r"^#{1,4}\s*", "", header_line).strip()

        # Skip generic headers like "Table of Contents" or "Sources"
        if title.lower() in ("table of contents", "sources", "document index", "overview"):
            continue

        body = "\n".join(lines[1:]).strip()

        # Extract OWASP ID (e.g., A01:2025, A05:2025)
        owasp_match = re.search(r"\b(A0?[1-9]:2025|A10:2025)\b", sec)
        owasp_id = owasp_match.group(1) if owasp_match else None

        # Extract CWE ID (e.g., CWE-89, CWE-22)
        cwe_match = re.search(r"\b(CWE-\d+)\b", sec)
        cwe_id = cwe_match.group(1) if cwe_match else None

        # Determine category
        category = "Secure Coding Practice"
        if "smell" in filename_lower or "complexity" in sec.lower():
            category = "Code Quality & Smells"
        elif owasp_id:
            category = f"OWASP 2025 ({owasp_id})"
        elif "architecture" in filename_lower:
            category = "Architecture & Design"

        # Determine language
        lang = default_lang
        if "java" in sec.lower() and "python" not in sec.lower():
            lang = "java"
        elif "python" in sec.lower() and "java" not in sec.lower():
            lang = "python"

        vuln_ex, sec_ex = extract_code_blocks(body)

        doc_id = f"DOC-{filepath.stem[:8].upper()}-{idx+1:02d}"

        chunks.append({
            "id": doc_id,
            "title": title[:100],
            "category": category,
            "owasp_id": owasp_id,
            "cwe_id": cwe_id,
            "language": lang,
            "content": body[:2000],  # Keep concise for high-relevance retrieval
            "vulnerable_example": vuln_ex,
            "secure_example": sec_ex,
            "tags": [filepath.stem.lower(), lang] + ([owasp_id.lower()] if owasp_id else []) + ([cwe_id.lower()] if cwe_id else []),
        })

    return chunks


def parse_text_guide(filepath: Path) -> List[Dict[str, Any]]:
    """Parses secure_coding.txt into structured knowledge base items by SECTION."""
    if not filepath.exists():
        return []

    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception as e:
        logger.warning(f"Could not read {filepath}: {e}")
        return []

    chunks: List[Dict[str, Any]] = []
    sections = re.split(r"(?:={40,}\n)?SECTION\s+\d+:\s*", content)

    for idx, sec in enumerate(sections):
        sec = sec.strip()
        if not sec or len(sec) < 100:
            continue

        lines = sec.splitlines()
        title = lines[0].strip()
        body = "\n".join(lines[1:]).strip()

        # Extract OWASP ID or CWE if present
        owasp_match = re.search(r"\b(A0?[1-9]:2025|A10:2025)\b", sec)
        cwe_match = re.search(r"\b(CWE-\d+)\b", sec)

        lang = "general"
        if "python" in title.lower() or "python" in sec.lower():
            lang = "python"
        elif "java" in title.lower() or "java" in sec.lower():
            lang = "java"

        chunks.append({
            "id": f"TXT-SEC-{idx:02d}",
            "title": title[:100],
            "category": "Master Security Guidelines",
            "owasp_id": owasp_match.group(1) if owasp_match else None,
            "cwe_id": cwe_match.group(1) if cwe_match else None,
            "language": lang,
            "content": body[:2500],
            "tags": ["secure-coding-txt", lang],
        })

    return chunks


def seed():
    """
    Ingests and indexes:
    1. Structured JSON knowledge files (Python, Java, OWASP 2025, Code Quality)
    2. Markdown documents (JAVA_SECURE_CODING_2025.md, PYTHON_SECURE_CODING_2025.md, etc.)
    3. Master text reference guide (secure_coding.txt)
    """
    logger.info("Initializing Secure Coding Knowledge Base Vector Store...")
    store = SecureCodingVectorStore()

    all_docs = []

    # 1. Ingest JSON knowledge files
    json_dirs = [SEED_DATA_DIR, RAG_DOCS_DIR]
    seen_json_ids = set()

    for jdir in json_dirs:
        if not jdir.exists():
            continue
        for jfile in jdir.glob("*.json"):
            try:
                with open(jfile, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    items = data if isinstance(data, list) else [data]
                    for item in items:
                        iid = item.get("id")
                        if iid and iid not in seen_json_ids:
                            seen_json_ids.add(iid)
                            all_docs.append(item)
                    logger.info(f"Loaded {len(items)} items from JSON {jfile.name}")
            except Exception as e:
                logger.error(f"Failed to load JSON {jfile}: {e}")

    # 2. Ingest Markdown documents
    md_dir = ROOT_DOCS_DIR if ROOT_DOCS_DIR.exists() else RAG_DOCS_DIR
    if md_dir.exists():
        for md_file in md_dir.glob("*.md"):
            if md_file.name == "README.md":
                continue
            parsed_chunks = parse_markdown_document(md_file)
            all_docs.extend(parsed_chunks)
            logger.info(f"Parsed {len(parsed_chunks)} structured sections from {md_file.name}")

    # 3. Ingest secure_coding.txt
    if SECURE_CODING_TXT.exists():
        txt_chunks = parse_text_guide(SECURE_CODING_TXT)
        all_docs.extend(txt_chunks)
        logger.info(f"Parsed {len(txt_chunks)} sections from secure_coding.txt")

    logger.info(f"Indexing total of {len(all_docs)} documents into vector store...")
    store.add_documents(all_docs)

    stats = store.get_stats()
    logger.info(f"Knowledge Base Indexing Complete! Total Indexed: {stats['total_documents']}")
    logger.info(f"Categories Breakdown: {stats['categories']}")

    # Verification search queries across Python and Java
    test_queries = [
        "SQL injection parameterized PreparedStatement and DB-API",
        "Python pickle unsafe deserialization and PyYAML safe_load",
        "Java Spring Security IDOR PreAuthorize and RBAC",
        "Bare except pass empty catch block exception handling",
        "AES-256-GCM authenticated encryption and unique IV",
        "XML External Entity XXE injection DefusedXML and DocumentBuilderFactory",
        "Path traversal ZipSlip canonical path normalization",
        "Cryptographically secure randomness secrets and SecureRandom",
    ]

    logger.info("Running verification search queries against Knowledge Base...")
    for q in test_queries:
        results = store.query(q, top_k=2)
        top_title = results[0].title if results else "No results"
        score = results[0].relevance_score if results else 0
        logger.info(f"Query: '{q[:40]}...' -> Top Match: {top_title} (score: {score})")

    print("\n" + "=" * 70)
    print(f"SUCCESS: Secure Coding Knowledge Base Seeded with {stats['total_documents']} Guidelines!")
    print("=" * 70)


if __name__ == "__main__":
    seed()
