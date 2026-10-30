import os
import sys
import uvicorn
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Force UTF-8 encoding for Windows console
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from backend.rag.seed_knowledge_base import seed

def main():
    print("=" * 70)
    print("[*] AegisAI - AI Code Review & Security Analysis Agent Platform")
    print("    OWASP Top 10 (2025) Standard | RAG Pipeline | Multi-Agent Engine")
    print("=" * 70)

    # 1. Ensure Knowledge Base is seeded
    print("\n[1/2] Verifying Secure Coding Knowledge Base (RAG)...")
    seed()

    import socket
    port = 8501
    for test_port in [8501, 8080, 8000]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', test_port)) != 0:
                port = test_port
                break

    # 2. Start Application Server
    print("\n[2/2] Launching Developer Portal & Multi-Agent API Server...")
    print(f">>> Portal URL: http://localhost:{port}")
    print(f">>> Swagger Docs: http://localhost:{port}/docs")
    print("Press CTRL+C to stop the server.\n")

    uvicorn.run("backend.app:app", host="127.0.0.1", port=port, reload=True)

if __name__ == "__main__":
    main()

