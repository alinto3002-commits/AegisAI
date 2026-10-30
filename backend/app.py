import os
import sys
from pathlib import Path
from typing import Dict, Any, List

# Ensure project root is in python path
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse

from backend.config import APP_NAME, APP_VERSION, SAMPLES_DIR
from backend.models.schemas import (
    CodeSubmission,
    SyntaxValidationResult,
    ReviewReport,
    ChatQuery,
    ChatResponse,
    KnowledgeSearchResult,
)
from backend.modules.submission import CodeSubmissionModule
from backend.agents.orchestrator import MultiAgentOrchestrator
from backend.agents.conversational_agent import ConversationalCodeAssistant
from backend.rag.retriever import SecureCodingRAGRetriever
from backend.rag.vector_store import SecureCodingVectorStore
from backend.modules.report_generator import CodeReviewReportGenerator

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Multi-Agent AI Code Review & OWASP Top 10 (2025) Security Analysis Platform",
)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Agents & RAG Services
orchestrator = MultiAgentOrchestrator()
chat_assistant = ConversationalCodeAssistant()
rag_retriever = SecureCodingRAGRetriever()
vector_store = SecureCodingVectorStore()

# ----------------- API Endpoints -----------------

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "app": APP_NAME,
        "version": APP_VERSION,
        "owasp_standard": "OWASP Top 10 (2025)",
        "supported_languages": ["python", "java"],
    }

@app.post("/api/validate", response_model=SyntaxValidationResult)
def validate_code(submission: CodeSubmission):
    """Module 1: Code Submission & AST Syntax Validation."""
    result = CodeSubmissionModule.validate_code(
        code=submission.code,
        language=submission.language,
        filename=submission.filename,
    )
    return result

@app.post("/api/validate-upload", response_model=SyntaxValidationResult)
async def validate_uploaded_file(file: UploadFile = File(...)):
    """Module 1: Validate file upload directly."""
    content = await file.read()
    try:
        code_str = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Uploaded file is not valid UTF-8 text.")

    result = CodeSubmissionModule.validate_code(
        code=code_str,
        filename=file.filename,
    )
    return result

@app.post("/api/analyze", response_model=ReviewReport)
def analyze_code(submission: CodeSubmission):
    """Module 3: Trigger Multi-Agent Code Review & Security Analysis Pipeline."""
    report = orchestrator.analyze(submission)
    return report

@app.post("/api/chat", response_model=ChatResponse)
def chat_with_assistant(query: ChatQuery):
    """Module 5: RAG-Powered Conversational Code Assistant."""
    response = chat_assistant.run(
        query=query.query,
        code_context=query.code_context,
        language=query.language or "python",
        findings_context=query.findings_context,
        history=query.history,
    )
    return response

@app.get("/api/kb/search", response_model=List[KnowledgeSearchResult])
def search_knowledge_base(q: str, limit: int = 5):
    """Module 2: Query the indexed OWASP 2025 & Secure Coding Knowledge Base."""
    return rag_retriever.search(q, top_k=limit)

@app.get("/api/kb/stats")
def get_knowledge_base_stats():
    """Module 2: Knowledge Base statistics and index metadata."""
    return vector_store.get_stats()

@app.post("/api/export/json")
def export_report_json(report: ReviewReport):
    """Module 6: Export review report as formatted JSON."""
    json_data = CodeReviewReportGenerator.to_json(report)
    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=review_report_{report.id}.json"},
    )

@app.post("/api/export/markdown")
def export_report_markdown(report: ReviewReport):
    """Module 6: Export review report as Pull Request Markdown."""
    md_content = CodeReviewReportGenerator.to_markdown(report)
    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=pr_review_{report.id}.md"},
    )

@app.post("/api/export/pdf")
def export_report_pdf(report: ReviewReport):
    """Module 6: Export executive PDF report."""
    pdf_bytes = CodeReviewReportGenerator.to_pdf(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=review_report_{report.id}.pdf"},
    )

@app.get("/api/samples")
def get_code_samples():
    """Returns pre-loaded sample codes for quick demonstration."""
    samples = {}
    eval_samples = PROJECT_ROOT / "evaluation" / "samples"
    for d, lang in [
        (eval_samples / "java", "java"),
        (eval_samples / "python", "python"),
        (SAMPLES_DIR / "java", "java"),
        (SAMPLES_DIR / "python", "python"),
    ]:
        if d.exists():
            ext = "*.java" if lang == "java" else "*.py"
            for f in d.glob(ext):
                key = f"{lang}_{f.stem}"
                if key not in samples:
                    samples[key] = {
                        "name": f.name,
                        "language": lang,
                        "code": f.read_text(encoding="utf-8"),
                    }
    return samples

@app.get("/api/evaluation/report")
def get_evaluation_report():
    """Returns the benchmark detection accuracy report and summary."""
    eval_dir = PROJECT_ROOT / "evaluation" / "results"
    report_file = eval_dir / "report.md"
    csv_file = eval_dir / "summary.csv"

    if not report_file.exists():
        try:
            from evaluation.evaluate import run_evaluation
            run_evaluation()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to generate evaluation: {e}")

    report_md = report_file.read_text(encoding="utf-8") if report_file.exists() else ""
    summary_csv = csv_file.read_text(encoding="utf-8") if csv_file.exists() else ""

    return {
        "report_markdown": report_md,
        "summary_csv": summary_csv,
    }

@app.post("/api/evaluation/run")
def trigger_evaluation():
    """Triggers the benchmark evaluation pipeline across Java and Python samples."""
    try:
        from evaluation.evaluate import run_evaluation
        run_evaluation()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evaluation failed: {e}")

    eval_dir = PROJECT_ROOT / "evaluation" / "results"
    report_file = eval_dir / "report.md"
    csv_file = eval_dir / "summary.csv"
    return {
        "status": "success",
        "report_markdown": report_file.read_text(encoding="utf-8") if report_file.exists() else "",
        "summary_csv": csv_file.read_text(encoding="utf-8") if csv_file.exists() else "",
    }


# Mount frontend directory for Web Developer Portal
FRONTEND_DIR = PROJECT_ROOT / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def serve_frontend_root():
        return FileResponse(str(FRONTEND_DIR / "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)
