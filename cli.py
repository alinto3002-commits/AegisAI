import argparse
import sys
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

from backend.models.schemas import CodeSubmission
from backend.modules.submission import CodeSubmissionModule
from backend.agents.orchestrator import MultiAgentOrchestrator
from backend.modules.report_generator import CodeReviewReportGenerator
from backend.rag.retriever import SecureCodingRAGRetriever

def scan_file(filepath: str, output_path: str = None):
    p = Path(filepath)
    if not p.exists():
        print(f"Error: File '{filepath}' does not exist.")
        sys.exit(1)

    code = p.read_text(encoding="utf-8")
    is_java = p.suffix.lower() == ".java"
    lang = "java" if is_java else "python"

    print(f"[*] Scanning {p.name} ({lang.upper()}) using AegisAI Multi-Agent Pipeline...")

    submission = CodeSubmission(code=code, language=lang, filename=p.name)
    orchestrator = MultiAgentOrchestrator()
    report = orchestrator.analyze(submission)

    # Print Summary
    print("\n" + "=" * 60)
    print(f"AI Code Review & Security Report: {report.filename}")
    print(f"Health Score: {report.health_score}/100 | Risk Level: {report.risk_level}")
    print(f"PR Verdict: {report.verdict}")
    print("=" * 60)
    print(f"Severity Breakdown: Critical: {report.severity_counts.get('CRITICAL',0)} | High: {report.severity_counts.get('HIGH',0)} | Medium: {report.severity_counts.get('MEDIUM',0)} | Low: {report.severity_counts.get('LOW',0)}")
    print("-" * 60)

    for idx, f in enumerate(report.findings, start=1):
        print(f"{idx}. [{f.severity.value}] {f.title} (Line {f.line_start})")
        if f.owasp_category:
            print(f"   Standard: {f.owasp_category} | CWE: {f.cwe_id}")
        if f.evidence:
            print(f"   Evidence: {f.evidence.strip()}")
        if f.remediation:
            print(f"   Fix Suggestion:\n     {f.remediation.corrected_snippet.splitlines()[0]}")
        print()

    if output_path:
        out_p = Path(output_path)
        if out_p.suffix.lower() == ".pdf":
            pdf_bytes = CodeReviewReportGenerator.to_pdf(report)
            out_p.write_bytes(pdf_bytes)
            print(f"[+] Exported PDF report to: {out_p.resolve()}")
        elif out_p.suffix.lower() == ".json":
            json_str = CodeReviewReportGenerator.to_json(report)
            out_p.write_text(json_str, encoding="utf-8")
            print(f"[+] Exported JSON report to: {out_p.resolve()}")
        else:
            md_str = CodeReviewReportGenerator.to_markdown(report)
            out_p.write_text(md_str, encoding="utf-8")
            print(f"[+] Exported Markdown report to: {out_p.resolve()}")

def validate_syntax(filepath: str):
    p = Path(filepath)
    if not p.exists():
        print(f"Error: File '{filepath}' does not exist.")
        sys.exit(1)

    code = p.read_text(encoding="utf-8")
    result = CodeSubmissionModule.validate_code(code, filename=p.name)

    print(f"[*] Syntax Validation for {p.name}:")
    if result.is_valid:
        print(f"  [PASS] Syntax is VALID ({result.line_count} lines)")
        print(f"  Cyclomatic Complexity: {result.cyclomatic_complexity}")
        ast = result.ast_summary or {}
        print(f"  AST Elements: {ast.get('function_count',0)} functions/methods, {ast.get('class_count',0)} classes")
    else:
        print(f"  [FAIL] Syntax ERROR: {result.error_message}")
        print(f"  Line {result.error_line}, Column {result.error_column}")

def search_kb(query: str):
    print(f"[*] Searching Secure Coding Knowledge Base for: '{query}'...")
    retriever = SecureCodingRAGRetriever()
    results = retriever.search(query, top_k=4)

    if not results:
        print("[-] No matching guidelines found.")
        return

    for idx, r in enumerate(results, start=1):
        print(f"\n{idx}. {r.title} (Relevance Score: {r.relevance_score})")
        print(f"   Category: {r.category} | OWASP: {r.owasp_id} | CWE: {r.cwe_id}")
        print(f"   Content: {r.content[:240]}...")

def main():
    parser = argparse.ArgumentParser(description="AegisAI CLI - AI Code Review & Security Analysis Agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Scan command
    scan_p = subparsers.add_parser("scan", help="Run multi-agent security and quality scan on a source file")
    scan_p.add_argument("file", help="Path to Python or Java source file")
    scan_p.add_argument("-o", "--output", help="Optional output path for report (.pdf, .md, .json)")

    # Validate command
    val_p = subparsers.add_parser("validate", help="Validate AST syntax and structure of a source file")
    val_p.add_argument("file", help="Path to Python or Java source file")

    # KB search command
    kb_p = subparsers.add_parser("kb-search", help="Search the Secure Coding Knowledge Base (RAG)")
    kb_p.add_argument("query", help="Search query string")

    args = parser.parse_args()

    if args.command == "scan":
        scan_file(args.file, args.output)
    elif args.command == "validate":
        validate_syntax(args.file)
    elif args.command == "kb-search":
        search_kb(args.query)

if __name__ == "__main__":
    main()
