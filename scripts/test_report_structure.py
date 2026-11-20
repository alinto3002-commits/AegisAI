import sys
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.models.schemas import ReviewReport, Finding, RemediationSuggestion, FindingSeverity, PRReviewSummary
from backend.modules.report_generator import CodeReviewReportGenerator

def test_report_generation():
    # 1. Test Report BEFORE error solving (Initial Audit)
    initial_report = ReviewReport(
        id='test-initial-123',
        filename='vulnerable_app.py',
        language='python',
        lines_of_code=45,
        cyclomatic_complexity=4,
        health_score=35,
        verdict='CHANGES_REQUESTED',
        risk_level='High',
        findings=[
            Finding(
                id='SEC-SQLI-001',
                title='SQL Injection via Unescaped String Formatting',
                severity=FindingSeverity.CRITICAL,
                line_start=14,
                line_end=14,
                cwe_id='CWE-89',
                owasp_category='A03:2025 - Injection',
                category='Security',
                description='Unsanitized input directly formatted into SQL query string enables arbitrary database execution.',
                evidence='query = f"SELECT * FROM users WHERE username = \'{user}\'"',
                agent_type='Security Vulnerability Agent',
                remediation=RemediationSuggestion(
                    original_snippet='query = f"SELECT * FROM users WHERE username = \'{user}\'"',
                    explanation='Use parameterized queries with placeholder binding.',
                    corrected_snippet='cursor.execute("SELECT * FROM users WHERE username = ?", (user,))',
                    diff='- query = f"SELECT..."\n+ cursor.execute("SELECT...", (user,))',
                    remediation_steps=['Replace f-string with parameterized query placeholder (?)']
                )
            )
        ],
        pr_summary=PRReviewSummary(
            verdict='CHANGES_REQUESTED',
            risk_level='High',
            health_score=35,
            summary_markdown='Blocking issues detected.',
            recommended_actions=['Fix SQL injection on line 14']
        )
    )

    md_before = CodeReviewReportGenerator.to_markdown(initial_report)
    pdf_before = CodeReviewReportGenerator.to_pdf(initial_report)
    print('=== CASE 1 (BEFORE ERROR SOLVING) ===')
    print('Markdown Title:', md_before.splitlines()[0])
    print('Is Pre-Remediation in MD:', 'Pre-Remediation' in md_before)
    print('Has Detailed Findings Catalog:', 'Detailed Findings' in md_before)
    print('PDF Bytes size:', len(pdf_before))
    assert len(pdf_before) > 1000
    assert 'Pre-Remediation' in md_before

    # 2. Test Report AFTER error solving (Remediation Resolution Report)
    remediated_report = ReviewReport(
        id='test-remed-456',
        filename='vulnerable_app.py',
        language='python',
        lines_of_code=45,
        cyclomatic_complexity=3,
        health_score=100,
        verdict='APPROVED',
        risk_level='Low',
        findings=[],
        is_remediated=True,
        initial_health_score=35,
        resolved_findings=[
            {
                'id': 'SEC-SQLI-001',
                'title': 'SQL Injection via Unescaped String Formatting',
                'severity': 'CRITICAL',
                'line_start': 14,
                'line_end': 14,
                'cwe_id': 'CWE-89',
                'owasp_category': 'A03:2025 - Injection',
                'description': 'Unsanitized input directly formatted into SQL query string enables arbitrary database execution.',
                'evidence': 'query = f"SELECT * FROM users WHERE username = \'{user}\'"',
                'remediation': {
                    'explanation': 'Replaced insecure f-string with parameterized query placeholder (?).',
                    'original_snippet': 'query = f"SELECT * FROM users WHERE username = \'{user}\'"',
                    'corrected_snippet': 'cursor.execute("SELECT * FROM users WHERE username = ?", (user,))',
                    'diff': '- query = f"SELECT..."\n+ cursor.execute("SELECT...", (user,))'
                }
            }
        ],
        pr_summary=PRReviewSummary(
            verdict='APPROVED',
            risk_level='Low',
            health_score=100,
            summary_markdown='All issues resolved.',
            recommended_actions=['Ready to merge']
        )
    )

    md_after = CodeReviewReportGenerator.to_markdown(remediated_report)
    pdf_after = CodeReviewReportGenerator.to_pdf(remediated_report)
    print('\n=== CASE 2 (AFTER ERROR SOLVING) ===')
    print('Markdown Title:', md_after.splitlines()[0])
    print('Is Post-Remediation in MD:', 'Post-Remediation' in md_after)
    print('Is Error Before in MD:', 'The Error Before' in md_after)
    print('Is What Changed in MD:', 'What Changed to Solve the Error' in md_after)
    print('PDF Bytes size:', len(pdf_after))
    assert len(pdf_after) > 1000
    assert 'Post-Remediation' in md_after
    assert 'The Error Before' in md_after
    assert 'What Changed to Solve the Error' in md_after

    print('\nAll assertions passed successfully! Both report structures verified.')

if __name__ == '__main__':
    test_report_generation()
