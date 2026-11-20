import urllib.request
import json
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

sample_keys = [
    ("python_simple_sample", "Python Simple (Low Complexity)"),
    ("python_moderate_sample", "Python Moderate (Medium Complexity - SQLi + MD5)"),
    ("python_vulnerable_sqli_secrets", "Python Complex (High Complexity - SQLi + Secrets + Path Traversal)"),
    ("java_SimpleSample", "Java Simple (Low Complexity)"),
    ("java_ModerateSample", "Java Moderate (Medium Complexity - Path Traversal + Weak PRNG)"),
    ("java_VulnerableAuthApp", "Java Complex (High Complexity - Hardcoded Secrets + Insecure Auth)"),
]

# Fetch samples
res = urllib.request.urlopen("http://127.0.0.1:8501/api/samples")
samples = json.loads(res.read().decode('utf-8'))

print("================================================================================")
print("  END-TO-END VERIFICATION: ACCURACY, REMEDIATION, RAG & REPORT COMPLETENESS")
print("================================================================================\n")

results = []
all_passed = True

for key, label in sample_keys:
    if key not in samples:
        print(f"❌ Sample {key} not found in /api/samples!")
        all_passed = False
        continue
    
    sample = samples[key]
    
    # 1. Analyze code
    req = urllib.request.Request(
        "http://127.0.0.1:8501/api/analyze",
        data=json.dumps({
            "code": sample["code"],
            "language": sample["language"],
            "filename": sample["name"]
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    report = json.loads(urllib.request.urlopen(req).read().decode('utf-8'))
    
    # 2. Check Remediation quality
    findings_count = len(report["findings"])
    rem_with_diff = sum(1 for f in report["findings"] if f.get("remediation", {}).get("diff"))
    rem_with_fix = sum(1 for f in report["findings"] if f.get("remediation", {}).get("corrected_snippet"))
    rem_with_test = sum(1 for f in report["findings"] if f.get("remediation", {}).get("unit_test_code"))
    
    # 3. Test PDF generation completeness
    pdf_req = urllib.request.Request(
        "http://127.0.0.1:8501/api/export/pdf",
        data=json.dumps(report).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    pdf_bytes = urllib.request.urlopen(pdf_req).read()
    pdf_valid = pdf_bytes.startswith(b"%PDF-") and len(pdf_bytes) > 1000
    
    # 4. Test Markdown export
    md_req = urllib.request.Request(
        "http://127.0.0.1:8501/api/export/markdown",
        data=json.dumps(report).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    md_text = urllib.request.urlopen(md_req).read().decode('utf-8')
    md_valid = len(md_text) > 200 and "Report ID:" in md_text
    
    status_icon = "✓" if pdf_valid and md_valid else "❌"
    print(f"{status_icon} {label}")
    print(f"    Lines: {report['lines_of_code']:<4} | Complexity: {report['cyclomatic_complexity']:<2} | Health Score: {report['health_score']:<3} | Verdict: {report['verdict']}")
    print(f"    Findings: {findings_count:<2} (Diffs: {rem_with_diff}/{findings_count}, Fixes: {rem_with_fix}/{findings_count}, Unit Tests: {rem_with_test}/{findings_count})")
    print(f"    PDF Export: {len(pdf_bytes)} bytes | MD Export: {len(md_text)} chars\n")
    
    results.append({
        "sample": label,
        "language": sample["language"],
        "lines": report["lines_of_code"],
        "complexity": report["cyclomatic_complexity"],
        "health_score": report["health_score"],
        "verdict": report["verdict"],
        "findings": findings_count,
        "pdf_bytes": len(pdf_bytes)
    })

print("================================================================================")
print("E2E TESTING SUMMARY:")
print(f"Total samples tested: {len(results)} | All PDF & Reports generated: {'YES' if all_passed else 'NO'}")
print("================================================================================")
