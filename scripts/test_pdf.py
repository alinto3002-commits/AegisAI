import urllib.request
import json
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

# 1. Fetch a sample
sample_req = urllib.request.urlopen("http://127.0.0.1:8501/api/samples")
samples = json.loads(sample_req.read().decode('utf-8'))
sample_key = "python_vulnerable_sqli_secrets" if "python_vulnerable_sqli_secrets" in samples else list(samples.keys())[0]
sample = samples[sample_key]

# 2. Analyze code
analyze_req = urllib.request.Request(
    "http://127.0.0.1:8501/api/analyze",
    data=json.dumps({
        "code": sample["code"],
        "language": sample["language"],
        "filename": sample["name"]
    }).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)
report = json.loads(urllib.request.urlopen(analyze_req).read().decode('utf-8'))
print(f"Analysis completed: Report ID {report['id']}, Findings: {len(report['findings'])}, Health Score: {report['health_score']}")

# 3. Test PDF generation endpoint
pdf_req = urllib.request.Request(
    "http://127.0.0.1:8501/api/export/pdf",
    data=json.dumps(report).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)
pdf_data = urllib.request.urlopen(pdf_req).read()
print(f"PDF exported successfully! Size: {len(pdf_data)} bytes.")

# Save to disk for inspection
output_path = "evaluation/test_export.pdf"
os.makedirs("evaluation", exist_ok=True)
with open(output_path, "wb") as f:
    f.write(pdf_data)
print(f"Saved PDF to {output_path}")

# Verify it begins with %PDF-
if pdf_data.startswith(b"%PDF-"):
    print("SUCCESS: Valid PDF header verified (%PDF-)!")
else:
    print(f"WARNING: Output does not start with PDF magic bytes. Content preview: {pdf_data[:100]}")
