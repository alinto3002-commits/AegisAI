import urllib.request
import json
import sys

sys.stdout.reconfigure(encoding='utf-8')

test_cases = [
    ("python", "def broken(\n    return 1", "broken.py"),
    ("java", "public class Broken { public void test() { System.out.println(1); ", "Broken.java"),
    ("python", "def ok():\n    return 1", "ok.py"),
    ("java", "public class Ok { public void test() {} }", "Ok.java")
]

for lang, code, filename in test_cases:
    # 1. Test validate
    req = urllib.request.Request(
        "http://127.0.0.1:8501/api/validate",
        data=json.dumps({"code": code, "language": lang, "filename": filename}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res_v = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))
    print(f"VALIDATE {filename:12}: is_valid={res_v['is_valid']}, err={res_v.get('error_message')}")

    # 2. Test analyze
    req_a = urllib.request.Request(
        "http://127.0.0.1:8501/api/analyze",
        data=json.dumps({"code": code, "language": lang, "filename": filename}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res_a = json.loads(urllib.request.urlopen(req_a).read().decode("utf-8"))
    print(f"ANALYZE  {filename:12}: health={res_a['health_score']}, verdict={res_a['verdict']}, findings={len(res_a['findings'])}")
    if res_a['findings']:
        for f in res_a['findings']:
            print(f"   - Finding: {f['title']} (Sev: {f['severity']}, Line: {f['line_start']})")
    print()
