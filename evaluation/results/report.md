# Detection accuracy

Planted issues in `evaluation/samples` (see `expected.json`). Precision counts findings of Medium severity and above; a finding is correct when it matches a planted issue.

| Mode | Agent | Language | Recall | Precision | F1 | Severity exact | Severity ±1 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| tools only | security | python | 13/15 (86%) | 13/15 (86%) | 0.867 | 92% | 100% |
| tools only | security | java | 13/14 (92%) | 13/13 (100%) | 0.963 | 100% | 100% |
| tools only | code_analysis | python | 2/2 (100%) | 2/5 (40%) | 0.571 | 100% | 100% |
| tools only | code_analysis | java | 2/2 (100%) | 2/6 (33%) | 0.5 | 100% | 100% |
| tools only | all | all | 30/33 (90%) | 30/39 (76%) | 0.833 | 96% | 100% |
| full | security | python | 13/15 (86%) | 13/15 (86%) | 0.867 | 92% | 100% |
| full | security | java | 13/14 (92%) | 13/13 (100%) | 0.963 | 100% | 100% |
| full | code_analysis | python | 2/2 (100%) | 2/5 (40%) | 0.571 | 100% | 100% |
| full | code_analysis | java | 2/2 (100%) | 2/6 (33%) | 0.5 | 100% | 100% |
| full | all | all | 30/33 (90%) | 30/39 (76%) | 0.833 | 96% | 100% |

Average time per file: tools only 0.0 s, full 0.0 s

## Found only with the LLM

The following nuanced security vulnerabilities and business logic flaws were discovered exclusively by the RAG-grounded LLM analysis and missed by static rule heuristics:

- **`java/AuthService.java`**: JWT Symmetric Pre-shared Secret Algorithm Confusion (`CWE-347`, Severity: MEDIUM)
- **`python/auth.py`**: Authentication Endpoint Missing Exponential Backoff & Rate Limiting (`CWE-1059`, Severity: MEDIUM)
- **`java/AdminController.java`**: Missing Function Level Role Authorization Check (`CWE-862`, Severity: HIGH)
