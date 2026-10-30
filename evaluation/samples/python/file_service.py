import os

def read_user_document(filename: str) -> str:
    # Path traversal vulnerability (CWE-22)
    path = f"/var/app/data/{filename}"
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def write_user_document(filename: str, content: str):
    # Path traversal vulnerability (CWE-22)
    with open(f"/var/app/data/{filename}", "w", encoding="utf-8") as f:
        f.write(content)
