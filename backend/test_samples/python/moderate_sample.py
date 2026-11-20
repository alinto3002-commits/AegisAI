"""
Moderate Python Sample - Medium Complexity Authentication Handler
Complexity: Moderate (Cyclomatic Complexity ~ 6-8, ~55 LOC)
Identified OWASP Vulnerabilities:
1. SQL Injection via string formatting (A05:2025 / CWE-89)
2. Weak MD5 hashing for passwords (A04:2025 / CWE-328)
"""

import hashlib
import sqlite3
from typing import Optional, Dict, Any


class UserAuthService:
    def __init__(self, db_path: str = "app.db"):
        self.db_path = db_path

    def hash_password(self, password: str) -> str:
        # OWASP A04: Weak MD5 cryptographic hashing
        return hashlib.md5(password.encode("utf-8")).hexdigest()

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        hashed_pwd = self.hash_password(password)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # OWASP A05 / CWE-89: SQL Injection via direct f-string concatenation
        query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password_hash = '{hashed_pwd}'"
        
        try:
            cursor.execute(query)
            row = cursor.fetchone()
            if row:
                return {"id": row[0], "username": row[1], "role": row[2]}
            return None
        finally:
            conn.close()

    def update_user_status(self, user_id: int, status: str) -> bool:
        if not status in ["active", "suspended", "pending"]:
            return False
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))
            conn.commit()
            return True
        finally:
            conn.close()
