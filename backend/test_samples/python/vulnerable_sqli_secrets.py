import os
import sqlite3
import hashlib
import pickle

# Hardcoded Secret (OWASP A07:2025)
API_SECRET_KEY = "ghp_abcdef1234567890abcdef12345678901234"
JWT_TOKEN_SECRET = "super_secret_production_key_999!"

def authenticate_user(username, password):
    # Weak Broken Hash Algorithm (OWASP A04:2025)
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # SQL Injection via formatted string (OWASP A05:2025)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{hashed}'"
    cursor.execute(query)
    user = cursor.fetchone()

    # Plaintext Password Logging (OWASP A09:2025)
    print(f"User {username} attempted login with password {password}")

    return user

def read_user_file(filename):
    # Path Traversal (OWASP A01:2025)
    filepath = f"/var/data/uploads/{filename}"
    try:
        with open(filepath, "rb") as f:
            # Insecure Deserialization (OWASP A08:2025)
            return pickle.loads(f.read())
    except:
        # Bare except swallowing errors (OWASP A10:2025)
        pass
    return None

def run_system_ping(host):
    # Command Injection (OWASP A05:2025)
    os.system("ping -c 1 " + host)
