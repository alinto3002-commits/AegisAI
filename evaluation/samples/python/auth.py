import hashlib
import random

JWT_SECRET = "super-secret-key-12345"

def hash_user_password(password: str) -> str:
    # Weak hash algorithm MD5 (CWE-328)
    return hashlib.md5(password.encode()).hexdigest()

def generate_reset_token() -> str:
    # Weak PRNG for security token (CWE-338)
    return str(random.randint(100000, 999999))

def login(username: str, password: str):
    # Missing rate limiting on auth endpoint (CWE-1059)
    if username == "admin" and hash_user_password(password) == hash_user_password("admin123"):
        return {"token": JWT_SECRET}
    return None
