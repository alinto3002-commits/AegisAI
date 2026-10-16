import os
import sqlite3
import hashlib
import json
import logging
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Retrieve secret safely from environment variable
API_SECRET_KEY = os.environ.get("API_SECRET_KEY")
BASE_UPLOAD_DIR = Path("/var/data/uploads").resolve()

def authenticate_user(username: str, password_hash: str) -> Optional[Dict[str, Any]]:
    """
    Safely authenticates user against database using parameterized queries.
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Parameterized query protects against SQL injection
    query = "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?"
    cursor.execute(query, (username, password_hash))
    row = cursor.fetchone()

    if row:
        logger.info("User authenticated successfully: %s", username)
        return {"id": row[0], "username": row[1], "role": row[2]}

    logger.warning("Authentication failed for username: %s", username)
    return None

def read_user_file(filename: str) -> Optional[Dict[str, Any]]:
    """
    Safely reads file avoiding path traversal and unpickling vulnerabilities.
    """
    safe_path = (BASE_UPLOAD_DIR / filename).resolve()
    if not safe_path.is_relative_to(BASE_UPLOAD_DIR):
        logger.error("Path traversal attempt detected: %s", filename)
        raise PermissionError("Access outside safe directory is forbidden")

    try:
        with open(safe_path, "r", encoding="utf-8") as f:
            return json.loads(f.read())
    except (FileNotFoundError, json.JSONDecodeError) as err:
        logger.warning("Could not read file %s: %s", safe_path, err)
        return None

def run_system_ping(host: str) -> bool:
    """
    Safely runs ping without invoking system shell.
    """
    import ipaddress
    try:
        ipaddress.ip_address(host)
    except ValueError:
        logger.error("Invalid IP address: %s", host)
        return False

    res = subprocess.run(["ping", "-c", "1", host], check=False, shell=False)
    return res.returncode == 0
