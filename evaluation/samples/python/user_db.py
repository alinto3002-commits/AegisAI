import sqlite3
import logging

logger = logging.getLogger(__name__)
db_pass = "root_pass_2025!"

def get_user_profile(user_id: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection via formatted string (CWE-89)
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()

def log_user_login(username: str, password: str):
    # Sensitive credential logging (CWE-532)
    logger.info(f"User login attempt: {username} with password {password}")
