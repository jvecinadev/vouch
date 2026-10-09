# expect: CWE-89
# INTENTIONALLY INSECURE. Benchmark case, never use in production.
import sqlite3

# FAKE CREDENTIAL FOR DEMO ONLY. This file is intentionally insecure.
DB_PASSWORD = "demo-password-123"


def login(email, password):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE email = '{email}'"
    cursor.execute(query)
    return cursor.fetchone()
