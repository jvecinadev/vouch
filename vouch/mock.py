"""Fake scan so the UI can be built and demoed without Ollama or scanners. Run: VOUCH_MOCK=1 python app.py"""
import time

from .models import Badge, Finding

PATCH = """--- a/auth/login.py
+++ b/auth/login.py
@@ -9,3 +9,3 @@
-    query = f"SELECT * FROM users WHERE email = '{email}'"
-    cursor.execute(query)
+    query = "SELECT * FROM users WHERE email = ?"
+    cursor.execute(query, (email,))
"""


def mock_findings() -> list:
    return [
        Finding(id="mock-1", tool="bandit", rule_id="B608", title="hardcoded sql expressions",
                cwe="CWE-89", severity="high", file="auth/login.py", line=9,
                message="Possible SQL injection via string-based query construction.",
                verdict="true_positive",
                explanation="The query is built by inserting the email straight into the SQL string. "
                            "An attacker can send input like ' OR '1'='1' -- to read every user.",
                patch=PATCH, badge=Badge.VERIFIED, attempts=2, first_try_applies=False,
                verify_log=["attempt 1: scanner still reports B608", "attempt 2: verified"]),
        Finding(id="mock-2", tool="bandit", rule_id="B105", title="hardcoded password string",
                cwe="CWE-259", severity="medium", file="auth/login.py", line=4,
                message="Possible hardcoded password.", verdict="true_positive",
                explanation="A password is written directly in the source code, so anyone with the "
                            "repository can read it.",
                patch="", badge=Badge.NEEDS_HUMAN, attempts=3,
                verify_log=["attempt 1: patch did not apply"]),
    ]


def scan():
    yield "status", "Scanning (mock)"
    time.sleep(0.6)
    for f in mock_findings():
        yield "status", f"Verifying {f.rule_id} (mock)"
        time.sleep(0.8)
        yield "finding", f
    yield "status", "Done (mock data)"
