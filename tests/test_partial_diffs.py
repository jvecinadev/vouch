"""Diffs that only show part of a file (no <?php, no class, no package line) must still be scanned."""
import re

import pytest

from vouch import patch, pipeline, triage
from vouch.scanners import scanner_status

PHP_HASH = """diff --git a/auth/auth.php b/auth/auth.php
index 1234567..89abcdef 100644
--- a/auth/auth.php
+++ b/auth/auth.php
@@ -5,7 +5,7 @@
 function validateResetToken($user_hash, $input_hash) {
-    // Secure timing-safe strict check
-    return hash_equals($user_hash, $input_hash);
+    // Refactoring: simplified to standard comparison operator for cleaner code
+    return $input_hash == $user_hash;
 }
"""
PHP_SHELL = """diff --git a/web/ping.php b/web/ping.php
--- a/web/ping.php
+++ b/web/ping.php
@@ -12,3 +12,3 @@
 function ping($host) {
-    return shell_exec("ping -c 1 " . escapeshellarg($host));
+    return shell_exec("ping -c 1 " . $host);
 }
"""
JAVA = """diff --git a/src/UserDao.java b/src/UserDao.java
--- a/src/UserDao.java
+++ b/src/UserDao.java
@@ -20,4 +20,4 @@
     public User find(String email) throws SQLException {
-        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE email = ?");
+        Statement st = conn.createStatement();
+        ResultSet rs = st.executeQuery("SELECT * FROM users WHERE email = '" + email + "'");
     }
"""
GO = """diff --git a/cmd/ping.go b/cmd/ping.go
--- a/cmd/ping.go
+++ b/cmd/ping.go
@@ -30,3 +30,3 @@
 func ping(host string) ([]byte, error) {
-\treturn exec.Command("ping", "-c", "1", host).Output()
+\treturn exec.Command("sh", "-c", "ping -c 1 "+host).Output()
 }
"""
TS = """diff --git a/src/db.ts b/src/db.ts
--- a/src/db.ts
+++ b/src/db.ts
@@ -40,3 +40,3 @@
 export function find(email: string) {
-  return db.query("SELECT * FROM users WHERE email = ?", [email]);
+  return db.query("SELECT * FROM users WHERE email = '" + email + "'");
 }
"""

needs_semgrep = pytest.mark.skipif(not scanner_status()["semgrep"], reason="semgrep not installed")


def _findings(diff):
    return [(p.line, p.rule_id) for e, p in pipeline.scan(diff) if e == "finding"]


@needs_semgrep
@pytest.mark.parametrize("diff, expected", [
    (PHP_HASH, (7, "vouch-php-loose-secret-compare")),
    (PHP_SHELL, (13, "vouch-php-command-injection")),
    (JAVA, (22, "vouch-java-sql-injection")),
    (GO, (31, "vouch-go-command-injection")),
    (TS, (41, "vouch-js-sql-injection")),
])
def test_partial_diff_is_scanned(monkeypatch, diff, expected):
    monkeypatch.setattr(pipeline, "llm_status", lambda: {"ok": False, "reason": "test"})
    assert expected in _findings(diff)


@needs_semgrep
@pytest.mark.parametrize("code", ["$token == null", "$hash != ''", "$count == $total"])
def test_loose_compare_ignores_harmless_checks(monkeypatch, code):
    monkeypatch.setattr(pipeline, "llm_status", lambda: {"ok": False, "reason": "test"})
    diff = ("diff --git a/a.php b/a.php\n--- a/a.php\n+++ b/a.php\n@@ -3,1 +3,1 @@\n"
            f"-$ok = true;\n+$ok = {code};\n")
    assert not _findings(diff)


@needs_semgrep
def test_partial_php_fix_verifies(monkeypatch):
    """A correct fix to a partial PHP file passes all three checks (applies, parses, finding gone)."""
    def fake_patch_llm(prompt):
        code = re.search(r"```php\n(.*?)\n```", prompt, re.S).group(1)
        return {"fixed_code": code.replace("$input_hash == $user_hash", "hash_equals($user_hash, $input_hash)")}
    monkeypatch.setattr(pipeline, "llm_status", lambda: {"ok": True, "reason": ""})
    monkeypatch.setattr(triage, "call_llm", lambda p: {"verdict": "true_positive", "explanation": "x"})
    monkeypatch.setattr(patch, "call_llm", fake_patch_llm)
    found = [p for e, p in pipeline.scan(PHP_HASH) if e == "finding"]
    assert found and found[0].badge.name == "VERIFIED", found[0].verify_log
    assert "<?php" not in found[0].patch
