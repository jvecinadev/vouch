"""A: the diff-aware removed-safeguard check. B: the model's own review of the diff."""
import re

import pytest

from vouch import patch, pipeline, review, triage
from vouch.diff import parse_diff
from vouch.models import Badge
from vouch.safeguards import removed_safeguards
from vouch.scanners import scanner_status

IN_ARRAY = """diff --git a/controllers/AdminController.php b/controllers/AdminController.php
index a1b2c3d..e4f5g6h 100644
--- a/controllers/AdminController.php
+++ b/controllers/AdminController.php
@@ -10,7 +10,7 @@ class AdminController {
     public function checkAccess($role) {
         $allowed_roles = ['admin', 'moderator'];
         
-        // Strict type check to ensure exact match
-        if (in_array($role, $allowed_roles, true)) {
+        // Refactoring: removed strict parameter for cleaner code
+        if (in_array($role, $allowed_roles)) {
             return true;
         }
"""


PHP_HASH = """diff --git a/auth/auth.php b/auth/auth.php
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


def _diff(path, start, body):
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -{start},9 +{start},9 @@\n{body}"


def _scan(monkeypatch, diff, model=False):
    monkeypatch.setattr(pipeline, "llm_status", lambda: {"ok": model, "reason": "test"})
    return [p for e, p in pipeline.scan(diff) if e == "finding"]


def test_user_in_array_diff_is_flagged(monkeypatch):
    assert [(f.line, f.rule_id, f.tool) for f in _scan(monkeypatch, IN_ARRAY)] == [
        (14, "vouch-removed-strict-in-array", "safeguard")]


@pytest.mark.parametrize("diff, expected", [
    (_diff("web/app.js", 3, ' function isAdmin(u) {\n-  return u.role === "admin";\n+  return u.role == "admin";\n }\n'),
     (4, "vouch-removed-strict-equality")),
    (_diff("Auth.java", 7, "-    return MessageDigest.isEqual(a, b);\n+    return Arrays.equals(a, b);\n"),
     (7, "vouch-removed-constant-time-compare")),
    (_diff("views.py", 20, " \n-@login_required\n def settings(request):\n"),
     (21, "vouch-removed-authorization-check")),
    (_diff("page.php", 5, '-echo htmlspecialchars($name);\n+echo $name;\n'),
     (5, "vouch-removed-output-escaping")),
    (_diff("db.go", 9, " rows, err := db.Query(q)\n-if err != nil {\n-\treturn err\n-}\n defer rows.Close()\n"),
     (10, "vouch-removed-error-check")),
])
def test_removed_safeguards(diff, expected):
    assert [(f.line, f.rule_id) for f in removed_safeguards(parse_diff(diff), [])] == [expected]


def test_moved_safeguard_is_not_flagged():
    diff = ("diff --git a/a.php b/a.php\n--- a/a.php\n+++ b/a.php\n"
            "@@ -3,2 +3,1 @@\n-$ok = hash_equals($a, $b);\n-log('x');\n+log('x');\n"
            "@@ -20,1 +19,2 @@\n+$ok = hash_equals($a, $b);\n return $ok;\n")
    assert removed_safeguards(parse_diff(diff), []) == []


def test_strict_flag_kept_is_not_flagged():
    diff = _diff("a.php", 1, "-if (in_array($r, $ok, true)) {\n+if (in_array($r, $allowed, true)) {\n")
    assert removed_safeguards(parse_diff(diff), []) == []


@pytest.mark.skipif(not scanner_status()["semgrep"], reason="semgrep not installed")
def test_no_duplicate_card_when_a_scanner_reports_the_same_line(monkeypatch):
    assert [(f.line, f.rule_id) for f in _scan(monkeypatch, PHP_HASH)] == [(7, "vouch-php-loose-secret-compare")]


def _fake_fix(replace_from, replace_to, fence="php"):
    def fake(prompt):
        code = re.search(rf"```{fence}\n(.*?)\n```", prompt, re.S).group(1)
        return {"fixed_code": code.replace(replace_from, replace_to)}
    return fake


def test_in_array_fix_verifies_in_a_partial_class(monkeypatch):
    """The file is a method without its class, so it never parses; the fix must add no new errors."""
    monkeypatch.setattr(triage, "call_llm", lambda p: {"verdict": "true_positive", "explanation": "x"})
    monkeypatch.setattr(patch, "call_llm", _fake_fix("$allowed_roles))", "$allowed_roles, true))"))
    found = _scan(monkeypatch, IN_ARRAY, model=True)
    assert found[0].badge == Badge.VERIFIED, found[0].verify_log


def test_fix_that_does_not_restore_the_safeguard_is_not_verified(monkeypatch):
    monkeypatch.setattr(triage, "call_llm", lambda p: {"verdict": "true_positive", "explanation": "x"})
    monkeypatch.setattr(patch, "call_llm", _fake_fix("Refactoring", "Note"))
    found = _scan(monkeypatch, IN_ARRAY, model=True)
    assert found[0].badge != Badge.VERIFIED
    assert "still missing" in found[0].verify_log[0]


LOGIN = _diff("auth/login.py", 30,
              " def can_login(user):\n-    return user.is_active and not user.is_locked\n+    return user.is_active\n")


def test_ai_review_finds_what_no_rule_covers(monkeypatch):
    monkeypatch.setattr(review, "call_llm", lambda p: {"issues": [{
        "line": 99, "title": "Locked accounts can log in", "cwe": "CWE-285 Improper Authorization",
        "severity": "high", "explanation": "The is_locked check was removed."}]})
    monkeypatch.setattr(triage, "call_llm", lambda p: {"verdict": "true_positive", "explanation": "x"})
    monkeypatch.setattr(patch, "call_llm", _fake_fix("return user.is_active",
                                                    "return user.is_active and not user.is_locked", "python"))
    found = _scan(monkeypatch, LOGIN, model=True)
    assert [(f.line, f.tool, f.cwe) for f in found] == [(31, "ai-review", "CWE-285")]   # line snapped to the + line
    assert found[0].badge == Badge.AI_CHECKED, found[0].verify_log


def test_ai_review_bad_output_is_ignored(monkeypatch):
    def broken(prompt):
        raise ValueError("not JSON")
    monkeypatch.setattr(review, "call_llm", broken)
    monkeypatch.setattr(pipeline, "llm_status", lambda: {"ok": True, "reason": ""})
    events = list(pipeline.scan(LOGIN))
    assert not [p for e, p in events if e == "finding"]
    assert any("model review failed" in p for e, p in events if e == "status")
    monkeypatch.setattr(review, "call_llm", lambda p: {"issues": "none", "x": [1]})
    assert not [p for e, p in pipeline.scan(LOGIN) if e == "finding"]


def test_ai_review_does_not_repeat_a_safeguard_finding(monkeypatch):
    monkeypatch.setattr(review, "call_llm", lambda p: {"issues": [{
        "line": 14, "title": "Loose in_array", "cwe": "CWE-697", "severity": "high", "explanation": "x"}]})
    monkeypatch.setattr(triage, "call_llm", lambda p: {"verdict": "true_positive", "explanation": "x"})
    monkeypatch.setattr(patch, "call_llm", _fake_fix("$allowed_roles))", "$allowed_roles, true))"))
    assert [f.tool for f in _scan(monkeypatch, IN_ARRAY, model=True)] == ["safeguard"]


GO_TWO_FILES = """diff --git a/cache/store.go b/cache/store.go
index 1234567..89abcdef 100644
--- a/cache/store.go
+++ b/cache/store.go
@@ -10,12 +10,10 @@ type SessionCache struct {
 
 // Set stores user session data
 func (c *SessionCache) Set(token string, userID int) {
-\tc.mu.Lock()
-\tdefer c.mu.Unlock()
-\tc.data[token] = userID
+\t// Performance optimization: removed lock contention on map writes
+\tc.data[token] = userID
 }

diff --git a/client/client.go b/client/client.go
index 1234567..89abcdef 100644
--- a/client/client.go
+++ b/client/client.go
@@ -10,12 +10,10 @@ import (
 
 // FetchUserData makes an outgoing HTTP request and returns the body
 func FetchUserData(url string) ([]byte, error) {
 \tresp, err := http.Get(url)
 \tif err != nil {
 \t\treturn nil, err
 \t}
-\t// Ensure connection is returned to the pool
-\tdefer resp.Body.Close()
 \t
-\treturn io.ReadAll(resp.Body)
+\t// Refactoring: removed defer since io.ReadAll already consumes the stream
+\treturn io.ReadAll(resp.Body)
 }
"""


def test_wrong_hunk_counts_do_not_swallow_the_next_file():
    files = parse_diff(GO_TWO_FILES)
    assert [f.path for f in files] == ["cache/store.go", "client/client.go"]
    assert "diff --git" not in files[0].new_text
    assert files[1].added_lines == {18, 19}


def test_removed_lock_and_close_are_flagged(monkeypatch):
    assert [(f.file, f.line, f.rule_id) for f in _scan(monkeypatch, GO_TWO_FILES)] == [
        ("cache/store.go", 14, "vouch-removed-lock"),
        ("client/client.go", 18, "vouch-removed-close")]


def test_lock_fix_verifies(monkeypatch):
    monkeypatch.setattr(triage, "call_llm", lambda p: {"verdict": "true_positive", "explanation": "x"})
    monkeypatch.setattr(patch, "call_llm", _fake_fix(
        "\t// Performance optimization: removed lock contention on map writes\n",
        "\tc.mu.Lock()\n\tdefer c.mu.Unlock()\n", "go"))
    found = _scan(monkeypatch, GO_TWO_FILES, model=True)
    lock = next(f for f in found if f.rule_id == "vouch-removed-lock")
    assert lock.badge == Badge.VERIFIED, lock.verify_log
