"""Diff-aware check: flag a change that REMOVES a known safeguard (hash_equals -> ==, strict in_array -> loose, ...).
Bandit and Semgrep only see the new code, so they can't notice that something safe was taken out.
A fix counts as verified once the safeguard is back (see restored())."""
import difflib
import re
from dataclasses import dataclass

from .diff import change_blocks
from .languages import language_of
from .models import Finding

TOOL = "safeguard"
JS = ("javascript", "typescript", "tsx")


@dataclass(frozen=True)
class Safeguard:
    rule_id: str
    languages: tuple          # empty = every language
    pattern: str
    title: str
    cwe: str
    severity: str
    advice: str


SAFEGUARDS = [
    Safeguard("vouch-removed-constant-time-compare", (),
              r"\b(hash_equals|compare_digest|timingSafeEqual|ConstantTimeCompare|MessageDigest\.isEqual)\s*\(",
              "constant-time comparison removed", "CWE-208", "high",
              "A constant-time comparison of a secret was removed. A normal comparison leaks timing, "
              "and in PHP == also does type juggling (\"0e123\" == \"0e456\"). Keep the constant-time comparison."),
    Safeguard("vouch-removed-password-check", (),
              r"\b(password_verify|check_password_hash|check_password|checkpw|compareSync|"
              r"CompareHashAndPassword|bcrypt\.compare)\s*\(",
              "password hash check removed", "CWE-287", "high",
              "A password-hash check was removed, so passwords may now be compared in plain text or not at all."),
    Safeguard("vouch-removed-strict-in-array", ("php",),
              r"\b(in_array|array_search|array_keys)\s*\([^;]*,\s*true\s*\)",
              "strict in_array() removed", "CWE-697", "high",
              "The strict flag (third argument true) was removed. A loose in_array()/array_search() compares "
              "with ==, so values of another type can match an allow-list (e.g. true or 0 against ['admin']). "
              "Keep strict mode for role and allow-list checks."),
    Safeguard("vouch-removed-strict-equality", ("php",) + JS,
              r"===|!==",
              "strict comparison replaced by loose", "CWE-697", "medium",
              "A strict === / !== comparison was replaced. Loose == converts types before comparing, "
              "so unexpected values can pass the check."),
    Safeguard("vouch-removed-authorization-check", (),
              r"(?i)\b(is_?admin|is_?authori[sz]ed|authori[sz]e|check_?(permission|access|role)s?|"
              r"has_?(role|permission|access)s?|require_?(auth|login|role)|login_required|"
              r"permission_required|verify_?(token|csrf|signature)|csrf_?(protect|token|check))\b",
              "authorization check removed", "CWE-862", "high",
              "An authentication / authorization check was removed, so the code may now run for users "
              "who should not be allowed."),
    Safeguard("vouch-removed-sql-parameters", (),
              r"\b(prepareStatement|bindParam|bindValue|bind_param|real_escape_string|setString|setInt)\s*\(|"
              r"->prepare\s*\(",
              "parameterized query removed", "CWE-89", "high",
              "A prepared statement / bound parameter was removed. Building the query from strings allows SQL injection."),
    Safeguard("vouch-removed-shell-escaping", (),
              r"\b(escapeshellarg|escapeshellcmd|shlex\.quote|quote)\s*\(",
              "shell escaping removed", "CWE-78", "high",
              "Shell escaping was removed, so user input can now inject commands."),
    Safeguard("vouch-removed-output-escaping", (),
              r"\b(htmlspecialchars|htmlentities|html\.escape|escape|DOMPurify\.sanitize|sanitize|"
              r"HTMLEscapeString|EscapeString|encodeURIComponent)\s*\(",
              "output escaping removed", "CWE-79", "high",
              "Escaping / sanitizing of output was removed, which can allow cross-site scripting."),
    Safeguard("vouch-removed-lock", (),
              r"\.R?Lock\s*\(\s*\)|\.lock\s*\(\s*\)|\.acquire\s*\(|\bsynchronized\b|\bwith\s+[\w.]*lock\b",
              "lock removed", "CWE-362", "high",
              "A lock was removed, so several threads/goroutines can now change this data at the same time "
              "(a race condition; in Go, concurrent map writes crash the program). Keep the lock."),
    Safeguard("vouch-removed-close", (),
              r"\.Close\s*\(\s*\)|\.close\s*\(\s*\)|\b(fclose|curl_close|mysqli_close)\s*\(",
              "resource close removed", "CWE-772", "medium",
              "A Close()/close() call was removed, so the connection, file or handle is never released. "
              "Under load this leaks connections or file descriptors until the service fails "
              "(in Go, keep defer resp.Body.Close())."),
    Safeguard("vouch-removed-error-return", ("go",),
              r"\b(errors\.(New|Wrapf?|Join)|fmt\.Errorf)\s*\(",
              "error return removed", "CWE-703", "high",
              "An error the function used to return was removed, so callers now treat a failure as success."),
    Safeguard("vouch-removed-error-check", ("go",),
              r"\bif\s+err\s*!=\s*nil\b",
              "error check removed", "CWE-391", "high",
              "An `if err != nil` check was removed, so a failure is now ignored."),
]
BY_ID = {s.rule_id: s for s in SAFEGUARDS}


def _count(pattern, texts) -> int:
    return sum(len(re.findall(pattern, t)) for t in texts)


def _hunk_range(hunk) -> range:
    nos = [no for _, no, _ in hunk]
    return range(min(nos) - 1, max(nos) + 2) if nos else range(0)


def removed_safeguards(files: list, existing: list) -> list:
    """Findings for safeguards the diff removed and did not add back anywhere in the same file.
    Skipped when a scanner already reports the same line, or the same CWE in the same hunk."""
    out = []
    for f in files:
        lang = language_of(f.path)
        for sg in SAFEGUARDS:
            if sg.languages and lang not in sg.languages:
                continue
            removed = [t for h in f.hunks for tag, _, t in h if tag == "-"]
            added = [t for h in f.hunks for tag, _, t in h if tag == "+"]
            missing = _count(sg.pattern, removed) - _count(sg.pattern, added)
            for hunk in f.hunks:
                span = _hunk_range(hunk)
                for gone, new, anchor in change_blocks(hunk):
                    if missing <= 0 or _count(sg.pattern, gone) <= _count(sg.pattern, [t for _, t in new]):
                        continue
                    old = next(t for t in gone if re.search(sg.pattern, t))
                    hunk_added = [no for tag, no, _ in hunk if tag == "+"]
                    if new:
                        line = max(new, key=lambda n: difflib.SequenceMatcher(None, old, n[1]).ratio())[0]
                    else:                              # pure removal: point at the nearest added line, if any
                        line = min(hunk_added, key=lambda n: abs(n - anchor)) if hunk_added else anchor
                    if any(e.file == f.path and (e.line == line or (e.line in span and e.cwe == sg.cwe))
                           for e in existing + out):
                        continue
                    missing -= 1
                    out.append(Finding(
                        id=f"safeguard-{len(out)}", tool=TOOL, rule_id=sg.rule_id, title=sg.title,
                        cwe=sg.cwe, severity=sg.severity, file=f.path, line=line,
                        message=f"{sg.advice} Removed line: {old.strip()}", code=old.strip()))
    return out


def restored(finding, before_text: str, after_text: str) -> bool:
    """The fix is verified when the safeguard appears more often in the patched file than before."""
    pattern = BY_ID[finding.rule_id].pattern
    return _count(pattern, [after_text]) > _count(pattern, [before_text])
