"""OWNER: Dev B. Run Bandit and Semgrep, normalize results into Finding objects."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys

import config
from .models import Finding

SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low",
            "ERROR": "high", "WARNING": "medium", "INFO": "low"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _has_bandit() -> bool:
    return importlib.util.find_spec("bandit") is not None   # works even if the venv isn't "activated"


def _rel(file_path, base) -> str:
    """Relative path with forward slashes, so Windows paths match the diff's a/b paths."""
    return os.path.relpath(file_path, str(base)).replace(os.sep, "/")


def scanner_status() -> dict:
    return {"bandit": _has_bandit(),
            "semgrep": shutil.which("semgrep") is not None}


def run_bandit(path) -> list:
    if not _has_bandit():
        return []
    proc = subprocess.run([sys.executable, "-m", "bandit", "-r", str(path), "-f", "json", "-q"],
                          capture_output=True, text=True)   # exit code 1 just means "issues found"
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    out = []
    for i, r in enumerate(data.get("results", [])):
        cwe = (r.get("issue_cwe") or {}).get("id")
        out.append(Finding(
            id=f"bandit-{i}", tool="bandit", rule_id=r["test_id"],
            title=r["test_name"].replace("_", " "),
            cwe=f"CWE-{cwe}" if cwe else None,
            severity=SEVERITY.get(r["issue_severity"], "low"),
            file=_rel(r["filename"], path), line=r["line_number"],
            message=r["issue_text"], code=r.get("code", "")))
    return out


def run_semgrep(path) -> list:
    if not shutil.which("semgrep") or not os.path.isdir(config.RULES_DIR):
        return []
    proc = subprocess.run(["semgrep", "--config", config.RULES_DIR, "--json", "--quiet",
                           "--metrics=off", "--disable-version-check", str(path)],
                          capture_output=True, text=True)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    out = []
    for i, r in enumerate(data.get("results", [])):
        extra = r.get("extra", {})
        cwes = (extra.get("metadata") or {}).get("cwe") or []
        cwe = cwes[0].split(":")[0] if cwes else None
        out.append(Finding(
            id=f"semgrep-{i}", tool="semgrep", rule_id=r["check_id"].split(".")[-1],
            title=r["check_id"].split(".")[-1].replace("-", " "), cwe=cwe,
            severity=SEVERITY.get(extra.get("severity", "INFO"), "low"),
            file=_rel(r["path"], path), line=r["start"]["line"],
            message=extra.get("message", ""), code=extra.get("lines", "")))
    return out


def run_scanners(path) -> list:
    return run_bandit(path) + run_semgrep(path)


def merge_findings(findings: list, files: list) -> list:
    """Keep only findings on lines the diff added, drop duplicates, sort by severity."""
    added = {f.path: f.added_lines for f in files}
    seen, out = set(), []
    for f in findings:
        if f.file in added and f.line not in added[f.file]:
            continue
        key = (f.file, f.line, f.cwe or f.rule_id)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    out.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.file, f.line))
    return out