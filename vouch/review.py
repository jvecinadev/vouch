"""The local model reads each changed hunk (removed and added lines) and reports security regressions
that no scanner rule or safeguard check covers. No scanner can re-check these, so they get their own badge."""
import re

import config
from .languages import NAMES, language_of
from .llm import call_llm
from .models import Finding

TOOL = "ai-review"
RULE_ID = "vouch-ai-review"

REVIEW_PROMPT = """You are a security code reviewer. Below is one change from a git diff of {file} ({language}).
Lines marked "-" were removed, "+" were added, and the others are unchanged. The number is the line in the new file.

```diff
{hunk}
```

Did this change add a security vulnerability or weaken a security check (for example: a weaker comparison,
removed validation, escaping, authorization, or error handling)? Only report real security problems caused
by this change. Do not report style issues.
Reply with JSON only:
{{"issues": [{{"line": <line number of a "+" line>, "title": "short name of the problem", "cwe": "CWE-<id>", "severity": "critical" or "high" or "medium" or "low", "explanation": "2-3 plain sentences: what changed, why it is unsafe"}}]}}
Reply {{"issues": []}} if the change is safe."""


def format_hunk(hunk: list) -> str:
    rows = []
    for tag, no, text in hunk:
        rows.append(f"     - {text}" if tag == "-" else f"{no:>4} {'+' if tag == '+' else ' '} {text}")
    return "\n".join(rows)


def _snap(line, hunk):
    """Move the model's line onto the nearest added line of this hunk (small models miscount)."""
    added = [no for tag, no, _ in hunk if tag == "+"] or [no for tag, no, _ in hunk if tag == "-"]
    if not added:
        return None
    try:
        line = int(line)
    except (TypeError, ValueError):
        return added[0]
    return min(added, key=lambda n: abs(n - line))


def review_diff(files: list, existing: list) -> tuple:
    """Return (findings, errors). Findings on a line, or with a CWE in a hunk, already reported are dropped."""
    out, errors, reviewed = [], [], 0
    for f in files:
        lang = language_of(f.path)
        for hunk in f.hunks:
            if not any(tag in "+-" for tag, _, _ in hunk):
                continue
            if reviewed >= config.MAX_REVIEW_HUNKS:
                errors.append(f"model review stopped after {reviewed} changes")
                return out, errors
            reviewed += 1
            prompt = REVIEW_PROMPT.format(file=f.path, language=NAMES.get(lang, "unknown"), hunk=format_hunk(hunk))
            try:
                issues = call_llm(prompt).get("issues") or []
            except Exception as e:
                errors.append(f"model review failed on {f.path}: {e}")
                continue
            nos = [no for _, no, _ in hunk]
            span = range(min(nos) - 1, max(nos) + 2)
            for issue in issues[:3] if isinstance(issues, list) else []:
                if not isinstance(issue, dict) or not str(issue.get("title", "")).strip():
                    continue
                line = _snap(issue.get("line"), hunk)
                m = re.search(r"CWE-\d+", str(issue.get("cwe", "")))
                cwe = m.group(0) if m else None
                if line is None or any(e.file == f.path and (e.line == line or (e.line in span and cwe and e.cwe == cwe))
                                       for e in existing + out):
                    continue
                sev = issue.get("severity")
                explanation = str(issue.get("explanation", "")).strip() or str(issue["title"])
                out.append(Finding(
                    id=f"ai-{len(out)}", tool=TOOL, rule_id=RULE_ID, title=str(issue["title"]).strip()[:80],
                    cwe=cwe, severity=sev if sev in ("critical", "high", "medium", "low") else "medium",
                    file=f.path, line=line, message=explanation))
    return out, errors
