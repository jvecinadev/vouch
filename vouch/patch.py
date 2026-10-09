"""OWNER: Dev C. Generate a fix and retry until it verifies.

Design choice: the model returns the corrected CODE, and WE build the unified diff with difflib.
Small models often write broken diff headers; this keeps patches applying cleanly.
"""
import difflib
import math
from pathlib import Path

import config
from .context import context_window
from .languages import NAMES, language_of
from .llm import call_llm
from .models import Badge
from .review import TOOL as REVIEW_TOOL
from .verify import verify_patch

PATCH_PROMPT = """You fix security vulnerabilities with the smallest possible change.

Issue: {title} ({cwe}) at line {line}
Scanner message: {message}

Code (lines {start}-{end} of {file}, written in {language}):
```{fence}
{snippet}
```
{trace}{feedback}
Rewrite this code so the vulnerability is fixed. Keep everything else identical (same language, indentation, names, and behavior). Do not add explanations.
Reply with JSON only: {{"fixed_code": "<the full corrected code for the lines above>"}}"""


class PatchGenerationError(ValueError):
    """Raised when the model response is unsafe to turn into a patch."""


def _validate_fixed_code(response, original_snippet: str) -> str:
    """Reject malformed or suspiciously destructive model responses."""
    if not isinstance(response, dict):
        raise PatchGenerationError("The model response was not a JSON object.")
    fixed = response.get("fixed_code")
    if not isinstance(fixed, str):
        raise PatchGenerationError("The model response must contain a string named 'fixed_code'.")
    fixed = fixed.strip("\r\n")
    if not fixed.strip():
        raise PatchGenerationError("The model returned empty code; refusing to generate a deletion patch.")

    original_lines = original_snippet.splitlines()
    fixed_lines = fixed.splitlines()
    if len(original_lines) >= 8:
        original_nonblank = sum(bool(line.strip()) for line in original_lines)
        fixed_nonblank = sum(bool(line.strip()) for line in fixed_lines)
        if original_nonblank >= 4 and fixed_nonblank < max(2, math.ceil(original_nonblank * 0.25)):
            raise PatchGenerationError("The model response removes most of the original code; refusing the patch.")
        similarity = difflib.SequenceMatcher(
            None,
            "\n".join(line.rstrip() for line in original_lines),
            "\n".join(line.rstrip() for line in fixed_lines),
        ).ratio()
        if similarity < 0.25:
            raise PatchGenerationError("The model response differs too much from the original snippet; refusing the patch.")
    return fixed


def make_diff(path: str, old: str, new: str) -> str:
    path = str(path).replace("\\", "/")
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))


def generate_patch(finding, file_text: str, feedback: str = "") -> str:
    start, end, snippet = context_window(file_text, finding.line, config.CONTEXT_RADIUS)
    fb = f"\nYour previous attempt failed: {feedback}\nFix that problem.\n" if feedback else ""
    lang = language_of(finding.file)
    prompt = PATCH_PROMPT.format(language=NAMES.get(lang, "unknown"), fence=lang or "",
                                 title=finding.title, cwe=finding.cwe or "no CWE", line=finding.line,
                                 message=finding.message, start=start, end=end,
                                 file=finding.file, snippet=snippet, feedback=fb,
                                 trace=(finding.trace + "\n") if finding.trace else "")
    fixed = _validate_fixed_code(call_llm(prompt), snippet)
    lines = file_text.splitlines()
    new_lines = lines[:start - 1] + fixed.splitlines() + lines[end:]
    return make_diff(finding.file, file_text, "\n".join(new_lines) + "\n")


def fix_with_retry(finding, workspace, baseline: list, max_retries: int = None):
    """Generate -> verify -> retry with the error. Sets finding.patch / badge / attempts."""
    max_retries = config.MAX_RETRIES if max_retries is None else max_retries
    file_text = (Path(workspace) / finding.file).read_text(encoding="utf-8")
    feedback, last_applies = "", False
    for attempt in range(max_retries + 1):
        finding.attempts = attempt + 1
        try:
            finding.patch = generate_patch(finding, file_text, feedback)
        except Exception as e:
            feedback = f"model error: {e}"
            finding.verify_log.append(f"attempt {attempt + 1}: {feedback}")
            continue
        result = verify_patch(finding.patch, finding, workspace, baseline)
        last_applies = result.applies
        if attempt == 0:
            finding.first_try_applies = result.applies
        if finding.tool == REVIEW_TOOL and result.applies and result.parses:
            finding.badge = Badge.AI_CHECKED
            finding.verify_log.append(f"attempt {attempt + 1}: applies and parses "
                                      "(AI-found issue: no scanner rule can re-check it)")
            return finding
        if result.ok:
            finding.badge = Badge.VERIFIED
            finding.verify_log.append(f"attempt {attempt + 1}: verified")
            return finding
        feedback = result.error
        finding.verify_log.append(f"attempt {attempt + 1}: {result.error}")
    finding.badge = Badge.UNVERIFIED if (finding.patch and last_applies) else Badge.NEEDS_HUMAN
    return finding