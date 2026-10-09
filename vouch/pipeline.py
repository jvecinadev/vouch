"""OWNER: Dev A. Glue: diff -> scan -> triage -> fix -> verify. Yields events so the UI can stream.

Events: ("status", str) | ("finding", Finding) | ("error", str)
"""
import shutil
from pathlib import Path

import config
from . import mock
from .diff import code_to_diff, is_diff, parse_diff, write_workspace
from .languages import EXTENSION, NAMES, guess_language, is_supported, supported_names
from .llm import llm_status
from .models import Badge
from .patch import fix_with_retry
from .scanners import merge_findings, run_scanners
from .triage import triage_finding


def scan(diff_text: str, language: str = "auto"):
    """`language` is only used when plain code (not a diff) is pasted: "auto" or e.g. "javascript"."""
    if config.USE_MOCK:
        yield from mock.scan()
        return
    yield "status", "Parsing diff"
    if not diff_text.strip():
        yield "error", "Nothing to scan. Paste a git diff or some code, or click a demo button."
        return
    if not is_diff(diff_text):
        lang = guess_language(diff_text) if language in (None, "", "auto") else language
        if lang not in EXTENSION:
            yield "error", ("This is plain code and Vouch couldn't tell its language. "
                            "Pick it in the Language list, or paste a git diff.")
            return
        name = f"pasted{EXTENSION[lang]}"
        yield "status", f"Plain code: scanning it as {NAMES[lang]} ({name})"
        diff_text = code_to_diff(diff_text, name)
    files = [f for f in parse_diff(diff_text) if is_supported(f.path)]
    if not files:
        yield "error", f"No supported files found in this diff. Vouch reads: {supported_names()}."
        return
    workspace = write_workspace(files)
    try:
        yield "status", "Scanning with Bandit and Semgrep"
        baseline = run_scanners(workspace)
        findings = merge_findings(baseline, files)[:config.MAX_FINDINGS]
        if not findings:
            yield "status", "No issues detected by the scanner rules (this is not a guarantee of safety)"
            return
        model = llm_status()
        if not model["ok"]:
            yield "status", f"Scanner-only mode. {model['reason']}"
            for f in findings:
                f.badge = Badge.SKIPPED
                yield "finding", f
            return
        for i, f in enumerate(findings, 1):
            text = (Path(workspace) / f.file).read_text(encoding="utf-8")
            yield "status", f"Triaging {i} of {len(findings)}"
            triage_finding(f, text)
            if f.verdict == "likely_false_positive":
                f.badge = Badge.SKIPPED
                yield "finding", f
                continue
            yield "status", f"Fixing and verifying {i} of {len(findings)}"
            fix_with_retry(f, workspace, baseline)
            yield "finding", f
        yield "status", "Done"
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
