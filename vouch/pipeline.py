"""OWNER: Dev A. Glue: diff -> scan -> triage -> fix -> verify. Yields events so the UI can stream.

Events: ("status", str) | ("finding", Finding) | ("error", str)
"""
import shutil
from pathlib import Path

import config
from . import mock
from .diff import parse_diff, write_workspace
from .llm import llm_status
from .models import Badge
from .patch import fix_with_retry
from .scanners import merge_findings, run_scanners
from .triage import triage_finding


def scan(diff_text: str):
    if config.USE_MOCK:
        yield from mock.scan()
        return
    yield "status", "Parsing diff"
    files = [f for f in parse_diff(diff_text) if f.path.endswith(".py")]
    if not files:
        yield "error", "No Python files found in this diff. Vouch v1 scans Python only."
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
            text = (Path(workspace) / f.file).read_text()
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
