from pathlib import Path

import pytest

from vouch.diff import parse_diff, write_workspace
from vouch.languages import check_syntax_text, is_supported, language_of
from vouch.models import Badge, Finding
from vouch.scanners import merge_findings, run_scanners, scanner_status
from vouch.trace import trace_finding

ROOT = Path(__file__).parent.parent
DEMO_JS = (ROOT / "examples" / "demo_js.diff").read_text()
needs_semgrep = pytest.mark.skipif(not scanner_status()["semgrep"], reason="semgrep not installed")


def test_language_detection():
    assert language_of("a/b.py") == "python"
    assert language_of("x.TS") == "typescript"
    assert language_of("App.java") == "java"
    assert not is_supported("README.md")


@pytest.mark.parametrize("lang,good,bad", [
    ("python", "x = 1\n", "x = (\n"),
    ("javascript", "const a = 1;\n", "function f({ return 1 }\n"),
    ("typescript", "let x: number = 1;\n", "let x: number = ;\n"),
    ("java", "class A { void f() { int x = 1; } }\n", "class A { void f() { int x = ; } }\n"),
    ("go", "package main\nfunc main() {}\n", "package main\nfunc main() {\n"),
    ("php", "<?php $a = 1;\n", "<?php function f( {\n"),
])
def test_syntax_check(lang, good, bad):
    assert check_syntax_text(good, lang)[0]
    ok, err = check_syntax_text(bad, lang)
    assert not ok and "line" in err


def test_trace_skips_non_python():
    f = Finding(id="1", tool="semgrep", rule_id="vouch-js-sql-injection", title="t", cwe="CWE-89",
                severity="high", file="a.js", line=1, message="m")
    assert trace_finding(f, "const q = 'SELECT ' + x;\n") == {"note": "", "lean": None}


@needs_semgrep
def test_semgrep_finds_js_demo_issues():
    files = parse_diff(DEMO_JS)
    found = merge_findings(run_scanners(write_workspace(files)), files)
    assert {f.rule_id for f in found} >= {"vouch-js-sql-injection", "vouch-js-command-injection",
                                         "vouch-js-hardcoded-secret"}


@needs_semgrep
@pytest.mark.skipif(not scanner_status()["bandit"], reason="bandit not installed")
def test_every_benchmark_case_is_detected():
    import re
    for case in sorted((ROOT / "benchmark" / "cases").iterdir()):
        if not is_supported(case):
            continue
        expected = re.search(r"expect:\s*(CWE-\d+)", case.read_text().splitlines()[0]).group(1)
        root = case.parent
        found = [f for f in run_scanners(root) if f.file == case.name]
        assert expected in {f.cwe for f in found}, case.name


def _js_finding(files, root):
    baseline = run_scanners(root)
    finding = next(f for f in merge_findings(baseline, files) if f.rule_id == "vouch-js-sql-injection")
    return finding, baseline


@needs_semgrep
def test_js_fix_loop_verifies_with_fake_model(monkeypatch):
    import vouch.patch as patch_mod
    files = parse_diff(DEMO_JS)
    root = write_workspace(files)
    finding, baseline = _js_finding(files, root)
    fixed = files[0].new_text.replace(
        "  const query = \"SELECT * FROM users WHERE email = '\" + email + \"'\";\n  return db.query(query);",
        "  const query = \"SELECT * FROM users WHERE email = ?\";\n  return db.query(query, [email]);")
    monkeypatch.setattr(patch_mod, "call_llm", lambda prompt: {"fixed_code": fixed})
    patch_mod.fix_with_retry(finding, root, baseline)
    assert finding.badge == Badge.VERIFIED


@needs_semgrep
def test_js_fix_with_syntax_error_is_rejected(monkeypatch):
    import vouch.patch as patch_mod
    files = parse_diff(DEMO_JS)
    root = write_workspace(files)
    finding, baseline = _js_finding(files, root)
    broken = files[0].new_text.replace("function login(email) {", "function login(email {")
    broken = broken.replace("\" + email + \"'\"", "?\"")
    monkeypatch.setattr(patch_mod, "call_llm", lambda prompt: {"fixed_code": broken})
    patch_mod.fix_with_retry(finding, root, baseline, max_retries=0)
    assert finding.badge != Badge.VERIFIED
    assert any("syntax error" in line for line in finding.verify_log)
