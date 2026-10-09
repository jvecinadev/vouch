from pathlib import Path

import pytest

import config
from vouch.diff import parse_diff, write_workspace
from vouch.models import Badge
from vouch.patch import make_diff
from vouch.pipeline import scan
from vouch.sarif import export_sarif
from vouch.scanners import merge_findings, run_scanners, scanner_status
from vouch.verify import check_applies, check_syntax

DEMO = (Path(__file__).parent.parent / "examples" / "demo_sqli.diff").read_text()


def test_parse_diff_reconstructs_new_file():
    files = parse_diff(DEMO)
    assert [f.path for f in files] == ["auth/login.py"]
    assert "SELECT * FROM users" in files[0].new_text
    assert 10 in files[0].added_lines


def test_workspace_blocks_path_traversal():
    files = parse_diff(DEMO)
    files[0].path = "../evil.py"
    root = write_workspace(files)
    assert not (root.parent / "evil.py").exists()


def test_patch_applies_and_parses():
    f = parse_diff(DEMO)[0]
    root = write_workspace([f])
    new = f.new_text.replace("cursor.execute(query)", "cursor.execute(query, (email,))")
    patch = make_diff(f.path, f.new_text, new)
    ok, err = check_applies(patch, root)
    assert ok, err
    assert check_syntax(root / f.path)[0]


def test_sarif_shape():
    from vouch.mock import mock_findings
    sarif = export_sarif(mock_findings())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 2


def test_mock_scan_yields_findings(monkeypatch):
    monkeypatch.setattr(config, "USE_MOCK", True)
    events = list(scan(""))
    assert any(e == "finding" for e, _ in events)


@pytest.mark.skipif(not scanner_status()["bandit"], reason="bandit not installed")
def test_bandit_finds_demo_issues():
    files = parse_diff(DEMO)
    root = write_workspace(files)
    found = merge_findings(run_scanners(root), files)
    assert {f.rule_id for f in found} >= {"B608"}


@pytest.mark.skipif(not scanner_status()["bandit"], reason="bandit not installed")
def test_fix_loop_verifies_with_fake_model(monkeypatch):
    import vouch.patch as patch_mod
    files = parse_diff(DEMO)
    root = write_workspace(files)
    baseline = run_scanners(root)
    finding = next(f for f in merge_findings(baseline, files) if f.rule_id == "B608")
    fixed = files[0].new_text.replace(
        "    query = f\"SELECT * FROM users WHERE email = '{email}'\"\n    cursor.execute(query)",
        "    query = \"SELECT * FROM users WHERE email = ?\"\n    cursor.execute(query, (email,))")
    monkeypatch.setattr(patch_mod, "call_llm", lambda prompt: {"fixed_code": fixed})
    patch_mod.fix_with_retry(finding, root, baseline)
    assert finding.badge == Badge.VERIFIED
