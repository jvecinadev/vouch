"""Ollama-loading, host-setting and text-encoding fixes."""
import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

import config
from vouch import llm, pipeline
from vouch.languages import guess_language, language_of
from vouch.scanners import scanner_status


def _fake_ollama(monkeypatch, listing):
    mod = types.ModuleType("ollama")
    mod.Client = lambda host: SimpleNamespace(list=lambda: listing)
    monkeypatch.setitem(sys.modules, "ollama", mod)
    monkeypatch.setattr(llm, "_cached", None)


def test_missing_ollama_package_is_scanner_only(monkeypatch):
    monkeypatch.setitem(sys.modules, "ollama", None)      # makes `import ollama` raise ImportError
    monkeypatch.setattr(llm, "_cached", None)
    status = llm.llm_status()
    assert not status["ok"] and "not installed" in status["reason"]


@pytest.mark.parametrize("listing", [
    {"models": [{"name": "qwen2.5-coder:3b"}]},                              # old SDK: dicts
    SimpleNamespace(models=[SimpleNamespace(model="qwen2.5-coder:3b")]),     # new SDK: objects
])
def test_model_listing_both_sdk_styles(monkeypatch, listing):
    monkeypatch.setattr(config, "MODEL", "qwen2.5-coder:3b")
    _fake_ollama(monkeypatch, listing)
    assert llm.llm_status()["ok"]


def test_ollama_host_falls_back_to_standard_variable(monkeypatch):
    monkeypatch.delenv("VOUCH_OLLAMA_HOST", raising=False)
    monkeypatch.setenv("OLLAMA_HOST", "0.0.0.0:11434")
    try:
        assert importlib.reload(config).OLLAMA_HOST == "127.0.0.1:11434"
        monkeypatch.setenv("VOUCH_OLLAMA_HOST", "http://gpu-box:11434")
        assert importlib.reload(config).OLLAMA_HOST == "http://gpu-box:11434"
    finally:
        monkeypatch.undo()
        importlib.reload(config)


NON_ASCII_DIFF = """diff --git a/café.py b/café.py
new file mode 100644
--- /dev/null
+++ b/café.py
@@ -0,0 +1,4 @@
+# Grüße, naïve café ☕
+def find(cursor, name):
+    q = f"SELECT * FROM users WHERE name = '{name}'"
+    return cursor.execute(q)
"""


@pytest.mark.skipif(not scanner_status()["bandit"], reason="bandit not installed")
def test_non_ascii_file_does_not_crash(monkeypatch):
    monkeypatch.setattr(pipeline, "llm_status", lambda: {"ok": False, "reason": "test"})
    events = list(pipeline.scan(NON_ASCII_DIFF))
    assert not [p for e, p in events if e == "error"]
    assert [p for e, p in events if e == "finding"]


def test_empty_input_gets_a_clear_error():
    assert list(pipeline.scan("  \n"))[-1][0] == "error"


@pytest.mark.parametrize("case", sorted(p for p in (Path(__file__).parent.parent / "benchmark" / "cases").iterdir()
                                         if language_of(p)))
def test_guess_language_of_plain_code(case):
    assert guess_language(case.read_text(encoding="utf-8")) == language_of(case)


def test_unknown_plain_text_asks_for_language():
    events = list(pipeline.scan("hello there, general kenobi"))
    assert events[-1][0] == "error" and "Language list" in events[-1][1]


PLAIN_JS = (Path(__file__).parent.parent / "benchmark" / "cases" / "sqli_js_01.js").read_text(encoding="utf-8")


@pytest.mark.skipif(not scanner_status()["semgrep"], reason="semgrep not installed")
@pytest.mark.parametrize("language", ["auto", "javascript"])
def test_plain_code_is_scanned(monkeypatch, language):
    monkeypatch.setattr(pipeline, "llm_status", lambda: {"ok": False, "reason": "test"})
    events = list(pipeline.scan(PLAIN_JS, language))
    findings = [p for e, p in events if e == "finding"]
    assert findings and all(f.file == "pasted.js" for f in findings)
