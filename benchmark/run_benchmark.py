"""OWNER: Dev C. Run every case in benchmark/cases through the pipeline for each model.

Each case is a source file (any supported language) whose FIRST line contains:  expect: CWE-89
e.g.  # expect: CWE-89   or   // expect: CWE-78   or   <?php // expect: CWE-78
Usage:  python benchmark/run_benchmark.py qwen2.5-coder:1.5b qwen2.5-coder:3b
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config                                  # noqa: E402
from vouch.languages import is_supported       # noqa: E402
from vouch.models import Badge                 # noqa: E402
from vouch.pipeline import scan                # noqa: E402

CASES = sorted(p for p in (Path(__file__).parent / "cases").iterdir() if is_supported(p))


def file_to_diff(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    return (f"diff --git a/{path.name} b/{path.name}\nnew file mode 100644\n--- /dev/null\n"
            f"+++ b/{path.name}\n@@ -0,0 +1,{len(lines)} @@\n" + "\n".join("+" + l for l in lines) + "\n")


def run(model: str) -> dict:
    config.MODEL = model
    row = {"cases": 0, "detected": 0, "triage_ok": 0, "applies_first_try": 0, "verified": 0}
    for case in CASES:
        expected = re.search(r"expect:\s*(CWE-\d+)", case.read_text(encoding="utf-8").splitlines()[0]).group(1)
        findings = [p for ev, p in scan(file_to_diff(case)) if ev == "finding"]
        match = next((f for f in findings if f.cwe == expected), None)
        row["cases"] += 1
        if match:
            row["detected"] += 1
            row["triage_ok"] += match.verdict == "true_positive"
            row["applies_first_try"] += match.first_try_applies
            row["verified"] += match.badge == Badge.VERIFIED
    return row


if __name__ == "__main__":
    models = sys.argv[1:] or [config.MODEL]
    print("| Model | Cases | Detected | Triage correct | Patch applies (1st try) | Fix verified |")
    print("|---|---|---|---|---|---|")
    for m in models:
        r = run(m)
        print(f"| {m} | {r['cases']} | {r['detected']} | {r['triage_ok']} | {r['applies_first_try']} | {r['verified']} |")
