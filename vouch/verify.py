"""OWNER: Dev B. The three checks that decide whether Vouch will stand behind a patch."""
import ast
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .scanners import run_scanners


@dataclass
class VerifyResult:
    applies: bool = False
    parses: bool = False
    finding_gone: bool = False
    error: str = ""          # fed back to the model on retry

    @property
    def ok(self) -> bool:
        return self.applies and self.parses and self.finding_gone


def check_applies(patch: str, workspace) -> tuple:
    proc = subprocess.run(["git", "apply", "--check", "-"], input=patch, cwd=str(workspace),
                          capture_output=True, text=True)
    return proc.returncode == 0, proc.stderr.strip()


def apply_to_copy(patch: str, workspace) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="vouch-patched-"))
    shutil.copytree(workspace, tmp, dirs_exist_ok=True)
    subprocess.run(["git", "apply", "-"], input=patch, cwd=str(tmp),
                   capture_output=True, text=True, check=True)
    return tmp


def check_syntax(file_path) -> tuple:
    try:
        ast.parse(Path(file_path).read_text())
        return True, ""
    except SyntaxError as e:
        return False, f"{e.msg} (line {e.lineno})"


def check_finding_gone(patched_dir, finding, baseline: list) -> bool:
    """The same rule must fire fewer times in that file than before the patch."""
    before = sum(1 for f in baseline if f.file == finding.file and f.rule_id == finding.rule_id)
    after = sum(1 for f in run_scanners(patched_dir)
                if f.file == finding.file and f.rule_id == finding.rule_id)
    return after < before


def verify_patch(patch: str, finding, workspace, baseline: list) -> VerifyResult:
    if not patch.strip():
        return VerifyResult(error="The patch was empty.")
    applies, err = check_applies(patch, workspace)
    if not applies:
        return VerifyResult(error=f"The patch did not apply: {err}")
    patched = None
    try:
        patched = apply_to_copy(patch, workspace)
        parses, err = check_syntax(patched / finding.file)
        if not parses:
            return VerifyResult(applies=True, error=f"The patched code has a syntax error: {err}")
        gone = check_finding_gone(patched, finding, baseline)
        if not gone:
            return VerifyResult(applies=True, parses=True,
                                error=f"The scanner still reports {finding.rule_id} after your patch.")
        return VerifyResult(applies=True, parses=True, finding_gone=True)
    except subprocess.CalledProcessError as e:
        return VerifyResult(error=f"The patch could not be applied: {e.stderr}")
    finally:
        if patched:
            shutil.rmtree(patched, ignore_errors=True)
