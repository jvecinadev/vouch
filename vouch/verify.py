"""OWNER: Dev B. The three checks that decide whether Vouch will stand behind a patch."""
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import review, safeguards
from .languages import check_syntax_text, count_syntax_errors, language_of
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
    proc = subprocess.run(["git", "apply", "--check", "-"], input=patch.encode(), cwd=str(workspace),
                          capture_output=True)
    return proc.returncode == 0, proc.stderr.decode(errors="replace").strip()


def apply_to_copy(patch: str, workspace) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="vouch-patched-"))
    shutil.copytree(workspace, tmp, dirs_exist_ok=True)
    subprocess.run(["git", "apply", "-"], input=patch.encode(), cwd=str(tmp),
                   capture_output=True, check=True)
    return tmp


def check_syntax(file_path) -> tuple:
    path = Path(file_path)
    return check_syntax_text(path.read_text(encoding="utf-8"), language_of(path))


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
        lang = language_of(finding.file)
        before = (Path(workspace) / finding.file).read_text(encoding="utf-8")
        after = (patched / finding.file).read_text(encoding="utf-8")
        parses, err = check_syntax(patched / finding.file)
        if not parses:
            # A diff often shows only part of a file (e.g. a method without its class), which never parses.
            # Then the patch only has to add no new syntax errors.
            old_errors = count_syntax_errors(before, lang)
            parses = 0 < old_errors and count_syntax_errors(after, lang) <= old_errors
        if not parses:
            return VerifyResult(applies=True, error=f"The patched code has a syntax error: {err}")
        if finding.tool == review.TOOL:           # AI-found: no scanner rule exists to re-check it
            return VerifyResult(applies=True, parses=True)
        if finding.tool == safeguards.TOOL:
            if not safeguards.restored(finding, before, after):
                return VerifyResult(applies=True, parses=True,
                                    error=f"The removed safeguard is still missing. Restore: {finding.code}")
        elif not check_finding_gone(patched, finding, baseline):
            return VerifyResult(applies=True, parses=True,
                                error=f"The scanner still reports {finding.rule_id} after your patch.")
        return VerifyResult(applies=True, parses=True, finding_gone=True)
    except subprocess.CalledProcessError as e:
        return VerifyResult(error=f"The patch could not be applied: {(e.stderr or b'').decode(errors='replace')}")
    finally:
        if patched:
            shutil.rmtree(patched, ignore_errors=True)