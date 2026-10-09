
import re
import tempfile
from pathlib import Path

from .models import ChangedFile

HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_diff(diff_text: str) -> list:
    files: list = []
    path = None
    body: dict = {}
    added: set = set()
    old_left = new_left = 0
    new_no = 0

    def flush():
        nonlocal path, body, added
        if path and body:
            last = max(body)
            text = "\n".join(body.get(i, "") for i in range(1, last + 1)) + "\n"
            files.append(ChangedFile(path=path, new_text=text, added_lines=set(added)))
        path, body, added = None, {}, set()

    for raw in diff_text.splitlines():
        if old_left > 0 or new_left > 0:          # inside a hunk: use the header counts
            if raw.startswith("\\"):
                continue
            tag, content = raw[:1], raw[1:]
            if tag == "+":
                body[new_no] = content
                added.add(new_no)
                new_no += 1
                new_left -= 1
            elif tag == "-":
                old_left -= 1
            else:                                  # context line
                body[new_no] = content
                new_no += 1
                old_left -= 1
                new_left -= 1
            continue
        if raw.startswith("diff --git") or raw.startswith("--- "):
            flush()
        elif raw.startswith("+++ "):
            target = raw[4:].strip()
            if target == "/dev/null":
                path = None
            else:
                path = target[2:] if target.startswith("b/") else target
        else:
            m = HUNK.match(raw)
            if m:
                old_left = int(m.group(1)) if m.group(1) is not None else 1
                new_no = int(m.group(2))
                new_left = int(m.group(3)) if m.group(3) is not None else 1
    flush()
    return files


def write_workspace(files: list) -> Path:
    """Write changed files to a temp dir so scanners and `git apply` have real files."""
    root = Path(tempfile.mkdtemp(prefix="vouch-")).resolve()
    for f in files:
        target = (root / f.path).resolve()
        if root not in target.parents:            # never write outside the workspace
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f.new_text, newline="\n")
    return root