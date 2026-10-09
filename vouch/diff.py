
import re
import tempfile
from pathlib import Path

from .models import ChangedFile

HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def is_diff(text: str) -> bool:
    return any(line.startswith("+++ ") for line in text.splitlines())


def code_to_diff(code: str, path: str) -> str:
    """Wrap plain code as a git diff that adds it as a new file, so the normal pipeline can scan it."""
    lines = code.splitlines()
    body = "".join(f"+{line}\n" for line in lines)
    return (f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n{body}")


def parse_diff(diff_text: str) -> list:
    files: list = []
    path = None
    body: dict = {}
    added: set = set()
    hunks: list = []
    old_left = new_left = 0
    new_no = 0

    def flush():
        nonlocal path, body, added, hunks
        if path and body:
            last = max(body)
            text = "\n".join(body.get(i, "") for i in range(1, last + 1)) + "\n"
            files.append(ChangedFile(path=path, new_text=text, added_lines=set(added), hunks=hunks))
        path, body, added, hunks = None, {}, set(), []

    for raw in diff_text.splitlines():
        if old_left > 0 or new_left > 0:          # inside a hunk: use the header counts
            if raw.startswith("\\"):
                continue
            tag, content = raw[:1], raw[1:]
            if hunks:
                hunks[-1].append((tag if tag in "+-" and tag else " ", new_no, content))
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
                hunks.append([])
    flush()
    return files


def _open_php(text: str) -> str:
    """A PHP diff usually starts below the `<?php` line, and without it PHP tools read the code as HTML.
    Put `<?php` on line 1 (line numbers stay the same)."""
    lines = text.split("\n")
    lines[0] = "<?php " + lines[0] if lines[0].strip() else "<?php"
    return "\n".join(lines)


def write_workspace(files: list) -> Path:
    """Write changed files to a temp dir so scanners and `git apply` have real files."""
    root = Path(tempfile.mkdtemp(prefix="vouch-")).resolve()
    for f in files:
        target = (root / f.path).resolve()
        if root not in target.parents:            # never write outside the workspace
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        text = f.new_text
        if target.suffix.lower() == ".php" and "<?" not in text:
            text = _open_php(text)
        target.write_text(text, encoding="utf-8", newline="\n")
    return root

def change_blocks(hunk: list) -> list:
    """Split a hunk into change blocks: (removed texts, added [(line, text)], line where the removal sits)."""
    blocks, removed, added = [], [], []
    anchor = None
    for tag, no, text in hunk + [(" ", None, "")]:
        if tag == "-":
            if added:                                  # a new block starts after a run of additions
                blocks.append((removed, added, anchor))
                removed, added, anchor = [], [], None
            removed.append(text)
            anchor = no if anchor is None else anchor
        elif tag == "+":
            added.append((no, text))
            anchor = no if anchor is None else anchor
        elif removed or added:
            blocks.append((removed, added, anchor))
            removed, added, anchor = [], [], None
    return blocks
