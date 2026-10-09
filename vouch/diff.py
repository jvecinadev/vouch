
import re
import tempfile
from pathlib import Path

from .models import ChangedFile

HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def is_diff(text: str) -> bool:
    return any(line.startswith("+++ ") for line in text.splitlines())


def code_to_diff(code: str, path: str) -> str:
    """Wrap plain code as a git diff that adds it as a new file."""
    lines = code.splitlines()
    body = "".join(f"+{line}\n" for line in lines)
    return (
        f"diff --git a/{path} b/{path}\n"
        f"new file mode 100644\n"
        f"--- /dev/null\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n"
        f"{body}"
    )


def parse_diff(diff_text: str, source_root=None) -> list:
    """Parse a unified diff and optionally recover complete files from source_root."""
    files = []
    path = None
    body = {}
    added = set()
    old_left = new_left = 0
    new_no = 0
    is_new_file = False

    def flush():
        nonlocal path, body, added, is_new_file

        if path and body:
            last = max(body)
            text = "\n".join(
                body.get(i, "") for i in range(1, last + 1)
            ) + "\n"

            contiguous = set(body) == set(range(1, last + 1))
            complete = is_new_file and contiguous

            if source_root is not None:
                root = Path(source_root).resolve()
                candidate = (root / path).resolve()

                if root in candidate.parents and candidate.is_file():
                    text = candidate.read_text(encoding="utf-8")
                    complete = True

            files.append(
                ChangedFile(
                    path=path,
                    new_text=text,
                    added_lines=set(added),
                    complete=complete,
                )
            )

        path, body, added, is_new_file = None, {}, set(), False

    for raw in diff_text.splitlines():
        if old_left > 0 or new_left > 0:
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

            else:
                body[new_no] = content
                new_no += 1
                old_left -= 1
                new_left -= 1

            continue

        if raw.startswith("diff --git"):
            flush()

        elif raw.startswith("--- "):
            flush()
            is_new_file = raw[4:].strip() == "/dev/null"

        elif raw.startswith("+++ "):
            target = raw[4:].strip()

            if target == "/dev/null":
                path = None
            else:
                path = target[2:] if target.startswith("b/") else target

        else:
            match = HUNK.match(raw)

            if match:
                old_left = (
                    int(match.group(1))
                    if match.group(1) is not None
                    else 1
                )
                new_no = int(match.group(2))
                new_left = (
                    int(match.group(3))
                    if match.group(3) is not None
                    else 1
                )

    flush()
    return files


def write_workspace(files: list) -> Path:
    """Write changed files to a temporary workspace."""
    root = Path(tempfile.mkdtemp(prefix="vouch-")).resolve()

    for file in files:
        target = (root / file.path).resolve()

        if root not in target.parents:
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            file.new_text,
            encoding="utf-8",
            newline="\n",
        )

    return root