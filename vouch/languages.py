"""Which languages Vouch reads, and a syntax check for each one.

Python uses the built-in `ast`. The others use tree-sitter grammars: one small pip package
per language, so no Node, Java, Go or PHP install is needed to check a patch.
"""
import ast
import importlib
import re
from pathlib import Path
from typing import Optional

LANGUAGES = {
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
    ".java": "java",
    ".go": "go",
    ".php": "php",
}
NAMES = {"python": "Python", "javascript": "JavaScript", "typescript": "TypeScript",
         "tsx": "TypeScript", "java": "Java", "go": "Go", "php": "PHP"}
EXTENSION = {"python": ".py", "javascript": ".js", "typescript": ".ts", "tsx": ".tsx",
             "java": ".java", "go": ".go", "php": ".php"}
# Strong hints, checked in this order; first match wins.
HINTS = [
    ("php", r"<\?php"),
    ("go", r"^\s*package\s+\w+\s*$|^\s*func\s+(\(\w+ \*?\w+\)\s*)?\w+\(|:="),
    ("java", r"^\s*import\s+java\.|\b(public|private|protected)\s+(static\s+)?(final\s+)?(class|void|[\w<>\[\]]+\s+\w+\s*\()|System\.out\."),
    ("typescript", r"^\s*(export\s+)?(interface|type)\s+\w+|:\s*(string|number|boolean|any|void)\b"),
    ("javascript", r"\brequire\(|^\s*(const|let|var)\s|\bfunction\b|=>|console\.|module\.exports"),
    ("python", r"^\s*(def|class)\s+\w+.*:\s*$|^\s*(import\s+\w+|from\s+[\w.]+\s+import)\b|\bprint\("),
]
# language -> (pip module, function that returns the grammar)
GRAMMARS = {
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "java": ("tree_sitter_java", "language"),
    "go": ("tree_sitter_go", "language"),
    "php": ("tree_sitter_php", "language_php"),
}
_parsers: dict = {}


def language_of(path) -> Optional[str]:
    return LANGUAGES.get(Path(str(path)).suffix.lower())


def is_supported(path) -> bool:
    return language_of(path) is not None


def supported_names() -> str:
    return ", ".join(dict.fromkeys(NAMES.values()))


def guess_language(code: str) -> Optional[str]:
    """Best guess for plain pasted code: strong hints first, then the first parser that accepts it."""
    for lang, pattern in HINTS:
        if re.search(pattern, code, re.MULTILINE):
            return lang
    # PHP is left out: its parser accepts any text as inline HTML. Real PHP has <?php (a hint above).
    for lang in ("python", "javascript", "typescript", "java", "go"):
        if check_syntax_text(code, lang)[0]:
            return lang
    return None


def _parser(lang: str):
    if lang not in _parsers:
        import tree_sitter
        module, func = GRAMMARS[lang]
        grammar = getattr(importlib.import_module(module), func)()
        _parsers[lang] = tree_sitter.Parser(tree_sitter.Language(grammar))
    return _parsers[lang]


def _first_error(node):
    if node.type == "ERROR" or node.is_missing:
        return node
    for child in node.children:
        if child.has_error or child.is_missing:
            hit = _first_error(child)
            if hit is not None:
                return hit
    return None


def check_syntax_text(text: str, lang: Optional[str]) -> tuple:
    """Return (ok, error message). Unknown language or missing parser counts as NOT ok."""
    if lang == "python":
        try:
            ast.parse(text)
            return True, ""
        except SyntaxError as e:
            return False, f"{e.msg} (line {e.lineno})"
    if lang not in GRAMMARS:
        return False, "no syntax checker for this file type"
    try:
        tree = _parser(lang).parse(text.encode("utf-8"))
    except ImportError as e:
        return False, f"{NAMES[lang]} parser not installed ({e.name}). Run: pip install -r requirements.txt"
    if not tree.root_node.has_error:
        return True, ""
    bad = _first_error(tree.root_node) or tree.root_node
    what = f"missing {bad.type}" if bad.is_missing else "unexpected code"
    return False, f"{what} (line {bad.start_point[0] + 1})"
