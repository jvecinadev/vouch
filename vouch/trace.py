"""Trace where the flagged value comes from, and say it in one short note for the model.

No LLM here: plain `ast`. Origins:
  external  = a function parameter (comes from the caller, nothing checks it)
  fixed     = a literal written in the code
  converted = passed through int()/float()/bool() (cannot carry SQL or shell text)
  unknown   = anything we cannot follow (calls, attributes, imports)
"""
import ast

# What "fixed" means depends on the kind of warning.
INJECTION = {"B608", "B602", "B604", "B605", "B606", "B607", "vouch-subprocess-shell-true"}
SECRET = {"B105", "B106", "B107"}

SAFE_CASTS = {"int", "float", "bool"}


def _names(node) -> list:
    return [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]


def _enclosing(tree, line):
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno <= line <= n.end_lineno:
            if best is None or n.lineno >= best.lineno:
                best = n
    return best


def _origin(name, scope, tree, line, depth=0):
    """Return (kind, detail) for `name` as seen at `line`."""
    if depth > 4:
        return "unknown", ""
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        params = {a.arg for a in scope.args.args + scope.args.kwonlyargs}
        if name in params:
            return "external", f"parameter of {scope.name}()"
    # latest assignment to `name` before `line` (function first, then module level)
    for body in ([scope] if scope is not tree else []) + [tree]:
        found = None
        for n in ast.walk(body):
            if isinstance(n, ast.Assign) and n.lineno < line and \
               any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
                if found is None or n.lineno > found.lineno:
                    found = n
        if found is None:
            continue
        v = found.value
        if isinstance(v, ast.Constant):
            return "fixed", "a literal in the code"
        if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id in SAFE_CASTS:
            return "converted", f"{v.func.id}() of another value"
        kinds = [_origin(n, scope, tree, found.lineno, depth + 1) for n in _names(v)]
        for k in ("external", "unknown"):
            hit = next((x for x in kinds if x[0] == k), None)
            if hit:
                return hit
        if kinds and all(k[0] in ("fixed", "converted") for k in kinds):
            return kinds[0]
        if not kinds:
            return "fixed", "built only from literals"
        return "unknown", ""
    return "unknown", ""


def trace_finding(finding, file_text: str) -> dict:
    """Return {"note": str, "lean": "real" | "false_alarm" | None}."""
    try:
        tree = ast.parse(file_text)
    except SyntaxError:
        return {"note": "", "lean": None}
    line = finding.line
    stmt = next((n for n in ast.walk(tree)
                 if isinstance(n, ast.stmt) and not isinstance(n, (ast.FunctionDef, ast.ClassDef))
                 and n.lineno <= line <= n.end_lineno), None)
    if stmt is None:
        return {"note": "", "lean": None}
    scope = _enclosing(tree, line) or tree

    if finding.rule_id in SECRET:
        return {"lean": "real", "note":
                "Trace: the secret is a fixed value written in the code. For a password that IS the "
                "problem (anyone with the repo can read it). Real issue. Fix: read it from an "
                "environment variable instead, e.g. os.environ[\"NAME\"], and add `import os`."}

    # only look at names the statement READS, not the one it assigns to
    targets = {t.id for t in getattr(stmt, "targets", []) if isinstance(t, ast.Name)}
    found = [(n, *_origin(n, scope, tree, line)) for n in dict.fromkeys(_names(stmt.value if hasattr(stmt, "value") and stmt.value else stmt))
             if n not in targets]
    if not found:
        return {"note": "", "lean": None}

    parts = [f"`{n}` is " + ("a fixed value written in the code" if k == "fixed" else d or "not traceable")
             for n, k, d in found]
    kinds = {k for _, k, _ in found}
    if finding.rule_id in INJECTION:
        if "external" in kinds:
            ext = next(n for n, k, _ in found if k == "external")
            return {"lean": "real", "note":
                    f"Trace: {'; '.join(parts)}. `{ext}` comes in from outside and nothing checks it. "
                    "Real issue."}
        if kinds <= {"fixed", "converted"}:
            return {"lean": "false_alarm", "note":
                    f"Trace: {'; '.join(parts)}. Every value in this string is fixed in the code or "
                    "converted to a number, so no outside input can reach it. Likely false alarm."}
    return {"lean": None, "note": f"Trace: {'; '.join(parts)}."}