"""UI components for Vouch. Every function returns an HTML string.

No Gradio imports here, so these are easy to test and to preview in a plain browser.
All dynamic text goes through html.escape(). Styles live in assets/style.css (scoped to .vouch-app).
"""
import base64
import html
import json
import re

from vouch.models import Badge
from vouch.sarif import export_sarif

esc = html.escape

SEVERITIES = ("critical", "high", "medium", "low")
STEPS = ("Scan", "Triage", "Fix", "Verify")

# badge -> (css modifier, label, icon)
VERIFY = {
    Badge.VERIFIED: ("success", "Fix verified", "✓"),
    Badge.UNVERIFIED: ("warn", "Applies, unverified", "!"),
    Badge.NEEDS_HUMAN: ("danger", "Needs human fix", "!"),
    Badge.SKIPPED: ("neutral", "No fix attempted", "–"),
}
VERDICTS = {
    "true_positive": ("Likely real issue", "real"),
    "likely_false_positive": ("Likely false positive", "fp"),
}

LOCK_SVG = ('<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 10V8a5 5 0 0 1 10 0v2"/>'
            '<rect x="5" y="10" width="14" height="10" rx="1"/></svg>')
DOWNLOAD_SVG = ('<svg viewBox="0 0 24 24" aria-hidden="true">'
                '<path d="M12 3v12m0 0 4-4m-4 4-4-4M5 19h14"/></svg>')
BRAND_SVG = ('<svg viewBox="0 0 24 24"><path d="M12 2.4 20 5.7v5.5c0 5.1-3.2 8.9-8 10.4-4.8-1.5-8-5.3-8-10.4V5.7L12 2.4Z"/>'
             '<path class="brand-mark-check" d="m8.2 12.1 2.2 2.2 5.3-5.2"/></svg>')


# ---------------------------------------------------------------- helpers

def inline_code(text: str) -> str:
    """Escape text, then turn `backticked` bits into <code>."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", esc(text or ""))


def data_url(text: str, mime: str = "text/plain") -> str:
    return f"data:{mime};base64," + base64.b64encode(text.encode()).decode()


def _severity(f) -> str:
    return f.severity if f.severity in SEVERITIES else "low"


# ---------------------------------------------------------------- top bar

def topbar(model: str, llm_ok: bool, reason: str = "", scanners: dict = None, mock: bool = False) -> str:
    """Brand + local-model status. Shows a fix hint when the model is unavailable."""
    scanners = scanners or {}
    tools = ", ".join(f"{k} {'ok' if v else 'missing'}" for k, v in scanners.items())
    if mock:
        sub = "Mock data"
    else:
        sub = "Running locally" if llm_ok else "Scanner-only mode"
    state = "ON" if (llm_ok or mock) else "OFF"
    off = "" if state == "ON" else " is-off"
    out = (
        '<header class="topbar v-panel">'
        '<div class="brand-block"><div class="brand-mark" aria-hidden="true">' + BRAND_SVG + '</div>'
        '<div><div class="brand-name">Vouch</div>'
        '<p>Local security fixes, checked before you see them.</p></div></div>'
        f'<div class="runtime-status" title="{esc(tools)}" aria-label="Local model status">'
        f'<span class="runtime-details"><strong>{esc(model)}</strong><small>{esc(sub)}</small></span>'
        f'<span class="status-switch{off}">{state}</span></div></header>'
    )
    if not llm_ok and not mock:
        out += (
            '<div class="notice"><strong>Scanner-only mode.</strong> '
            f'Model {esc(model)} unavailable: {esc(reason)}. Findings still work without the model. '
            f'To enable fixes, run <code>ollama serve</code> and <code>ollama pull {esc(model)}</code>, '
            'then click <b>Re-check</b>.</div>'
        )
    return out


def input_header(language: str = "Python") -> str:
    return (
        '<div class="section-heading"><div><span class="eyebrow">Input</span>'
        '<h1>Review your changes</h1></div>'
        f'<span class="language-pill">{esc(language)}</span></div>'
        '<p class="section-copy">Paste a unified git diff. Only changed lines are checked '
        'by the scanner rules.</p>'
    )


def privacy_note() -> str:
    return f'<div class="privacy-note">{LOCK_SVG}<span>Your code stays on this machine.</span></div>'


def footer() -> str:
    return ('<footer class="app-footer"><span>Vouch / localhost</span>'
            '<span>Scanner results still require human review.</span></footer>')


# ---------------------------------------------------------------- progress

def parse_status(status: str):
    """Map the pipeline's status text to (active_step, i, n). active_step: 0=Scan .. 3=Verify."""
    s = (status or "").lower()
    m = re.search(r"(\d+) of (\d+)", s)
    i, n = (int(m.group(1)), int(m.group(2))) if m else (None, None)
    if "triag" in s:
        step = 1
    elif "fix" in s or "verif" in s:
        step = 3
    else:
        step = 0
    return step, i, n


def progress_panel(status: str = "Ready", state: str = "idle") -> str:
    """state: idle | running | done | error"""
    step, i, n = parse_status(status)
    if state == "done":
        pct, label = 100, "Scan complete"
    elif state == "error":
        pct, label = 0, "Scan stopped"
    elif state == "running":
        pct, label = min(95, step * 25 + 12), "Scan progress"
    else:
        pct, label = 0, "Scan progress"
    count = f'<span class="progress-count">{i:02d} / {n:02d}</span>' if (i and n and state == "running") else ""
    steps = ""
    for idx, name in enumerate(STEPS):
        if state == "done":
            cls = "complete"
        elif state == "running":
            cls = "complete" if idx < step else ("active" if idx == step else "")
        else:
            cls = ""
        steps += f'<li class="step {cls}"><span class="step-icon">{idx + 1:02d}</span><span>{name}</span></li>'
    return (
        '<section class="progress-panel v-panel"><div class="progress-topline"><div>'
        f'<span class="eyebrow">{label}</span><h2>{esc(status)}</h2></div>{count}</div>'
        f'<div class="progress-track" aria-label="{pct} percent complete"><span style="width:{pct}%"></span></div>'
        f'<ol class="progress-steps">{steps}</ol></section>'
    )


def metrics(findings: list) -> str:
    total = len(findings)
    verified = sum(1 for f in findings if f.badge == Badge.VERIFIED)
    counts = {s: sum(1 for f in findings if _severity(f) == s) for s in SEVERITIES}
    breakdown = " / ".join(f"{c} {s}" for s, c in counts.items() if c) or "None yet"
    return (
        '<article class="metric-card metric-dark v-panel"><span class="metric-label">Findings</span>'
        f'<strong>{total:02d}</strong><small>{esc(breakdown)}</small></article>'
        '<article class="metric-card v-panel"><span class="metric-label">Verified</span>'
        f'<strong>{verified:02d}</strong><small>{"Patch passed checks" if verified else "No verified fixes yet"}</small></article>'
        '<article class="metric-card metric-orange v-panel"><span class="metric-label">Privacy</span>'
        '<strong>100%</strong><small>Local processing</small></article>'
    )


# ---------------------------------------------------------------- finding card

def diff_lines(text: str) -> str:
    """Colour a unified diff, one block-level <span> per line."""
    out = []
    for line in text.splitlines():
        if line.startswith(("+++", "---", "diff ", "index ")):
            cls = "diff-meta"
        elif line.startswith("@@"):
            cls = "diff-hunk"
        elif line.startswith("+"):
            cls = "diff-add"
        elif line.startswith("-"):
            cls = "diff-remove"
        else:
            cls = "patch-context"
        out.append(f'<span class="{cls}">{esc(line) or " "}</span>')
    return "".join(out)


def _log_rows(log: list) -> str:
    rows = ""
    for line in log:
        m = re.match(r"attempt (\d+):\s*(.*)", line, re.I)
        if m:
            n, msg = m.groups()
            if msg.strip().lower() == "verified":
                rows += f'<li><span>Attempt {n}</span><strong class="pass">Pass</strong></li>'
            else:
                rows += f'<li><span>Attempt {n}: {esc(msg)}</span><strong class="fail">Fail</strong></li>'
        else:
            rows += f'<li><span>{esc(line)}</span><strong class="note">Note</strong></li>'
    return f'<ul class="verification-list">{rows}</ul>' if rows else ""


def _hero_text(f) -> str:
    if f.badge == Badge.VERIFIED:
        return "Passed on first attempt" if f.attempts <= 1 else f"Passed after attempt {f.attempts}"
    if f.badge == Badge.UNVERIFIED:
        return "Patch applies, a later check failed"
    if f.badge == Badge.NEEDS_HUMAN:
        return f"No valid patch after {f.attempts} attempt{'s' if f.attempts != 1 else ''}" if f.attempts else "No valid patch"
    return "Likely false positive" if f.verdict == "likely_false_positive" else "Model unavailable or not needed"


def _trace_tile(f) -> str:
    nodes = ""
    if f.trace:
        nodes += (f'<div class="trace-node"><span class="trace-type">Trace</span>'
                  f'<p>{inline_code(f.trace)}</p></div><span class="trace-arrow" aria-hidden="true">→</span>')
    code = (f.code or "").strip().splitlines()[0] if (f.code or "").strip() else f"{f.file}:{f.line}"
    nodes += (f'<div class="trace-node trace-danger"><span class="trace-type">Flagged code</span>'
              f'<strong>{esc(f.file)}:{f.line}</strong><code>{esc(code)}</code></div>')
    cls = "context-trace" + ("" if f.trace else " context-trace-1") + (" context-trace-2" if f.trace else "")
    return (
        '<section class="trace-tile v-panel bento-tile"><div class="tile-heading">'
        '<span class="tile-index tile-index-orange">02</span><div>'
        '<span class="content-label">Context trace</span><small>Where the flagged value comes from</small></div></div>'
        f'<div class="{cls}">{nodes}</div></section>'
    )


def _patch_tile(f) -> str:
    if f.patch:
        lines = f.patch.splitlines()
        adds = sum(1 for x in lines if x.startswith("+") and not x.startswith("+++"))
        dels = sum(1 for x in lines if x.startswith("-") and not x.startswith("---"))
        body = (f'<div class="patch-code"><div class="patch-toolbar"><span>{esc(f.file)}</span>'
                f'<span>Unified diff</span></div><pre><code>{diff_lines(f.patch)}</code></pre></div>')
        label = f"+{adds} / -{dels}"
    else:
        body = '<p class="tile-empty">No patch was generated for this finding.</p>'
        label = "No patch"
    return (
        '<section class="patch-tile v-panel bento-tile"><div class="tile-heading patch-heading"><div>'
        '<span class="tile-index">03</span><span class="content-label">Suggested patch</span></div>'
        f'<span class="patch-label">{esc(label)}</span></div>{body}</section>'
    )


def finding_board(f, n: int = 1) -> str:
    sev = _severity(f)
    vmod, vlabel, vicon = VERIFY[f.badge]
    verdict, vclass = VERDICTS.get(f.verdict, ("Not triaged", "none"))
    cwe = f.cwe or "No CWE"
    if f.verdict:
        why = inline_code(f.explanation or f.message)
    else:
        why = (inline_code(f.message) + '<br><i>Scanner-only result: the local model was unavailable, '
               'so no explanation or fix was generated.</i>')

    # explanation tile (4 + 5 + 6 below share the 12-column grid defined in the CSS)
    explanation = (
        '<section class="explanation-tile v-panel bento-tile"><div class="tile-heading">'
        '<span class="tile-index">01</span><span class="content-label">Why it was flagged</span></div>'
        f'<p>{why}</p><div class="confidence-row"><span>Scanner rule · {esc(f.tool)}</span>'
        f'<strong>{esc(f.rule_id)}</strong></div></section>'
    )
    verification = (
        '<aside class="verification-tile v-panel bento-tile"><div class="tile-heading">'
        '<span class="tile-index tile-index-orange">04</span><span class="content-label">Verification</span></div>'
        f'<div class="verification-hero hero-{vmod}"><span>{vicon}</span><div><strong>{esc(vlabel)}</strong>'
        f'<small>{esc(_hero_text(f))}</small></div></div>{_log_rows(f.verify_log)}'
        + ('<p class="retry-note">Earlier attempts failed and were corrected by the retry loop. See the log above.</p>'
           if f.badge == Badge.VERIFIED and f.attempts > 1 else
           '<p class="retry-note">Review this one manually before merging.</p>'
           if f.badge in (Badge.NEEDS_HUMAN, Badge.UNVERIFIED) else "")
        + '</aside>'
    )

    # footer actions
    if f.patch:
        copy_btn = ('<button class="v-button v-button-primary" type="button" '
                    f'data-patch="{esc(f.patch, quote=True)}" '
                    "onclick=\"navigator.clipboard.writeText(this.dataset.patch);this.textContent='Copied'\">"
                    'Copy patch</button>')
        dl_btn = (f'<a class="v-button v-button-secondary" href="{data_url(f.patch)}" '
                  f'download="vouch-fix-{n}.patch">Download .patch</a>')
        head, sub = (("Ready to review", "The verified patch can now be copied or downloaded.")
                     if f.badge == Badge.VERIFIED else
                     ("Review before applying", "This patch is not fully verified. Check it by hand."))
    else:
        copy_btn = dl_btn = ""
        head, sub = "No patch available", "There is nothing to copy or download for this finding."
    dismiss = ('<button class="v-button v-button-ghost" type="button" '
               "onclick=\"this.closest('.finding-board').style.display='none'\">Dismiss</button>")

    return (
        f'<article class="finding-board v-panel" aria-label="{esc(f.title)} finding">'
        '<header class="finding-summary"><div class="finding-title-block">'
        f'<span class="severity severity-{sev}">{sev}</span>'
        f'<div><h3>{esc(f.title.title())}</h3><p>{esc(cwe)} · {esc(f.rule_id)}</p></div></div>'
        f'<span class="verification verification-{vmod}"><span class="verification-check">{vicon}</span>{esc(vlabel)}</span>'
        f'<div class="summary-location"><span>{esc(f.file)}</span><strong>Line {f.line}</strong></div>'
        f'<div class="summary-triage"><span class="verdict-dot verdict-{vclass}"></span><span>{esc(verdict)}</span></div>'
        '</header>'
        f'<div class="finding-grid">{explanation}{_trace_tile(f)}{_patch_tile(f)}{verification}</div>'
        '<footer class="finding-actions"><div><span class="content-label">'
        f'{esc(head)}</span><p>{esc(sub)}</p></div>'
        f'<div class="action-buttons">{copy_btn}{dl_btn}{dismiss}</div></footer></article>'
    )


def working_card(status: str) -> str:
    """Placeholder shown at the bottom of the list while the pipeline is still running."""
    return (
        '<article class="queued-finding v-panel"><div class="queued-copy">'
        '<span class="severity severity-low">Next</span>'
        f'<div><h3>Analysing your diff</h3><p>{esc(status)}</p></div></div>'
        '<div class="queue-progress" aria-hidden="true"><span></span><span></span><span></span></div>'
        '<span class="verification verification-pending"><span class="mini-spinner"></span>Working</span></article>'
    )


# ---------------------------------------------------------------- results column

def export_button(findings: list) -> str:
    if not findings:
        return f'<button class="v-button v-button-secondary export-button" type="button" disabled>{DOWNLOAD_SVG}Download SARIF</button>'
    sarif = json.dumps(export_sarif(findings), indent=2)
    return (f'<a class="v-button v-button-secondary export-button" href="{data_url(sarif, "application/json")}" '
            f'download="vouch.sarif">{DOWNLOAD_SVG}Download SARIF</a>')


def render_results(findings: list, status: str = "Ready", state: str = "idle") -> str:
    """Whole right-hand column. state: idle | running | done | error"""
    if findings:
        cards = "".join(finding_board(f, i) for i, f in enumerate(findings, 1))
    elif state == "idle":
        cards = '<div class="empty-state v-panel">Paste a git diff and press <b>Scan</b>, or load the demo diff.</div>'
    elif state == "done":
        cards = '<div class="empty-state v-panel">No findings. This is not a guarantee of safety.</div>'
    elif state == "error":
        cards = f'<div class="empty-state v-panel is-error">{esc(status)}</div>'
    else:
        cards = ""
    if state == "running":
        cards += working_card(status)
    return (
        f'<section class="results-column" aria-busy="{str(state == "running").lower()}">'
        f'<div class="scan-bento">{progress_panel(status, state)}{metrics(findings)}</div>'
        '<section class="findings-section"><div class="findings-heading"><div>'
        '<span class="eyebrow">Results</span>'
        f'<h2>Findings <span class="finding-total">{len(findings)}</span></h2></div>'
        f'{export_button(findings)}</div>{cards}</section></section>'
    )