"""OWNER: Dev A. The single-page Gradio UI. Run: python app.py   (or VOUCH_MOCK=1 python app.py)"""
import base64
import html
from pathlib import Path

import gradio as gr

import config
from vouch.languages import EXTENSION, NAMES, supported_names
from vouch.llm import llm_status
from vouch.models import Badge
from vouch.pipeline import scan
from vouch.sarif import write_sarif
from vouch.scanners import scanner_status

BADGES = {
    Badge.VERIFIED: ("Fix verified", "#16a34a"),
    Badge.UNVERIFIED: ("Applies but unverified", "#d97706"),
    Badge.NEEDS_HUMAN: ("Needs human fix", "#dc2626"),
    Badge.SKIPPED: ("No fix attempted", "#6b7280"),
}
SEVERITY = {"critical": "#7f1d1d", "high": "#dc2626", "medium": "#d97706", "low": "#2563eb"}
CSS_FILE = Path(__file__).parent / "assets" / "style.css"
DEMO_DIFF = Path(__file__).parent / "examples" / "demo_sqli.diff"
DEMO_JS_DIFF = Path(__file__).parent / "examples" / "demo_js.diff"


def pill(text, color):
    return (f'<span style="background:{color};color:#fff;padding:2px 10px;border-radius:12px;'
            f'font-size:12px;font-weight:600">{html.escape(text)}</span>')


def patch_buttons(f, n) -> str:
    """Copy button + .patch download link (a data: URL, so no server route is needed)."""
    b64 = base64.b64encode(f.patch.encode()).decode()
    name = f"vouch-fix-{n}.patch"
    return (f'<pre style="overflow-x:auto">{html.escape(f.patch)}</pre>'
            f'<button onclick="navigator.clipboard.writeText(this.dataset.patch)" '
            f'data-patch="{html.escape(f.patch, quote=True)}">Copy patch</button> '
            f'<a href="data:text/plain;base64,{b64}" download="{name}">'
            f'<button type="button">Download .patch</button></a>')


def retry_log(f) -> str:
    """Show every verification attempt, so a failed-then-fixed patch is visible on the card."""
    if not f.verify_log:
        return ""
    items = "".join(f"<li>{html.escape(line)}</li>" for line in f.verify_log)
    return f'<details open><summary><small>Verification log</small></summary><ul>{items}</ul></details>'


def render_card(f, n=1) -> str:
    label, color = BADGES[f.badge]
    retry = f" (fixed on attempt {f.attempts})" if f.badge == Badge.VERIFIED and f.attempts > 1 else ""
    verdict = {"true_positive": "Likely real issue",
               "likely_false_positive": "Likely false positive"}.get(f.verdict, "")
    patch = patch_buttons(f, n) if f.patch else ""
    note = ""
    if f.badge == Badge.SKIPPED and not f.verdict:
        note = "<p><small><i>Scanner-only result: the local model was unavailable, so no explanation or fix was generated.</i></small></p>"
    return (f'<div class="vouch-card" style="border:1px solid #444;border-radius:8px;padding:14px;margin-bottom:12px">'
            f'{pill(f.severity.upper(), SEVERITY.get(f.severity, "#6b7280"))} '
            f'<b>{html.escape(f.title.title())}</b> {html.escape(f.cwe or "")}<br>'
            f'<small>{html.escape(f.file)}, line {f.line}</small> &nbsp; {html.escape(verdict)}'
            f'<p>{html.escape(f.explanation or f.message)}</p>{note}{patch}'
            f'<p>{pill(label, color)}{html.escape(retry)}</p>{retry_log(f)}</div>')


def render_cards(findings) -> str:
    return "".join(render_card(f, i) for i, f in enumerate(findings, 1)) or "<i>No findings yet.</i>"


def status_banner() -> str:
    llm, tools = llm_status(), scanner_status()
    lines = []
    if config.USE_MOCK:
        lines.append("MOCK MODE: showing fake data")
    if llm["ok"]:
        lines.append(f"Model: {config.MODEL} (running locally)")
    else:
        lines.append(f"**Scanner-only mode.** Model {config.MODEL} unavailable: {llm['reason']}")
    lines.append("Scanners: " + ", ".join(f"{k} {'ok' if v else 'missing'}" for k, v in tools.items()))
    text = " | ".join(lines)
    if not llm["ok"] and not config.USE_MOCK:
        text += ("\n\n*Fix:* start Ollama (`ollama serve`) and run `ollama pull "
                 f"{config.MODEL}`, then click **Re-check**. Findings still work without the model.")
    return text


def run_scan(diff_text, language="auto"):
    findings, status = [], "Starting"
    yield render_cards(findings), status, None
    for event, payload in scan(diff_text, language):
        if event == "status":
            status = payload
        elif event == "error":
            status = f"Error: {payload}"
        elif event == "finding":
            findings.append(payload)
        yield render_cards(findings), status, None
    yield render_cards(findings), status, (write_sarif(findings) if findings else None)


def build_ui():
    with gr.Blocks(title="Vouch") as demo:
        gr.Markdown("# Vouch\nLocal security fixes that are verified before you see them.\n\n"
                    f"Reads: {supported_names()}")
        banner = gr.Markdown(status_banner)          # a function: re-evaluated on every page load
        recheck = gr.Button("Re-check Ollama", size="sm")
        with gr.Row():
            with gr.Column():
                diff_box = gr.Textbox(label="Paste a git diff or plain code", lines=18)
                language = gr.Dropdown(
                    [("Auto-detect", "auto")] + [(NAMES[k], k) for k in EXTENSION if k != "tsx"],
                    value="auto", label="Language (only used for plain code; a diff uses its file names)")
                with gr.Row():
                    scan_btn = gr.Button("Scan", variant="primary")
                    demo_btn = gr.Button("Load Python demo")
                    demo_js_btn = gr.Button("Load JavaScript demo")
            with gr.Column():
                status = gr.Markdown("Ready.")
                cards = gr.HTML(render_cards([]))
                sarif = gr.File(label="Download SARIF")
        recheck.click(status_banner, outputs=banner)
        demo_btn.click(lambda: DEMO_DIFF.read_text(encoding="utf-8"), outputs=diff_box)
        demo_js_btn.click(lambda: DEMO_JS_DIFF.read_text(encoding="utf-8"), outputs=diff_box)
        scan_btn.click(run_scan, inputs=[diff_box, language], outputs=[cards, status, sarif])
    return demo


if __name__ == "__main__":
    css = CSS_FILE.read_text(encoding="utf-8") if CSS_FILE.exists() else ""
    try:
        build_ui().launch(css=css)       # Gradio 6+
    except TypeError:
        build_ui().launch()              # older Gradio: css would have to go in gr.Blocks(css=...)