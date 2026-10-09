"""OWNER: Dev A. The single-page Gradio UI. Run: python app.py   (or VOUCH_MOCK=1 python app.py)"""
import html
from pathlib import Path

import gradio as gr

import config
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
CSS_FILE = Path(__file__).parent / "assets" / "style.css"   # designer's CSS goes here
DEMO_DIFF = Path(__file__).parent / "examples" / "demo_sqli.diff"


def pill(text, color):
    return (f'<span style="background:{color};color:#fff;padding:2px 10px;border-radius:12px;'
            f'font-size:12px;font-weight:600">{html.escape(text)}</span>')


def render_card(f) -> str:
    label, color = BADGES[f.badge]
    retry = f" (fixed on attempt {f.attempts})" if f.badge == Badge.VERIFIED and f.attempts > 1 else ""
    verdict = {"true_positive": "Likely real issue",
               "likely_false_positive": "Likely false positive"}.get(f.verdict, "")
    patch = (f'<pre style="overflow-x:auto">{html.escape(f.patch)}</pre>'
             f'<button onclick="navigator.clipboard.writeText(this.dataset.patch)" '
             f'data-patch="{html.escape(f.patch, quote=True)}">Copy patch</button>') if f.patch else ""
    return (f'<div class="vouch-card" style="border:1px solid #444;border-radius:8px;padding:14px;margin-bottom:12px">'
            f'{pill(f.severity.upper(), SEVERITY.get(f.severity, "#6b7280"))} '
            f'<b>{html.escape(f.title.title())}</b> {html.escape(f.cwe or "")}<br>'
            f'<small>{html.escape(f.file)}, line {f.line}</small> &nbsp; {html.escape(verdict)}'
            f'<p>{html.escape(f.explanation or f.message)}</p>{patch}'
            f'<p>{pill(label, color)}{html.escape(retry)}</p></div>')


def render_cards(findings) -> str:
    return "".join(render_card(f) for f in findings) or "<i>No findings yet.</i>"


def status_banner() -> str:
    llm, tools = llm_status(), scanner_status()
    lines = []
    if config.USE_MOCK:
        lines.append("MOCK MODE: showing fake data")
    lines.append(f"Model: {config.MODEL} ({'running locally' if llm['ok'] else llm['reason']})")
    lines.append("Scanners: " + ", ".join(f"{k} {'ok' if v else 'missing'}" for k, v in tools.items()))
    return " | ".join(lines)


def run_scan(diff_text):
    findings, status = [], "Starting"
    yield render_cards(findings), status, None
    for event, payload in scan(diff_text):
        if event == "status":
            status = payload
        elif event == "error":
            status = f"Error: {payload}"
        elif event == "finding":
            findings.append(payload)
        yield render_cards(findings), status, None
    yield render_cards(findings), status, (write_sarif(findings) if findings else None)


def build_ui():
    css = CSS_FILE.read_text() if CSS_FILE.exists() else ""
    with gr.Blocks(title="Vouch", css=css) as demo:
        gr.Markdown("# Vouch\nLocal security fixes that are verified before you see them.")
        gr.Markdown(status_banner())
        with gr.Row():
            with gr.Column():
                diff_box = gr.Textbox(label="Paste a git diff", lines=18)
                with gr.Row():
                    scan_btn = gr.Button("Scan", variant="primary")
                    demo_btn = gr.Button("Load demo diff")
            with gr.Column():
                status = gr.Markdown("Ready.")
                cards = gr.HTML(render_cards([]))
                sarif = gr.File(label="Download SARIF")
        demo_btn.click(lambda: DEMO_DIFF.read_text(), outputs=diff_box)
        scan_btn.click(run_scan, inputs=diff_box, outputs=[cards, status, sarif])
    return demo


if __name__ == "__main__":
    build_ui().launch()
