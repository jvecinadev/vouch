"""OWNER: Dev A. The single-page Gradio UI. Run: python app.py   (or VOUCH_MOCK=1 python app.py)"""
from pathlib import Path

import gradio as gr

import config
from ui import components as ui
from vouch.languages import EXTENSION, NAMES, supported_names
from vouch.llm import llm_status
from vouch.pipeline import scan
from vouch.scanners import scanner_status

CSS_FILE = Path(__file__).parent / "assets" / "style.css"
DEMO_DIFF = Path(__file__).parent / "examples" / "demo_sqli.diff"
DEMO_JS_DIFF = Path(__file__).parent / "examples" / "demo_js.diff"


def topbar_now() -> str:
    """Re-evaluated on every page load and on Re-check."""
    llm = llm_status()
    return ui.topbar(config.MODEL, llm["ok"], llm.get("reason", ""), scanner_status(), config.USE_MOCK)


def run_scan(diff_text, language="auto"):
    findings, status = [], "Starting"
    yield ui.render_results(findings, status, "running")
    state = "running"
    for event, payload in scan(diff_text):
    yield render_cards(findings), status, None
    for event, payload in scan(diff_text, language):
        if event == "status":
            status = payload
        elif event == "error":
            status, state = payload, "error"
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
        build_ui().launch(css=css)       
    except TypeError:
        build_ui(css).launch()         