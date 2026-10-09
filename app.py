"""OWNER: Dev A. The single-page Gradio UI. Run: python app.py   (or VOUCH_MOCK=1 python app.py)"""
from pathlib import Path

import gradio as gr

import config
from ui import components as ui
from vouch.llm import llm_status
from vouch.pipeline import scan
from vouch.scanners import scanner_status

CSS_FILE = Path(__file__).parent / "assets" / "style.css"
DEMO_DIFF = Path(__file__).parent / "examples" / "demo_sqli.diff"


def topbar_now() -> str:
    """Re-evaluated on every page load and on Re-check."""
    llm = llm_status()
    return ui.topbar(config.MODEL, llm["ok"], llm.get("reason", ""), scanner_status(), config.USE_MOCK)


def run_scan(diff_text):
    findings, status = [], "Starting"
    yield ui.render_results(findings, status, "running")
    state = "running"
    for event, payload in scan(diff_text):
        if event == "status":
            status = payload
        elif event == "error":
            status, state = payload, "error"
        elif event == "finding":
            findings.append(payload)
        yield ui.render_results(findings, status, state)
    yield ui.render_results(findings, status, "error" if state == "error" else "done")


def build_ui(css: str = ""):
    with gr.Blocks(title="Vouch", css=css) if css else gr.Blocks(title="Vouch") as demo:
        with gr.Column(elem_classes=["vouch-app"]):
            topbar = gr.HTML(topbar_now)                       # a function: re-evaluated on page load
            with gr.Row(elem_classes=["workspace"]):
                with gr.Column(elem_classes=["input-column", "v-panel"]):
                    gr.HTML(ui.input_header())
                    diff_box = gr.Textbox(show_label=False, container=False, lines=18,
                                          placeholder="Paste a git diff here", elem_classes=["code-input"])
                    with gr.Row(elem_classes=["input-actions"]):
                        scan_btn = gr.Button("Scan", elem_classes=["v-button", "v-button-primary"])
                        demo_btn = gr.Button("Load demo diff", elem_classes=["v-button", "v-button-secondary"])
                    gr.HTML(ui.privacy_note())
                    recheck = gr.Button("Re-check Ollama", size="sm", elem_classes=["v-button", "v-button-ghost"])
                results = gr.HTML(ui.render_results([]))
            gr.HTML(ui.footer())
        recheck.click(topbar_now, outputs=topbar)
        demo_btn.click(lambda: DEMO_DIFF.read_text(), outputs=diff_box)
        scan_btn.click(run_scan, inputs=diff_box, outputs=results)
    return demo


if __name__ == "__main__":
    css = CSS_FILE.read_text() if CSS_FILE.exists() else ""
    try:
        build_ui().launch(css=css)       
    except TypeError:
        build_ui(css).launch()         