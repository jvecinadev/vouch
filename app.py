"""OWNER: Dev A. The single-page Gradio UI. Run: python app.py   (or VOUCH_MOCK=1 python app.py)"""
from pathlib import Path

import gradio as gr

import config
from ui import components as ui
from vouch.languages import EXTENSION, NAMES
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
    for event, payload in scan(diff_text, language):
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
                                          placeholder="Paste a git diff or plain code here",
                                          elem_classes=["code-input"])
                    language = gr.Dropdown(
                        [("Auto-detect", "auto")] + [(NAMES[k], k) for k in EXTENSION if k != "tsx"],
                        value="auto", label="Language (only used for plain code; a diff uses its file names)")
                    with gr.Row(elem_classes=["input-actions"]):
                        scan_btn = gr.Button("Scan", elem_classes=["v-button", "v-button-primary"])
                        demo_btn = gr.Button("Load Python demo", elem_classes=["v-button", "v-button-secondary"])
                        demo_js_btn = gr.Button("Load JavaScript demo",
                                                elem_classes=["v-button", "v-button-secondary"])
                    gr.HTML(ui.privacy_note())
                    recheck = gr.Button("Re-check Ollama", size="sm", elem_classes=["v-button", "v-button-ghost"])
                results = gr.HTML(ui.render_results([]))
            gr.HTML(ui.footer())
        recheck.click(topbar_now, outputs=topbar)
        demo_btn.click(lambda: DEMO_DIFF.read_text(encoding="utf-8"), outputs=diff_box)
        demo_js_btn.click(lambda: DEMO_JS_DIFF.read_text(encoding="utf-8"), outputs=diff_box)
        scan_btn.click(run_scan, inputs=[diff_box, language], outputs=results)
    return demo


if __name__ == "__main__":
    css = CSS_FILE.read_text(encoding="utf-8") if CSS_FILE.exists() else ""
    try:
        build_ui().launch(css=css)       # Gradio 6+
    except TypeError:
        build_ui(css).launch()           # older Gradio: css goes into gr.Blocks
