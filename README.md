# Vouch

## Problem

Code changes are reviewed quickly, and security bugs slip through. Static scanners find issues but produce many false positives and rarely suggest fixes. They also only see the *new* code, so they miss changes that **remove** a safeguard (for example, swapping a constant-time compare for `==`, or dropping a prepared statement). Sending private code to a cloud AI service is not an option for many teams.

## Project Name

**Vouch**: a local, privacy-first security reviewer for git diffs.

## Brief Description

Paste a git diff (or plain code) into a web page and Vouch will:

1. **Scan** the changed files with Bandit and Semgrep.
2. **Detect removed safeguards** that scanners can't see (password checks, escaping, auth checks, strict comparisons, error handling, and more).
3. **Review** each changed hunk with a local AI model for issues no rule covers.
4. **Triage** each finding as a real issue or a likely false positive, with a plain-language explanation.
5. **Suggest a fix** as a patch, then **verify** it: the patch must apply, the code must still parse, and the finding must be gone.

Everything runs on your machine. Your code is never sent to an outside service. Results can be exported as SARIF for CI tools.

Supported languages: Python, JavaScript, TypeScript, Java, Go, PHP.

## Tools

| Tool | Used for |
|---|---|
| [Python](https://www.python.org/) | Main language |
| [Gradio](https://www.gradio.app/) | Web interface |
| [Ollama](https://ollama.com/) | Runs the local AI model |
| [Bandit](https://bandit.readthedocs.io/) | Python security scanning |
| [Semgrep](https://semgrep.dev/) | Multi-language scanning with custom rules |
| [tree-sitter](https://tree-sitter.github.io/) | Syntax checking of patched code (JS, TS, Java, Go, PHP) |
| [Git](https://git-scm.com/) | Validating and applying suggested patches |
| [pytest](https://pytest.org/) | Tests |

## Assets

```
vouch/
├── app.py            # Gradio web app (entry point)
├── config.py         # Settings (model name, Ollama host, limits)
├── requirements.txt  # Python dependencies
├── vouch/            # Core logic: diff parsing, scanners, safeguards,
│                     #   review, triage, patching, verification, SARIF export
├── rules/            # Custom Semgrep rules (python, java, javascript, go, php)
├── assets/           # style.css for the UI
├── ui/               # UI components
├── examples/         # Demo diffs loaded by the "Load demo" buttons
├── benchmark/        # Test cases and a script to compare models
└── tests/            # Automated tests
```

## Models

Vouch uses a small local model through Ollama. The default is **`qwen2.5-coder:3b`**.

To use a different model, set `VOUCH_MODEL` before starting the app:

```bash
# macOS / Linux
export VOUCH_MODEL=qwen2.5-coder:1.5b

# Windows (PowerShell)
$env:VOUCH_MODEL = "qwen2.5-coder:1.5b"
```

If Ollama or the model isn't available, Vouch still works in **scanner-only mode** (findings are shown without AI triage or fixes).

## Installation

### Prerequisites

- Python 3.10 or newer
- [Git](https://git-scm.com/downloads) (must be on your PATH)
- [Ollama](https://ollama.com/download) (optional, needed for AI review, triage, and fixes)

### Steps

1. **Get the project and open a terminal in its folder**

   ```bash
   cd vouch
   ```

2. **Create and activate a virtual environment**

   ```bash
   python -m venv venv

   # macOS / Linux
   source venv/bin/activate

   # Windows (PowerShell)
   venv\Scripts\Activate.ps1
   ```

3. **Install the dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Install the AI model** (skip this for scanner-only mode)

   ```bash
   ollama pull qwen2.5-coder:3b
   ```

   Make sure Ollama is running (the desktop app, or `ollama serve`).

5. **Start the app**

   ```bash
   python app.py
   ```

6. **Open the link shown in the terminal** (usually http://127.0.0.1:7860).

## Usage

1. Paste a git diff, or plain code, into the box. Or click **Load Python demo** / **Load JavaScript demo**.
2. For plain code, pick the language (or leave it on Auto-detect).
3. Click **Scan** and watch the findings appear.
4. If the top bar says Ollama is not reachable, start Ollama and click **Re-check Ollama**.

### Try it without a model

```bash
# macOS / Linux
VOUCH_MOCK=1 python app.py

# Windows (PowerShell)
$env:VOUCH_MOCK = "1"; python app.py
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `VOUCH_MODEL` | `qwen2.5-coder:3b` | Ollama model to use |
| `VOUCH_OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama address (falls back to `OLLAMA_HOST`) |
| `VOUCH_MOCK` | unset | Set to `1` to run with fake results |

## Running the Tests

```bash
pytest
```

## Benchmark

Compare models on the sample vulnerable files in `benchmark/cases`:

```bash
python benchmark/run_benchmark.py qwen2.5-coder:1.5b qwen2.5-coder:3b
```

It prints a table of how many issues each model detected, triaged correctly, and fixed with a verified patch.

## Troubleshooting

- **"Ollama not reachable"**: start Ollama, then click **Re-check Ollama**.
- **"Model not pulled"**: run `ollama pull qwen2.5-coder:3b`.
- **Semgrep missing**: re-run `pip install -r requirements.txt` inside the activated virtual environment. Vouch still runs with the other checks.
- **Patches never apply**: confirm `git --version` works in the same terminal.

## Limitations

- A clean result is **not** a guarantee of safety.
- The model is small, so its explanations and fixes can be wrong. Always review suggested patches.
- Only the supported languages listed above are scanned.