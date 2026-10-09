"""OWNER: Dev C. Ask the model: real issue or false positive, and explain it."""
from .context import context_window
from .languages import NAMES, language_of
from .llm import call_llm
from .trace import trace_finding
import config

TRIAGE_PROMPT = """You are a security code reviewer. A static scanner reported an issue.

Rule: {rule_id} ({cwe})
Scanner message: {message}
File: {file} ({language}), line {line}

Code around the finding:
```{fence}
{snippet}
```
{trace}
Decide if this is a real vulnerability. Reply with JSON only:
{{"verdict": "true_positive" or "likely_false_positive", "explanation": "2-3 plain sentences: what is wrong and how it could be exploited", "severity": "critical" or "high" or "medium" or "low"}}"""


def triage_finding(finding, file_text: str):
    _, _, snippet = context_window(file_text, finding.line, config.CONTEXT_RADIUS)
    lang = language_of(finding.file)
    finding.trace = trace_finding(finding, file_text)["note"]
    prompt = TRIAGE_PROMPT.format(trace=("\n" + finding.trace + "\n") if finding.trace else "",
                                  language=NAMES.get(lang, "unknown"), fence=lang or "",
                                  rule_id=finding.rule_id, cwe=finding.cwe or "no CWE",
                                  message=finding.message, file=finding.file,
                                  line=finding.line, snippet=snippet)
    try:
        data = call_llm(prompt)
        verdict = data.get("verdict", "")
        finding.verdict = verdict if verdict in ("true_positive", "likely_false_positive") else "true_positive"
        finding.explanation = str(data.get("explanation", "")).strip() or finding.message
        if data.get("severity") in ("critical", "high", "medium", "low"):
            finding.severity = data["severity"]   # model's estimate, not a CVSS score
    except Exception as e:                        # model down or bad JSON: fall back to scanner text
        finding.verdict = "true_positive"
        finding.explanation = finding.message
        finding.verify_log.append(f"triage failed: {e}")
    return finding