"""OWNER: Dev B. Export findings as SARIF 2.1.0 for CI tools."""
import json
import tempfile

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def export_sarif(findings: list) -> dict:
    rules = {}
    for f in findings:
        rules.setdefault(f.rule_id, {"id": f.rule_id, "name": f.title,
                                     "shortDescription": {"text": f.title}})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Vouch", "rules": list(rules.values())}},
            "results": [{
                "ruleId": f.rule_id,
                "level": LEVEL.get(f.severity, "warning"),
                "message": {"text": f.explanation or f.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line}}}],
                "properties": {"cwe": f.cwe, "verdict": f.verdict,
                               "badge": f.badge.value, "suggestedPatch": f.patch},
            } for f in findings],
        }],
    }


def write_sarif(findings: list) -> str:
    out = tempfile.NamedTemporaryFile("w", suffix=".sarif", prefix="vouch-", delete=False)
    json.dump(export_sarif(findings), out, indent=2)
    out.close()
    return out.name
