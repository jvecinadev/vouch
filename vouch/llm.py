"""OWNER: Dev C. The ONLY file that talks to Ollama. Everything else calls call_llm()."""
import json

import config

_cached = None   # (host, client): one client per host, reused across calls


def _client():
    """Import ollama lazily, so a missing package means scanner-only mode instead of a crash."""
    global _cached
    import ollama
    if _cached is None or _cached[0] != config.OLLAMA_HOST:
        _cached = (config.OLLAMA_HOST, ollama.Client(host=config.OLLAMA_HOST))
    return _cached[1]


def call_llm(prompt: str, json_mode: bool = True):
    kwargs = {"format": "json"} if json_mode else {}
    resp = _client().chat(model=config.MODEL,
                          messages=[{"role": "user", "content": prompt}],
                          options={"temperature": 0.1}, **kwargs)
    text = resp["message"]["content"]
    return json.loads(text) if json_mode else text


def _model_name(m):
    """Works with both SDK styles: dicts (old) and objects (new)."""
    if isinstance(m, dict):
        return m.get("model") or m.get("name")
    return getattr(m, "model", None) or getattr(m, "name", None)


def llm_status() -> dict:
    try:
        listing = _client().list()
        models = listing.get("models", []) if isinstance(listing, dict) else getattr(listing, "models", [])
        names = [n for n in (_model_name(m) for m in models or []) if n]
    except ImportError:
        return {"ok": False, "reason": "The ollama Python package is not installed. Run: pip install ollama"}
    except Exception as e:
        return {"ok": False, "reason": f"Ollama not reachable: {e}"}
    wanted = config.MODEL
    if wanted in names or f"{wanted}:latest" in names:
        return {"ok": True, "reason": ""}
    return {"ok": False, "reason": f"Model not pulled. Run: ollama pull {wanted}"}
