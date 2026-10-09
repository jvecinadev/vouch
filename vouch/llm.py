"""OWNER: Dev C. The ONLY file that talks to Ollama. Everything else calls call_llm()."""
import json

import config


def call_llm(prompt: str, json_mode: bool = True):
    import ollama
    client = ollama.Client(host=config.OLLAMA_HOST)
    kwargs = {"format": "json"} if json_mode else {}
    resp = client.chat(model=config.MODEL,
                       messages=[{"role": "user", "content": prompt}],
                       options={"temperature": 0.1}, **kwargs)
    text = resp["message"]["content"]
    return json.loads(text) if json_mode else text


def llm_status() -> dict:
    try:
        import ollama
        listing = ollama.Client(host=config.OLLAMA_HOST).list()
        models = getattr(listing, "models", None)
        if models is None:
            models = listing.get("models", [])
        names = []
        for m in models:
            name = getattr(m, "model", None)
            if name is None and hasattr(m, "get"):
                name = m.get("model") or m.get("name")
            names.append(name)
    except Exception as e:
        return {"ok": False, "reason": f"Ollama not reachable: {e}"}
    wanted = config.MODEL
    if wanted in names or f"{wanted}:latest" in names:
        return {"ok": True, "reason": ""}
    return {"ok": False, "reason": f"Model not pulled. Run: ollama pull {wanted}"}
