"""OWNER: Dev C. The ONLY file that talks to Ollama. Everything else calls call_llm()."""
import json
import ollama
import config

client = ollama.Client(host=config.OLLAMA_HOST)

def call_llm(prompt: str, json_mode: bool = True):
    kwargs = {"format": "json"} if json_mode else {}
    
    resp = client.chat(
        model=config.MODEL,
        messages=[{"role": "user", "content": prompt}],
        options={"temperature": 0.1}, 
        **kwargs
    )
    
    text = resp["message"]["content"] 
    return json.loads(text) if json_mode else text


def llm_status() -> dict:
    try:
        listing = client.list()
        # Safely extract names regardless of SDK version object vs dict structure
        names = []
        models = getattr(listing, "models", None) or listing.get("models", [])
        
        for m in models:
            name = getattr(m, "model", None) or (m.get("model") if hasattr(m, "get") else m.get("name"))
            if name:
                names.append(name)
                
    except Exception as e:
        return {"ok": False, "reason": f"Ollama not reachable: {e}"}

    wanted = config.MODEL
    # Check both standard and implicit tag variants
    if wanted in names or f"{wanted}:latest" in names:
        return {"ok": True, "reason": ""}
        
    return {"ok": False, "reason": f"Model not pulled. Run: ollama pull {wanted}"}
