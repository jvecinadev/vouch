import os

MODEL = os.getenv("VOUCH_MODEL", "qwen2.5-coder:3b")
# VOUCH_OLLAMA_HOST wins; otherwise use Ollama's own OLLAMA_HOST. 0.0.0.0 is a bind address, not one you can connect to.
OLLAMA_HOST = (os.getenv("VOUCH_OLLAMA_HOST") or os.getenv("OLLAMA_HOST")
               or "http://127.0.0.1:11434").replace("0.0.0.0", "127.0.0.1")
MAX_RETRIES = 2        
CONTEXT_RADIUS = 10      
MAX_FINDINGS = 10
USE_MOCK = os.getenv("VOUCH_MOCK") == "1"   
RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
