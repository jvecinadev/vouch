import os

MODEL = os.getenv("VOUCH_MODEL", "qwen2.5-coder:3b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MAX_RETRIES = 2        
CONTEXT_RADIUS = 10      
MAX_FINDINGS = 10
USE_MOCK = os.getenv("VOUCH_MOCK") == "1"   
RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
