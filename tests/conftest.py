import pytest

from vouch import review


@pytest.fixture(autouse=True)
def no_real_model_review(monkeypatch):
    """Tests never call a real Ollama for the diff review; tests that need it patch review.call_llm."""
    monkeypatch.setattr(review, "call_llm", lambda prompt: {"issues": []})
