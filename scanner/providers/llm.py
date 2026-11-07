"""Optional Ollama provider; baseline scanning never requires a running LLM."""

import os
from urllib.parse import urlparse

import requests


class LLMProvider:
    def analyze(self, code, language="python"):
        raise NotImplementedError


class OllamaProvider(LLMProvider):
    def __init__(self, model=None, base_url=None):
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.2")
        self.base_url = (
            base_url or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434" )
        ).rstrip("/")

        scheme = urlparse(self.base_url).scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("OLLAMA_BASE_URL must use http:// or https://" )

    def analyze(self, code, language="python"):
        payload = {
            "model": self.model,
            "prompt": (
                "Return JSON findings with cwe_id, rule_id, severity, confidence, "
                "line_start, line_end, message, recommendation. Language: "
                f"{language}\n{code}"
            ),
            "stream": False,
        }

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                headers={"Accept": "application/json"},
                timeout=30,
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except requests.RequestException as exc:
            return {"error": str(exc), "findings": []}
        except (TypeError, ValueError) as exc:
            return {"error": f"Invalid Ollama response: {exc}", "findings": []}
