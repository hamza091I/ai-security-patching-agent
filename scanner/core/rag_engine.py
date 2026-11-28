"""Backward-compatible entry points for the canonical scanner RAG engine.

The project used to have a second Chroma-only implementation here. Keeping this
wrapper avoids breaking imports while ensuring every caller uses the same backend
selection and deterministic fallback in ``scanner.rag.vector_db``.
"""
from scanner.rag.rag_engine import SecurityRAGEngine as _SecurityRAGEngine


class SecurityRAGEngine(_SecurityRAGEngine):
    """Compatibility facade exposing the old ``search_similar_fix`` method."""

    def search_similar_fix(self, code_snippet: str):
        match = self.search(code_snippet, n_results=1)
        if not match:
            return {
                "found": False,
                "cwe_id": "None",
                "type": "Secure / Unknown",
                "description": "No matching vulnerability was found in the security knowledge base.",
                "recommendation": "No recommendations needed at this time.",
            }
        record = match[0]
        return {
            "found": True,
            **record,
            "type": record.get("title", "Security issue"),
            "description": record.get("explanation", ""),
            "recommendation": record.get("secure_example", "Review the secure example."),
        }
