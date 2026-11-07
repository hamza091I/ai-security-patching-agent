"""Small, deterministic knowledge-vector store used by the security RAG layer.

The project can run without a model download or an external vector service. Records
are indexed from vulnerabilities_dataset.json and searched with a token-overlap
similarity score plus an exact CWE boost. The interface is intentionally compatible
with a future Chroma adapter.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{1,}")


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in _TOKEN_RE.findall(text or "")}


def _normalise(record: dict[str, Any]) -> dict[str, Any]:
    cwe_id = str(record.get("cwe_id") or record.get("cwe") or "").upper()
    return {
        "cwe_id": cwe_id,
        "title": str(record.get("title") or record.get("type") or cwe_id),
        "vulnerable_example": str(record.get("vulnerable_example") or ""),
        "secure_example": str(record.get("secure_example") or ""),
        "explanation": str(record.get("explanation") or record.get("description") or ""),
    }


class KnowledgeVectorStore:
    """Searchable local store with a stable result schema."""

    def __init__(self, records: Iterable[dict[str, Any]] | None = None, dataset_path: str | Path | None = None):
        if records is None:
            path = Path(dataset_path) if dataset_path else Path(__file__).resolve().parents[2] / "vulnerabilities_dataset.json"
            try:
                records = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
            except (OSError, ValueError):
                records = []
        self.records = [_normalise(record) for record in records if isinstance(record, dict)]
        self._index = {
            record["cwe_id"]: _tokens(" ".join(record.values()))
            for record in self.records
            if record["cwe_id"]
        }

    def count(self) -> int:
        return len(self.records)

    def get_by_cwe(self, cwe_id: str | None) -> dict[str, Any] | None:
        wanted = str(cwe_id or "").upper()
        return next((record for record in self.records if record["cwe_id"] == wanted), None)

    def search(self, query: str, n_results: int = 3, cwe_id: str | None = None) -> list[dict[str, Any]]:
        """Return ranked records with score and match reason.

        An exact CWE match wins over semantic overlap. This makes results stable and
        prevents a close-looking vulnerability from replacing a known CWE fix.
        """
        query_tokens = _tokens(query)
        wanted = str(cwe_id or "").upper()
        ranked: list[dict[str, Any]] = []
        for record in self.records:
            record_tokens = self._index.get(record["cwe_id"], set())
            overlap = len(query_tokens & record_tokens)
            score = overlap / max(1, len(query_tokens | record_tokens))
            exact = bool(wanted and record["cwe_id"] == wanted)
            if exact:
                score += 1.0
            if score > 0 or exact:
                ranked.append({**record, "score": round(score, 4), "match": "exact_cwe" if exact else "token_overlap"})
        ranked.sort(key=lambda item: (-item["score"], item["cwe_id"]))
        return ranked[: max(0, int(n_results))]

    def lookup(self, cwe_id: str | None, query: str = "") -> dict[str, Any] | None:
        exact = self.get_by_cwe(cwe_id)
        if exact:
            return {**exact, "score": 1.0, "match": "exact_cwe"}
        return self.search(query, n_results=1)[0] if query else None


_default_store: KnowledgeVectorStore | None = None


def get_knowledge_store() -> KnowledgeVectorStore:
    global _default_store
    if _default_store is None:
        _default_store = KnowledgeVectorStore()
    return _default_store


def query_knowledge_base(query_text: str, n_results: int = 1, cwe_id: str | None = None) -> list[dict[str, Any]]:
    """Public function used by the RAG engine and tests."""
    return get_knowledge_store().search(query_text, n_results=n_results, cwe_id=cwe_id)
