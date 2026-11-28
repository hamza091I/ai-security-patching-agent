"""Knowledge stores used by the security RAG layer.

The deterministic store is the default and requires no model download.  Chroma is
an optional backend behind the same small interface; if its dependencies are not
installed, callers transparently fall back to the deterministic store.
"""
from __future__ import annotations

import json
import os
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


def _load_records(dataset_path: str | Path | None = None) -> list[dict[str, Any]]:
    path = Path(dataset_path) if dataset_path else Path(__file__).resolve().parents[2] / "vulnerabilities_dataset.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    except (OSError, ValueError):
        raw = []
    return [_normalise(record) for record in raw if isinstance(record, dict)]


class KnowledgeStore:
    """Small interface shared by deterministic and optional vector backends."""

    records: list[dict[str, Any]]

    def count(self) -> int:
        raise NotImplementedError

    def search(self, query: str, n_results: int = 3, cwe_id: str | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    def lookup(self, cwe_id: str | None, query: str = "") -> dict[str, Any] | None:
        results = self.search(query, n_results=1, cwe_id=cwe_id)
        return results[0] if results else None


class KnowledgeVectorStore(KnowledgeStore):
    """Deterministic local store using token overlap and exact-CWE priority."""

    def __init__(self, records: Iterable[dict[str, Any]] | None = None, dataset_path: str | Path | None = None):
        self.records = [_normalise(record) for record in (records if records is not None else _load_records(dataset_path))]
        self._index: dict[str, set[str]] = {}
        for record in self.records:
            cwe_id = record["cwe_id"]
            if cwe_id and cwe_id not in self._index:
                self._index[cwe_id] = _tokens(" ".join(record.values()))

    def count(self) -> int:
        return len(self.records)

    def get_by_cwe(self, cwe_id: str | None) -> dict[str, Any] | None:
        wanted = str(cwe_id or "").upper()
        return next((record for record in self.records if record["cwe_id"] == wanted), None)

    def search(self, query: str, n_results: int = 3, cwe_id: str | None = None) -> list[dict[str, Any]]:
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
        return super().lookup(cwe_id, query=query) if query else None


class ChromaKnowledgeStore(KnowledgeStore):
    """Optional embedding-backed store implementing the same public contract.

    Imports happen only when this backend is selected, so the normal demo and test
    path remains offline-friendly and does not download SentenceTransformer models.
    """

    def __init__(self, records: Iterable[dict[str, Any]] | None = None, dataset_path: str | Path | None = None, persist_directory: str | None = None):
        try:
            import chromadb
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("Chroma backend requires chromadb and sentence-transformers") from exc
        self.records = [_normalise(record) for record in (records if records is not None else _load_records(dataset_path))]
        self.model = SentenceTransformer(os.getenv("RAG_EMBEDDING_MODEL", "all-MiniLM-L6-v2"))
        client = chromadb.PersistentClient(path=persist_directory or os.getenv("RAG_CHROMA_PATH", "chroma_db"))
        self.collection = client.get_or_create_collection(name="security_knowledge_base")
        if self.records and self.collection.count() == 0:
            documents = [" ".join(record.values()) for record in self.records]
            self.collection.add(
                ids=[record["cwe_id"] or f"record-{index}" for index, record in enumerate(self.records)],
                documents=documents,
                embeddings=self.model.encode(documents).tolist(),
                metadatas=self.records,
            )

    def count(self) -> int:
        return len(self.records)

    def search(self, query: str, n_results: int = 3, cwe_id: str | None = None) -> list[dict[str, Any]]:
        if not query and cwe_id:
            query = cwe_id
        result = self.collection.query(query_embeddings=[self.model.encode(query).tolist()], n_results=max(1, int(n_results)))
        documents = (result.get("documents") or [[]])[0]
        metadatas = (result.get("metadatas") or [[]])[0]
        distances = (result.get("distances") or [[]])[0]
        rows = []
        for index, metadata in enumerate(metadatas):
            row = {**_normalise(metadata), "score": round(1 - float(distances[index]), 4) if index < len(distances) else 0.0, "match": "embedding"}
            if cwe_id and row["cwe_id"] == str(cwe_id).upper():
                row["score"] += 1.0
                row["match"] = "exact_cwe"
            if index < len(documents) and not row["explanation"]:
                row["explanation"] = documents[index]
            rows.append(row)
        return sorted(rows, key=lambda item: (-item["score"], item["cwe_id"]))[: max(0, int(n_results))]


_default_store: KnowledgeStore | None = None


def get_knowledge_store() -> KnowledgeStore:
    global _default_store
    if _default_store is None:
        backend = os.getenv("RAG_BACKEND", "deterministic").lower()
        if backend == "chroma":
            try:
                _default_store = ChromaKnowledgeStore()
            except (ImportError, RuntimeError, OSError, ValueError):
                _default_store = KnowledgeVectorStore()
        else:
            _default_store = KnowledgeVectorStore()
    return _default_store


def query_knowledge_base(query_text: str, n_results: int = 1, cwe_id: str | None = None) -> list[dict[str, Any]]:
    return get_knowledge_store().search(query_text, n_results=n_results, cwe_id=cwe_id)
