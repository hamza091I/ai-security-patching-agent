"""Deterministic RAG facade for scanner findings."""
from __future__ import annotations

from scanner.analysis.ast_parser import analyze_code_string
from scanner.rag.vector_db import KnowledgeVectorStore, get_knowledge_store


class SecurityRAGEngine:
    """Enrich findings with the best matching CWE knowledge record."""

    def __init__(self, store: KnowledgeVectorStore | None = None):
        self.store = store or get_knowledge_store()
        self.records = self.store.records

    def find(self, cwe_id: str | None, query: str = "") -> dict:
        match = self.store.lookup(cwe_id, query=query)
        return match or {}

    def search(self, query: str, n_results: int = 3, cwe_id: str | None = None) -> list[dict]:
        return self.store.search(query, n_results=n_results, cwe_id=cwe_id)

    def enrich_findings(self, findings: list[dict]) -> list[dict]:
        enriched = []
        for finding in findings:
            knowledge = self.find(finding.get("cwe_id"), query=finding.get("message", ""))
            enriched.append({"detected_issue": finding, "rag_suggested_fix": knowledge})
        return enriched


def analyze_and_retrieve_fix(code_string: str) -> dict:
    findings = analyze_code_string(code_string)
    engine = SecurityRAGEngine()
    return {
        "code_scanned": code_string,
        "enriched_vulnerabilities": engine.enrich_findings(findings),
        "knowledge_base_size": engine.store.count(),
    }
