"""Compatibility exports for the project RAG vector store."""

from scanner.rag.vector_db import KnowledgeVectorStore, get_knowledge_store, query_knowledge_base

__all__ = ["KnowledgeVectorStore", "get_knowledge_store", "query_knowledge_base"]
