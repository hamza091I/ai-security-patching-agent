# Baraa and Najah Development Tasks

## Baraa — RAG and Vector Store

The RAG layer now uses `scanner/rag/vector_db.py` as a deterministic local knowledge store. It loads the records from `vulnerabilities_dataset.json`, normalizes CWE records, indexes searchable tokens, supports exact CWE lookup, and ranks semantic-like token overlap results. Exact CWE matches are given priority so a known fix is not replaced by a similar vulnerability. The store returns the vulnerability title, vulnerable example, secure example, explanation, score, and match type.

`scanner/rag/rag_engine.py` now enriches each detector finding with a normalized RAG fix. It supports direct CWE lookup, ranked search, injected stores for unit tests, and a safe empty result when no record exists. `app/rag/vector_db.py` re-exports the same implementation so the project has one vector-store interface instead of an empty duplicate module.

## Najah — Dashboard and Evaluation UI

The backend now exposes `GET /api/evaluation/summary/` for authenticated users. It reads the latest checked benchmark report and returns the counts, metrics, total cases, passed cases, failed cases, and report source.

The Dashboard now contains a Benchmark Evaluation card with Precision, Recall, F1-score, True Positives, False Positives, and False Negatives. The card loads dynamically from the new API and shows how many benchmark cases passed and how many require follow-up. The existing live scan, patch preview, engine comparison, and history remain available.

## Verification

The merged project passed `python manage.py check` and all 54 tests. The RAG smoke test retrieved `CWE-95` for `value = eval(user_input)` from a six-record knowledge base. Existing benchmark results remain 20 true positives, 16 true negatives, 4 false positives, and 0 false negatives.

The RAG implementation is intentionally deterministic and does not require a model download. A production embedding adapter can be added later behind the same `KnowledgeVectorStore` interface.
