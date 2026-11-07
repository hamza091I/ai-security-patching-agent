import unittest

from scanner.rag.rag_engine import SecurityRAGEngine, analyze_and_retrieve_fix
from scanner.rag.vector_db import KnowledgeVectorStore


RECORDS = [
    {
        "cwe_id": "CWE-95",
        "title": "Eval Injection",
        "vulnerable_example": "result = eval(user_input)",
        "secure_example": "result = ast.literal_eval(user_input)",
        "explanation": "Avoid executing user controlled code.",
    },
    {
        "cwe_id": "CWE-798",
        "title": "Hardcoded Secret",
        "vulnerable_example": "password = 'demo'",
        "secure_example": "password = os.environ['PASSWORD']",
        "explanation": "Load credentials from the environment.",
    },
]


class KnowledgeVectorStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = KnowledgeVectorStore(records=RECORDS)

    def test_exact_cwe_match_has_priority(self):
        result = self.store.search("user controlled code", cwe_id="CWE-95", n_results=1)
        self.assertEqual(result[0]["cwe_id"], "CWE-95")
        self.assertEqual(result[0]["match"], "exact_cwe")

    def test_token_search_returns_relevant_fix(self):
        result = self.store.search("hardcoded password credential", n_results=1)
        self.assertEqual(result[0]["cwe_id"], "CWE-798")
        self.assertGreater(result[0]["score"], 0)

    def test_unknown_lookup_is_safe(self):
        self.assertIsNone(self.store.lookup("CWE-999"))

    def test_rag_enriches_detected_finding(self):
        engine = SecurityRAGEngine(store=self.store)
        result = engine.enrich_findings([{"cwe_id": "CWE-95", "message": "eval injection"}])
        self.assertEqual(result[0]["rag_suggested_fix"]["cwe_id"], "CWE-95")
        self.assertIn("literal_eval", result[0]["rag_suggested_fix"]["secure_example"])

    def test_analyze_and_retrieve_fix_returns_kb_size(self):
        result = analyze_and_retrieve_fix("value = eval(user_input)")
        self.assertGreaterEqual(result["knowledge_base_size"], 1)
        self.assertEqual(result["enriched_vulnerabilities"][0]["detected_issue"]["cwe_id"], "CWE-95")


if __name__ == "__main__":
    unittest.main()
