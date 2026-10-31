from django.test import SimpleTestCase
from scanner.analysis.catalog_rules import RULES, analyze_catalog

class CatalogRegressionTests(SimpleTestCase):
    def test_catalog_has_80_detectors(self):
        self.assertEqual(len(RULES), 80)
    def test_every_detector_has_positive_and_secure_snippets(self):
        for rule in RULES:
            positive=analyze_catalog(rule["vulnerable_code"],rule["language"])
            self.assertTrue(any(x["rule_id"]==rule["id"] for x in positive), rule["id"])
            secure=analyze_catalog(rule["secure_code"],rule["language"])
            self.assertFalse(any(x["rule_id"]==rule["id"] for x in secure), rule["id"])
