from django.test import SimpleTestCase

from scanner.evaluation.benchmark_runner import run_case
from scanner.evaluation.metrics import calculate_metrics, classify_case


class MetricsTests(SimpleTestCase):
    def test_metrics_are_calculated(self):
        result = calculate_metrics(
            true_positives=8,
            true_negatives=6,
            false_positives=1,
            false_negatives=2,
        )

        self.assertEqual(result["true_positives"], 8)
        self.assertEqual(result["true_negatives"], 6)
        self.assertEqual(result["false_positives"], 1)
        self.assertEqual(result["false_negatives"], 2)

        self.assertEqual(result["precision"], 0.8889)
        self.assertEqual(result["recall"], 0.8)
        self.assertEqual(result["f1_score"], 0.8421)

    def test_zero_denominators_do_not_crash(self):
        result = calculate_metrics(
            true_positives=0,
            true_negatives=0,
            false_positives=0,
            false_negatives=0,
        )

        self.assertEqual(result["precision"], 0.0)
        self.assertEqual(result["recall"], 0.0)
        self.assertEqual(result["f1_score"], 0.0)
        self.assertEqual(result["accuracy"], 0.0)

    def test_cwe_comparison(self):
        from scanner.evaluation.metrics import compare_cwes

        result = compare_cwes(
            expected_cwes={"CWE-95", "CWE-78"},
            detected_cwes={"CWE-95", "CWE-89"},
        )

        self.assertEqual(result["true_positives"], ["CWE-95"])
        self.assertEqual(result["false_negatives"], ["CWE-78"])
        self.assertEqual(result["false_positives"], ["CWE-89"])

    def test_negative_case_is_true_negative_when_no_finding_is_returned(self):
        result = classify_case(set(), set())

        self.assertEqual(result["true_negatives"], 1)
        self.assertEqual(result["false_positives"], 0)

    def test_runner_calls_the_real_scanner_contract(self):
        def fake_scanner(*, code, filename, **kwargs):
            self.assertEqual(code, "value = eval(user_input)")
            self.assertEqual(filename, "benchmark.py")
            return {
                "all_findings": [{"cwe_id": "CWE-95"}],
            }

        row = run_case(
            {
                "id": "TEST-001",
                "language": "python",
                "vulnerable_code": "value = eval(user_input)",
                "expected": {"cwe_id": "CWE-95", "should_detect": True},
            },
            scanner=fake_scanner,
        )

        self.assertTrue(row["passed"])
        self.assertEqual(row["counts"]["true_positives"], 1)

