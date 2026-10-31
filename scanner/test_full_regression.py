import json
from pathlib import Path
from django.test import SimpleTestCase
from scanner.analysis.orchestrator import scan_code
class FullPositiveRegressionTests(SimpleTestCase):
    def test_original_20_benchmark_cases(self):
        cases=json.loads((Path(__file__).resolve().parent.parent/'benchmark-v0.json').read_text())
        for case in cases:
            filename='case.js' if case.get('language') in {'javascript','typescript'} else 'case.py'
            findings=scan_code(case['vulnerable_code'],filename)['findings']
            self.assertIn(case['expected']['cwe_id'],{f['cwe_id'] for f in findings},case['id'])
