# Hamzeh Week 1 Integration

This folder is a clean merged copy of the public GitHub repository plus Hamzeh Karram's Week 1 evaluation work.

## Preserved team work

The repository detector work was kept from the GitHub `main` branch, including:

- `scanner/analysis/ast_parser.py`
- `scanner/test_detection_variants.py`
- the existing scanner rules and shared Finding Contract

## Added Hamzeh work

- `scanner/evaluation/metrics.py`
- `scanner/evaluation/benchmark_runner.py`
- `scanner/evaluation/test_metrics.py`
- updated `scanner/evaluator.py`
- updated `scanner/views.py` with scan summaries and duration
- updated `scanner/tests.py`
- updated `README.md`
- `reports/hamzeh-week1-evaluation.json`

The Benchmark Runner calls the real scanner entry point:

```python
from scanner.analysis.security_scanner import full_security_scan
```

## Verification

Commands executed on the merged copy:

```bash
python manage.py check
python manage.py test
python scanner/evaluation/benchmark_runner.py
```

Results:

- Django check: passed
- Tests: 48 passed
- Benchmark cases: 40
- True positives: 20
- True negatives: 16
- False positives: 4
- False negatives: 0
- Precision: 0.8333
- Recall: 1.0000
- F1-score: 0.9091
- Accuracy: 0.9000

The remaining false positives are NEG-002, NEG-008, NEG-015 and NEG-016. They are preserved in the report as follow-up detector-improvement targets.

## Security cleanup

The deliverable does not contain local secrets or generated environment files. The following were removed from the clean copy:

- `.env`
- `db.sqlite3`
- `.venv/` and `venv/`
- `__pycache__/`
- compiled Python files

Use `.env.example` to create a local `.env` file when setting up the project.
