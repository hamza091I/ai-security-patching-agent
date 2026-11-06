"""Command-line entry point for the benchmark evaluation pipeline."""
from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.evaluation.benchmark_runner import run_benchmark


def evaluate_cases(cases, negative_cases=None):
    """Keep a compatibility wrapper for callers using the old API."""
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        positive_path = root / "positive.json"
        negative_path = root / "negative.json"
        positive_path.write_text(json.dumps(cases), encoding="utf-8")
        negative_path.write_text(json.dumps(negative_cases or []), encoding="utf-8")
        result = run_benchmark(positive_path, negative_path)

    return {
        "counts": result["counts"],
        "metrics": {
            "precision": result["metrics"]["precision"],
            "recall": result["metrics"]["recall"],
            "accuracy": result["metrics"]["accuracy"],
            "f1": result["metrics"]["f1_score"],
            "false_positive_rate": result["metrics"]["false_positive_rate"],
        },
        "cases": [
            {
                "id": row["id"],
                "expected": row["expected_cwes"],
                "predicted": row["detected_cwes"],
                "detected": row["passed"],
            }
            for row in result["cases"]
            if row["should_detect"]
        ],
        "negative_cases": [
            {
                "id": row["id"],
                "predicted": row["detected_cwes"],
                "clean": row["passed"],
            }
            for row in result["cases"]
            if not row["should_detect"]
        ],
    }


def evaluate_file(path="benchmark-v0.json"):
    path = Path(path)
    negative = path.with_name("benchmark-negative-v0.json")
    return evaluate_cases(
        json.loads(path.read_text(encoding="utf-8")),
        json.loads(negative.read_text(encoding="utf-8")) if negative.exists() else [],
    )


if __name__ == "__main__":
    print(json.dumps(evaluate_file(), indent=2))
