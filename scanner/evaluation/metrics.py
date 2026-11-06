from __future__ import annotations

from typing import Iterable


def safe_divide(numerator: int | float, denominator: int | float) -> float:
    """Return zero instead of raising when a metric has no denominator."""
    if denominator == 0:
        return 0.0
    return numerator / denominator


def calculate_metrics(
    true_positives: int,
    true_negatives: int,
    false_positives: int,
    false_negatives: int,
) -> dict:
    """Calculate the main binary-classification metrics."""
    precision = safe_divide(true_positives, true_positives + false_positives)
    recall = safe_divide(true_positives, true_positives + false_negatives)
    f1_score = safe_divide(2 * precision * recall, precision + recall)
    total = true_positives + true_negatives + false_positives + false_negatives
    accuracy = safe_divide(true_positives + true_negatives, total)
    false_positive_rate = safe_divide(
        false_positives,
        false_positives + true_negatives,
    )
    false_negative_rate = safe_divide(
        false_negatives,
        false_negatives + true_positives,
    )

    return {
        "true_positives": true_positives,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "total": total,
    }


def compare_cwes(
    expected_cwes: Iterable[str],
    detected_cwes: Iterable[str],
) -> dict:
    """Return the CWE-level overlap and errors for one benchmark case."""
    expected = {str(value) for value in expected_cwes if value}
    detected = {str(value) for value in detected_cwes if value}
    return {
        "true_positives": sorted(expected.intersection(detected)),
        "false_negatives": sorted(expected - detected),
        "false_positives": sorted(detected - expected),
    }


def classify_case(expected_cwes: Iterable[str], detected_cwes: Iterable[str]) -> dict:
    """Classify one positive or negative benchmark case at CWE level."""
    comparison = compare_cwes(expected_cwes, detected_cwes)
    expected = set(expected_cwes)
    detected = set(detected_cwes)

    # A clean benchmark case is a true negative only when nothing was found.
    if not expected:
        return {
            "true_positives": 0,
            "true_negatives": 1 if not detected else 0,
            "false_positives": len(detected),
            "false_negatives": 0,
            "true_positive_cwes": comparison["true_positives"],
            "false_negative_cwes": comparison["false_negatives"],
            "false_positive_cwes": comparison["false_positives"],
        }

    return {
        "true_positives": len(comparison["true_positives"]),
        "true_negatives": 0,
        "false_positives": len(comparison["false_positives"]),
        "false_negatives": len(comparison["false_negatives"]),
        "true_positive_cwes": comparison["true_positives"],
        "false_negative_cwes": comparison["false_negatives"],
        "false_positive_cwes": comparison["false_positives"],
    }
