from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Iterable

from scanner.analysis.security_scanner import full_security_scan
from scanner.evaluation.metrics import calculate_metrics, classify_case

ScannerFunction = Callable[..., dict]


def load_cases(path: str | Path) -> list[dict]:
    """Load a benchmark list from the supported JSON shapes."""
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("cases", "benchmarks", "items", "data"):
            if isinstance(data.get(key), list):
                return data[key]

    raise ValueError(f"Unsupported benchmark format: {file_path}")


def benchmark_filename(case: dict) -> str:
    """Return an extension that matches the benchmark language."""
    language = str(case.get("language", "python")).lower()
    extension = "js" if language == "javascript" else "ts" if language == "typescript" else "py"
    return str(case.get("filename") or f"benchmark.{extension}")


def extract_cwes(findings: Iterable[dict]) -> set[str]:
    """Extract normalized CWE IDs from scanner findings."""
    cwes = set()
    for finding in findings or []:
        cwe_id = finding.get("cwe_id") or finding.get("cwe") or finding.get("CWE")
        if cwe_id and str(cwe_id) != "SYNTAX":
            cwes.add(str(cwe_id))
    return cwes


def expected_cwes(case: dict) -> set[str]:
    """Read the expected CWE only when the benchmark says it should detect one."""
    expected = case.get("expected") or {}
    if isinstance(expected, dict):
        should_detect = expected.get("should_detect", bool(expected.get("cwe_id")))
        cwe_id = expected.get("cwe_id") or case.get("cwe_id")
    else:
        should_detect = bool(expected)
        cwe_id = case.get("cwe_id")

    return {str(cwe_id)} if should_detect and cwe_id else set()


def run_case(case: dict, scanner: ScannerFunction = full_security_scan) -> dict:
    """Run one benchmark case through the real combined scanner."""
    is_negative = not expected_cwes(case)
    code = case.get("secure_code") if is_negative else case.get("vulnerable_code")
    code = code or case.get("code") or case.get("source") or ""
    filename = benchmark_filename(case)

    scan_result = scanner(
        code=code,
        filename=filename,
    )
    findings = scan_result.get("all_findings", scan_result.get("findings", []))
    detected = extract_cwes(findings)
    expected = expected_cwes(case)
    counts = classify_case(expected, detected)

    return {
        "id": case.get("id") or case.get("name"),
        "language": case.get("language", "python"),
        "filename": filename,
        "expected_cwes": sorted(expected),
        "detected_cwes": sorted(detected),
        "findings_count": len(findings),
        "should_detect": bool(expected),
        "passed": (
            not counts["false_negatives"]
            and not counts["false_positives"]
            and (bool(expected) == bool(detected))
        ),
        "counts": {
            key: counts[key]
            for key in (
                "true_positives",
                "true_negatives",
                "false_positives",
                "false_negatives",
            )
        },
        "true_positive_cwes": counts["true_positives"],
        "false_positive_cwes": counts["false_positives"],
        "false_negative_cwes": counts["false_negatives"],
    }


def run_benchmark(
    positive_path: str | Path = "benchmark-v0.json",
    negative_path: str | Path | None = "benchmark-negative-v0.json",
    scanner: ScannerFunction = full_security_scan,
) -> dict:
    """Run positive and negative cases and calculate aggregate metrics."""
    cases = load_cases(positive_path)
    if negative_path and Path(negative_path).exists():
        cases += load_cases(negative_path)

    rows = [run_case(case, scanner=scanner) for case in cases]
    totals = {key: 0 for key in (
        "true_positives",
        "true_negatives",
        "false_positives",
        "false_negatives",
    )}
    for row in rows:
        for key, value in row["counts"].items():
            totals[key] += value

    return {
        "total_cases": len(rows),
        "passed_cases": sum(1 for row in rows if row["passed"]),
        "failed_cases": sum(1 for row in rows if not row["passed"]),
        "counts": totals,
        "metrics": calculate_metrics(**totals),
        "cases": rows,
    }


if __name__ == "__main__":
    result = run_benchmark()
    print(json.dumps(result, indent=2))
