import json
from pathlib import Path

from scanner.analysis.ast_parser import analyze_code_string
from scanner.bandit_scanner import run_bandit_scan


# Normalize Bandit CWE classifications
BANDIT_CWE_MAPPING = {
    "B105": "CWE-798",
    "B307": "CWE-95",
}


def remove_duplicates(results):
    """
    Remove duplicate vulnerabilities detected
    by AST and Bandit.
    """

    unique_results = {}

    for issue in results:

        if "error" in issue:
            continue

        key = (
            issue.get("cwe_id"),
            issue.get("line_start")
        )

        if key in unique_results:

            existing = unique_results[key]

            sources = existing["source"].split(" + ")

            if issue["source"] not in sources:
                sources.append(issue["source"])

            existing["source"] = " + ".join(sources)

            if issue.get("rule_id"):
                existing["rule_id"] += f", {issue['rule_id']}"

        else:
            unique_results[key] = issue.copy()

    return list(unique_results.values())


def scan_file(file_path):

    try:
        path = Path(file_path)

        if not path.is_file():
            return [{"error": f"File not found: {file_path}"}]

        code = path.read_text(encoding="utf-8")

        unified_results = []

        # Run AST Analyzer
        ast_results = analyze_code_string(code)

        for issue in ast_results:

            cwe = issue.get("cwe_id")

            unified_results.append({
                "source": "AST",
                "cwe_id": cwe,
                "rule_id": f"AST-{cwe}",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "line_start": issue.get("line"),
                "issue": issue.get("message"),
                "recommendation": issue.get("recommendation"),
                "more_info": None
            })

        # Run Bandit Scanner
        bandit_results = run_bandit_scan(file_path)

        for issue in bandit_results:

            if "error" in issue:
                unified_results.append(issue)
                continue

            rule_id = issue.get("rule_id")

            cwe = BANDIT_CWE_MAPPING.get(
                rule_id,
                f"CWE-{issue['cwe_id']}" if issue.get("cwe_id") else None
            )

            unified_results.append({
                "source": "Bandit",
                "cwe_id": cwe,
                "rule_id": rule_id,
                "severity": issue.get("severity"),
                "confidence": issue.get("confidence"),
                "line_start": issue.get("line_start"),
                "issue": issue.get("issue"),
                "recommendation": issue.get("recommendation"),
                "more_info": issue.get("more_info")
            })

        # Remove duplicate findings
        final_results = remove_duplicates(unified_results)

        return final_results

    except Exception as e:
        return [{"error": str(e)}]


if __name__ == "__main__":

    file_path = input("Enter Python file path: ")

    results = scan_file(file_path)

    print(json.dumps(results, indent=4))