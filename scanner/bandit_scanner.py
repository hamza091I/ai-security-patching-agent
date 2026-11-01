import subprocess
import json
import sys


def run_bandit_scan(file_path):
    """
    Run Bandit security analysis on a Python file
    and return vulnerabilities in a unified format.
    """

    try:
        command = [
            sys.executable,
            "-m",
            "bandit",
            "-f",
            "json",
            file_path
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )

        if not result.stdout:
            return [{
                "error": result.stderr or "Bandit returned no output"
            }]

        data = json.loads(result.stdout)
        vulnerabilities = []

        for issue in data.get("results", []):

            cwe = issue.get("issue_cwe") or {}

            vulnerabilities.append({
                "cwe_id": cwe.get("id"),
                "rule_id": issue.get("test_id"),
                "severity": issue.get("issue_severity"),
                "confidence": issue.get("issue_confidence"),
                "line_start": issue.get("line_number"),
                "recommendation": (
                    "Review and remediate: "
                    + issue.get("issue_text", "Security issue detected")
                ),
                "issue": issue.get("issue_text"),
                "more_info": issue.get("more_info")
            })

        return vulnerabilities

    except subprocess.TimeoutExpired:
        return [{"error": "Bandit scan timed out"}]

    except json.JSONDecodeError:
        return [{"error": "Invalid JSON returned by Bandit"}]

    except Exception as e:
        return [{"error": str(e)}]



if __name__ == "__main__":
    file_path = input("Enter Python file path: ")

    results = run_bandit_scan(file_path)

    print(json.dumps(results, indent=4))        