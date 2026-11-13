"""Optional Bandit adapter returning the shared Finding contract."""

import json
import logging
import os
import subprocess
import sys
import tempfile
from functools import lru_cache

from scanner.contracts import normalize_finding

logger = logging.getLogger("security_platform")

BANDIT_CWE = {
    "B101": "CWE-489",
    "B102": "CWE-78",
    "B307": "CWE-95",
    "B301": "CWE-502",
    "B602": "CWE-78",
    "B603": "CWE-78",
    "B604": "CWE-78",
    "B605": "CWE-78",
    "B608": "CWE-89",
    "B105": "CWE-798",
    "B106": "CWE-798",
    "B107": "CWE-798",
    "B324": "CWE-327",
}
CONFIDENCE = {"HIGH": 0.95, "MEDIUM": 0.75, "LOW": 0.5}


@lru_cache(maxsize=1)
def _bandit_command():
    """Prefer the interpreter running Django so virtualenvs work on every OS."""
    try:
        probe = subprocess.run(
            [sys.executable, "-m", "bandit", "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if probe.returncode == 0:
            return [sys.executable, "-m", "bandit"]
    except (OSError, subprocess.SubprocessError):
        pass
    return ["bandit"]


def run_bandit_scan(file_path):
    command = _bandit_command() + ["-f", "json", "-q", file_path]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout or "{}")
    except FileNotFoundError:
        logger.info("bandit_not_installed")
        return []
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        logger.warning("bandit_scan_failed: %s", type(exc).__name__)
        return []
    findings = []
    for issue in data.get("results", []):
        test_id = issue.get("test_id", "bandit-unknown")
        raw = {
            "cwe_id": BANDIT_CWE.get(test_id, "UNKNOWN"),
            "rule_id": test_id,
            "type": "Bandit: " + test_id,
            "severity": str(issue.get("issue_severity", "medium")).lower(),
            "confidence": CONFIDENCE.get(str(issue.get("issue_confidence", "MEDIUM")).upper(), 0.75),
            "line": issue.get("line_number", 0),
            "message": issue.get("issue_text", ""),
            "evidence": issue.get("code", ""),
            "recommendation": "Review and remediate this Bandit finding.",
        }
        findings.append(normalize_finding(raw, engine="bandit", language="python"))
    return findings


def scan_code(code):
    fd, path = tempfile.mkstemp(suffix=".py", text=True)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(code)
        return run_bandit_scan(path)
    finally:
        if os.path.exists(path):
            os.unlink(path)
