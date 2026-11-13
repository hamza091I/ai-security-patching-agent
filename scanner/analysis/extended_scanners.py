"""Deterministic lightweight scanners that complement AST/Bandit.

They are intentionally dependency-free and produce the shared finding contract.
External production scanners can be plugged in behind the same functions.
"""
import re
from scanner.contracts import normalize_finding


def _finding(cwe, rule, message, line, severity="MEDIUM", recommendation="Review this finding.", language="text"):
    return normalize_finding({"cwe_id": cwe, "rule_id": rule, "type": rule, "severity": severity.lower(), "line": line, "message": message, "evidence": message, "recommendation": recommendation}, engine="extended", language=language)


def scan_secrets(code, filename=""):
    patterns = [
        (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['\"][A-Z0-9/+=]{12,}", "secret-cloud-key"),
        (r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "hardcoded-secret"),
        (r"gh[pousr]_[A-Za-z0-9_]{20,}", "github-token"),
    ]
    findings = []
    for number, line in enumerate(code.splitlines(), 1):
        for pattern, rule in patterns:
            if re.search(pattern, line) and not re.search(r"(?i)(example|placeholder|replace[-_ ]with|os\.getenv|environ)", line):
                findings.append(_finding("CWE-798", rule, "Potential hardcoded credential detected.", number, "HIGH", "Move the secret to a vault or environment variable."))
    return findings


def scan_dependencies(code, filename=""):
    findings = []
    for number, line in enumerate(code.splitlines(), 1):
        if re.search(r"(?i)(pip install|npm install|curl .*\|.*sh|wget .*\|.*sh)", line):
            findings.append(_finding("CWE-494", "unverified-dependency", "Dependency or script is fetched without a pinned integrity check.", number, "MEDIUM", "Pin versions and verify checksums before execution."))
    return findings


def scan_iac(code, filename=""):
    findings = []
    for number, line in enumerate(code.splitlines(), 1):
        if re.search(r"(?i)(privileged:\s*true|0\.0\.0\.0/0|publicly_accessible:\s*true)", line):
            findings.append(_finding("CWE-284", "insecure-infrastructure", "Infrastructure configuration exposes a privileged or public resource.", number, "HIGH", "Restrict the resource to least privilege and private networks."))
    return findings


def scan_container(code, filename=""):
    findings = []
    for number, line in enumerate(code.splitlines(), 1):
        if re.search(r"(?i)^\s*USER\s+root\s*$", line) or re.search(r"(?i)--privileged", line):
            findings.append(_finding("CWE-250", "container-root", "Container runs with excessive privileges.", number, "HIGH", "Use a non-root user and drop unnecessary capabilities."))
    return findings


def scan_extended(code, filename=""):
    return scan_secrets(code, filename) + scan_dependencies(code, filename) + scan_iac(code, filename) + scan_container(code, filename)
