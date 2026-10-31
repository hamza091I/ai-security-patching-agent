"""Dependency-free JavaScript/TypeScript security detectors.

The implementation is conservative and syntax-agnostic so it works without a
Node parser dependency while still detecting data-flow-lite patterns.
"""
import re
from scanner.contracts import normalize_finding
from scanner.rules.registry import rule_for

RULES = [
    ("CWE-95", "js-eval", r"\beval\s*\(", "eval() executes arbitrary JavaScript.", "Avoid eval and use a safe parser.", "critical"),
    ("CWE-94", "js-new-function", r"\bnew\s+Function\s*\(", "new Function() compiles runtime code.", "Use a safe parser or fixed functions.", "critical"),
    ("CWE-79", "dom-xss", r"\.(?:innerHTML|outerHTML)\s*=|\.insertAdjacentHTML\s*\(", "An HTML sink can introduce DOM XSS.", "Use textContent or a trusted sanitizer.", "high"),
    ("CWE-89", "dynamic-query", r"(?:query|execute)\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_$][\w$]*)", "A database query is built from dynamic input.", "Use parameterized queries.", "high"),
    ("CWE-798", "hardcoded-secret", r"(?:api[_-]?key|secret|password|token)\s*=\s*['\"]", "A credential-like value is hardcoded.", "Use environment variables or a secret manager.", "high"),
    ("CWE-78", "child-process-shell", r"(?:exec|execSync)\s*\(", "A shell command is executed from JavaScript.", "Use spawn with an argument array and shell disabled.", "critical"),
    ("CWE-918", "ssrf", r"(?:axios|fetch|https?\.request)\s*\(\s*(?:req\.|user|input|url)", "A server-side request uses an uncontrolled URL.", "Allowlist destinations before making the request.", "high"),
    ("CWE-601", "open-redirect", r"res\.redirect\s*\(\s*req\.", "Redirect destination is controlled by the request.", "Allowlist redirect destinations.", "medium"),
    ("CWE-942", "cors-wildcard", r"(?:origin|Access-Control-Allow-Origin)\s*:\s*['\"]\*['\"]", "CORS allows every origin.", "Configure an explicit origin allowlist.", "high"),
    ("CWE-693", "missing-security-headers", r"express\.static\s*\(", "Static app setup does not show security headers.", "Use helmet or explicit security headers.", "medium"),
]

def analyze_javascript(code, language="javascript"):
    findings = []
    for cwe, rule, pattern, message, recommendation, severity in RULES:
        if not rule_for(cwe, language):
            continue
        for match in re.finditer(pattern, code, re.I | re.M):
            line = code.count("\n", 0, match.start()) + 1
            findings.append(normalize_finding({"cwe_id": cwe, "rule_id": rule, "type": rule,
                "severity": severity, "confidence": .86, "line": line, "message": message,
                "evidence": code.splitlines()[line-1].strip(), "recommendation": recommendation},
                engine="javascript", language=language))
    return findings
