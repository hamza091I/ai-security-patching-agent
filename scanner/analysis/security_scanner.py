"""Combined scan orchestration with Registry enforcement and deduplication."""
from scanner.analysis.ast_parser import analyze_code_string
from scanner.analysis.bandit_scanner import scan_code as bandit_scan
from scanner.analysis.orchestrator import detect_language
from scanner.analysis.javascript_parser import analyze_javascript
from scanner.analysis.catalog_rules import analyze_catalog
from scanner.rules.registry import filter_findings

def _dedupe(items):
    out, seen = [], set()
    for finding in items:
        key = (finding.get("cwe_id"), finding.get("line_start"), finding.get("line_end"), finding.get("language"))
        if key not in seen:
            seen.add(key)
            out.append(finding)
    return out

def full_security_scan(code, filename="sample.py", engines=None):
    language = detect_language(code, filename)
    engines = set(engines or {"ast", "bandit", "javascript"})
    ast_findings, bandit_findings, javascript_findings = [], [], []
    if language == "python":
        if "ast" in engines:
            ast_findings = analyze_code_string(code)
        if "bandit" in engines:
            bandit_findings = bandit_scan(code)
    elif "javascript" in engines:
        javascript_findings = analyze_javascript(code, language) + analyze_catalog(code, language)
    all_findings = _dedupe(filter_findings(ast_findings + bandit_findings + javascript_findings, language))
    return {"language": language, "ast_findings": ast_findings, "bandit_findings": bandit_findings,
            "javascript_findings": javascript_findings, "all_findings": all_findings}
