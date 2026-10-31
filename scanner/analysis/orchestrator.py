from scanner.analysis.ast_parser import analyze_code_string
from scanner.analysis.javascript_parser import analyze_javascript
from scanner.analysis.catalog_rules import analyze_catalog
def detect_language(code,filename=""):
    n=filename.lower()
    if n.endswith((".js",".jsx")): return "javascript"
    if n.endswith((".ts",".tsx")): return "typescript"
    return "python"
def deduplicate_findings(findings):
    out=[]; seen=set()
    for f in findings:
        key=(f.get("cwe_id"),f.get("line_start"),f.get("language"))
        if key not in seen: seen.add(key); out.append(f)
    return out
def scan_code(code,filename=""):
    lang=detect_language(code,filename); findings=(analyze_javascript(code,lang) + analyze_catalog(code,lang)) if lang in {"javascript","typescript"} else (analyze_code_string(code) + analyze_catalog(code,"python"))
    return {"language":lang,"findings":deduplicate_findings(findings)}
