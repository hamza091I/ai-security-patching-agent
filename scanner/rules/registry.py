"""Canonical allow-list for the security scanner.

The registry is deliberately data-only: detectors produce findings, while this
module defines which CWE/rules are in scope for the product.
"""

RULE_REGISTRY = {
    "CWE-22": {"title": "Path Traversal", "languages": {"python", "javascript", "typescript"}, "severity": "high"},
    "CWE-78": {"title": "Command Injection", "languages": {"python", "javascript", "typescript"}, "severity": "critical"},
    "CWE-79": {"title": "Cross-Site Scripting", "languages": {"javascript", "typescript"}, "severity": "high"},
    "CWE-89": {"title": "SQL Injection", "languages": {"python", "javascript", "typescript"}, "severity": "high"},
    "CWE-95": {"title": "Code Injection", "languages": {"python", "javascript", "typescript"}, "severity": "critical"},
    "CWE-295": {"title": "Improper Certificate Validation", "languages": {"python"}, "severity": "high"},
    "CWE-327": {"title": "Weak Cryptography", "languages": {"python", "javascript", "typescript"}, "severity": "medium"},
    "CWE-352": {"title": "Cross-Site Request Forgery", "languages": {"python", "javascript", "typescript"}, "severity": "high"},
    "CWE-434": {"title": "Unrestricted Upload", "languages": {"python", "javascript", "typescript"}, "severity": "high"},
    "CWE-489": {"title": "Debug Code", "languages": {"python", "javascript", "typescript"}, "severity": "low"},
    "CWE-502": {"title": "Insecure Deserialization", "languages": {"python", "javascript", "typescript"}, "severity": "critical"},
    "CWE-611": {"title": "XML External Entity", "languages": {"python", "javascript", "typescript"}, "severity": "high"},
    "CWE-732": {"title": "Unsafe File Permissions", "languages": {"python"}, "severity": "medium"},
    "CWE-798": {"title": "Hardcoded Secret", "languages": {"python", "javascript", "typescript"}, "severity": "high"},
    "CWE-918": {"title": "Server-Side Request Forgery", "languages": {"python", "javascript", "typescript"}, "severity": "high"},
}

# The catalog contributes the remaining in-scope CWE definitions. Importing it
# is avoided here to keep the registry dependency-free and usable by tooling.
_CATALOG_CWES = {
    "CWE-117":"Log Injection", "CWE-134":"Format String Injection", "CWE-185":"Incorrect Regular Expression",
    "CWE-200":"Sensitive Information Exposure", "CWE-209":"Information Exposure Through Error Messages",
    "CWE-256":"Plaintext Password Storage", "CWE-259":"Hard-coded Password", "CWE-269":"Improper Privilege Management",
    "CWE-284":"Improper Access Control", "CWE-285":"Improper Authorization", "CWE-287":"Improper Authentication",
    "CWE-288":"Authentication Bypass", "CWE-306":"Missing Authentication", "CWE-307":"Brute Force",
    "CWE-311":"Missing Encryption", "CWE-312":"Cleartext Storage", "CWE-319":"Cleartext Transmission",
    "CWE-321":"Hard-coded Cryptographic Key", "CWE-326":"Inadequate Encryption Strength", "CWE-330":"Insufficient Randomness",
    "CWE-338":"Weak PRNG", "CWE-347":"Improper Signature Verification", "CWE-359":"Privacy Violation",
    "CWE-362":"Improper Synchronization", "CWE-367":"TOCTOU Race Condition", "CWE-369":"Divide by Zero",
    "CWE-377":"Insecure Temporary File", "CWE-378":"Insecure Temporary File Permissions", "CWE-379":"Insecure Temporary Directory",
    "CWE-400":"Uncontrolled Resource Consumption", "CWE-401":"Memory Leak", "CWE-409":"Compression Bomb",
    "CWE-425":"Direct Request Attack", "CWE-427":"Uncontrolled Search Path", "CWE-470":"Unsafe Reflection",
    "CWE-471":"Mutable Data Assumption", "CWE-497":"Exposure of System Data", "CWE-494":"Download Without Integrity",
    "CWE-522":"Insufficiently Protected Credentials", "CWE-532":"Sensitive Data in Logs", "CWE-552":"Externally Accessible Files",
    "CWE-565":"Reliance on Cookies", "CWE-598":"Sensitive Data in URL", "CWE-601":"Open Redirect",
    "CWE-613":"Insufficient Session Expiration", "CWE-614":"Insecure Cookie", "CWE-620":"Unverified Password Change",
    "CWE-639":"Authorization Bypass Through User-Controlled Key", "CWE-643":"XPath Injection", "CWE-668":"Exposure to Wrong Sphere",
    "CWE-693":"Protection Mechanism Failure", "CWE-703":"Improper Exception Handling", "CWE-704":"Incorrect Type Conversion",
    "CWE-707":"Improper Neutralization", "CWE-749":"Exposed Dangerous Method", "CWE-770":"Allocation Without Limits",
    "CWE-776":"XML Entity Expansion", "CWE-778":"Insufficient Logging", "CWE-779":"Logging Sensitive Data",
    "CWE-787":"Out-of-bounds Write", "CWE-789":"Uncontrolled Memory Allocation", "CWE-862":"Missing Authorization",
    "CWE-863":"Incorrect Authorization", "CWE-915":"Mass Assignment", "CWE-922":"Insecure Storage",
    "CWE-939":"Weak Authentication", "CWE-942":"Permissive CORS", "CWE-943":"NoSQL Injection",
    "CWE-1004":"Sensitive Cookie Without HttpOnly", "CWE-1021":"Clickjacking", "CWE-1275":"Insecure SameSite Cookie",
    "CWE-1321":"Prototype Pollution", "CWE-1333":"Regular Expression DoS", "CWE-1336":"Template Injection",
    "CWE-1395":"Dependency Confusion", "CWE-1426":"Insecure CORS Policy", "CWE-1429":"Improper Redirect Validation",
    "CWE-1446":"Sensitive Data in Local Storage", "CWE-1447":"HTML/Markdown Injection", "CWE-1448":"Insecure Child Process",
}
for cwe, title in _CATALOG_CWES.items():
    RULE_REGISTRY.setdefault(cwe, {"title": title, "languages": {"python", "javascript", "typescript"}, "severity": "medium"})

for cwe, title in {
    "CWE-434": "Unrestricted Upload", "CWE-502": "Insecure Deserialization",
    "CWE-611": "XML External Entity", "CWE-918": "Server-Side Request Forgery",
    "CWE-943": "NoSQL Injection",
}.items():
    RULE_REGISTRY.setdefault(cwe, {"title": title, "languages": {"python", "javascript", "typescript"}, "severity": "high"})

for cwe, title in {
    "CWE-1104": "Unmaintained Third-Party Dependency", "CWE-1333": "Inefficient Regular Expression",
    "CWE-1336": "Server-Side Template Injection", "CWE-1395": "Dependency Confusion",
    "CWE-1426": "Insecure CORS Policy Configuration",
}.items():
    RULE_REGISTRY.setdefault(cwe, {"title": title, "languages": {"python", "javascript", "typescript"}, "severity": "medium"})

for cwe, title in {
    "CWE-215": "Information Exposure Through Debug Information", "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-276": "Incorrect Default Permissions", "CWE-521": "Weak Password Requirements",
}.items():
    RULE_REGISTRY.setdefault(cwe, {"title": title, "languages": {"python", "javascript", "typescript"}, "severity": "medium"})

# Every entry has a stable machine-readable identity and detector name.
for cwe_id, rule in RULE_REGISTRY.items():
    rule.setdefault("rule_id", cwe_id.lower().replace("-", "-") + "-detector")
    rule.setdefault("detector", "ast" if "python" in rule["languages"] else "catalog")

SUPPORTED_CWES = frozenset(RULE_REGISTRY)

def rule_for(cwe_id, language=None):
    rule = RULE_REGISTRY.get(cwe_id)
    if rule is None or (language and language not in rule["languages"]):
        return None
    return rule

def is_supported(cwe_id, language=None):
    return rule_for(cwe_id, language) is not None

def filter_findings(findings, language=None):
    return [f for f in findings if is_supported(str(f.get("cwe_id", "")), language or f.get("language")) or f.get("cwe_id") == "SYNTAX"]
