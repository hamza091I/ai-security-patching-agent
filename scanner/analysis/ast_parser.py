"""Deterministic Python AST security analyzer."""
import ast
from scanner.contracts import normalize_finding
from scanner.rules.registry import rule_for

RULES = {
    "CWE-95": ("Code Injection", "critical", "Avoid eval(); use ast.literal_eval() or an explicit parser.", "eval-injection"),
    "CWE-78": ("Command Injection", "critical", "Use subprocess.run() with an argument list and shell=False.", "command-injection"),
    "CWE-89": ("SQL Injection", "high", "Use parameterized queries.", "sql-dynamic-query"),
    "CWE-502": ("Insecure Deserialization", "critical", "Use JSON or a safe schema instead of pickle for untrusted data.", "pickle-load"),
    "CWE-22": ("Path Traversal", "high", "Constrain paths to an allowed directory and validate the resolved path.", "dynamic-open-path"),
    "CWE-798": ("Hardcoded Secret", "high", "Load secrets from a secret manager or environment variable.", "hardcoded-secret"),
    "CWE-327": ("Weak Cryptography", "medium", "Use an approved modern algorithm or password KDF.", "weak-hash"),
    "CWE-295": ("Improper Certificate Validation", "high", "Keep TLS certificate verification enabled.", "tls-verify-disabled"),
    "CWE-352": ("Cross-Site Request Forgery", "high", "Protect state-changing endpoints with CSRF tokens.", "csrf-missing-protection"),
    "CWE-434": ("Unrestricted Upload", "high", "Validate and constrain uploaded filenames and content.", "unrestricted-upload"),
    "CWE-918": ("Server-Side Request Forgery", "high", "Allowlist destinations before making server-side requests.", "server-side-request-forgery"),
    "CWE-611": ("XML External Entity", "high", "Use defusedxml and disable external entities.", "xml-external-entity"),
    "CWE-732": ("Unsafe File Permissions", "medium", "Use least-privilege file permissions.", "unsafe-file-mode"),
    "CWE-489": ("Debug Code", "low", "Disable debug mode outside local development.", "debug-enabled"),
}

class ASTSecurityAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []
        self.dynamic_values = set()

    def _add(self, node, cwe, evidence):
        if not rule_for(cwe, "python"):
            return
        title, severity, recommendation, rule_id = RULES[cwe]
        self.vulnerabilities.append({"cwe_id": cwe, "rule_id": rule_id, "type": title,
            "severity": severity, "confidence": .95, "line": getattr(node, "lineno", 0),
            "line_end": getattr(node, "end_lineno", getattr(node, "lineno", 0)),
            "message": evidence, "evidence": evidence, "recommendation": recommendation})

    def analyze(self, code):
        self.vulnerabilities = []
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return [normalize_finding({"cwe_id":"SYNTAX", "rule_id":"python-syntax", "type":"SyntaxError",
                "severity":"critical", "confidence":1.0, "line":exc.lineno or 0, "message":str(exc),
                "evidence":str(exc), "recommendation":"Fix the syntax error before security analysis."}, engine="ast", language="python")]
        self.visit(tree)
        return [normalize_finding(item, engine="ast", language="python") for item in self.vulnerabilities]

    @staticmethod
    def _is_dynamic(node):
        return isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Name))

    def visit_Assign(self, node):
        if isinstance(node.value, (ast.JoinedStr, ast.BinOp)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.dynamic_values.add(target.id)
        for target in node.targets:
            if isinstance(target, ast.Name) and any(k in target.id.lower() for k in ("password", "secret", "api_key", "apikey", "token")):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and node.value.value:
                    self._add(node, "CWE-798", "A credential-like variable contains a hardcoded string.")
        self.generic_visit(node)

    def visit_Call(self, node):
        f = node.func
        if isinstance(f, ast.Name) and f.id == "save_upload" and node.args:
            self._add(node, "CWE-434", "Uploaded filename is passed to storage without visible validation.")
        if isinstance(f, ast.Name) and f.id == "eval":
            self._add(node, "CWE-95", "eval() executes input as Python code.")
        if isinstance(f, ast.Name) and f.id == "open" and node.args and self._is_dynamic(node.args[0]):
            self._add(node, "CWE-22", "open() receives a dynamically constructed path.")
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            pair = (f.value.id, f.attr)
            if pair == ("os", "system"):
                self._add(node, "CWE-78", "os.system() executes a shell command and may allow command injection.")
            elif pair in (("pickle", "load"), ("pickle", "loads")):
                self._add(node, "CWE-502", "pickle.load(s) can execute attacker-controlled objects.")
            elif f.attr in {"execute", "executemany"} and node.args and self._is_dynamic(node.args[0]):
                self._add(node, "CWE-89", "SQL execute() receives a dynamically constructed query.")
            elif pair in (("hashlib", "md5"), ("hashlib", "sha1")):
                self._add(node, "CWE-327", f"Weak hash algorithm {f.attr}() is not suitable for security-sensitive use.")
            elif pair == ("requests", "get"):
                if any(k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False for k in node.keywords):
                    self._add(node, "CWE-295", "TLS certificate verification is disabled.")
                elif node.args and isinstance(node.args[0], ast.Name):
                    self._add(node, "CWE-918", "requests.get() receives a variable URL without an allowlist.")
            elif f.attr == "parse" and f.value.id in {"etree", "ET", "ElementTree"}:
                self._add(node, "CWE-611", "XML parsing may resolve external entities; use defusedxml.")
            elif (f.value.id, f.attr) == ("app", "run") and any(k.arg == "debug" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                self._add(node, "CWE-489", "Application debug mode is enabled.")
            elif pair == ("os", "chmod") and len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and node.args[1].value == 0o777:
                self._add(node, "CWE-732", "File permissions are set to world-writable mode 0777.")
        if isinstance(f, ast.Attribute) and f.attr in {"run", "call", "Popen"} and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
            self._add(node, "CWE-78", "subprocess executes with shell=True.")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        route = any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "route" for d in node.decorator_list)
        if route and not any(isinstance(d, ast.Name) and d.id in {"csrf_protect", "csrf_exempt"} for d in node.decorator_list):
            self._add(node, "CWE-352", "A routed endpoint has no visible CSRF protection.")
        self.generic_visit(node)

def analyze_code_string(code):
    return ASTSecurityAnalyzer().analyze(code)
