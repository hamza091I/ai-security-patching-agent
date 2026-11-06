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

# --- Week 1: detection variants -------------------------------------------
# Fully qualified call names (import aliases are resolved, see _qualname).
EVAL_CALLS = {"eval", "exec", "builtins.eval", "builtins.exec"}
OS_COMMAND_CALLS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_call", "check_output"}
SUBPROCESS_QUALNAMES = {"subprocess." + name for name in SUBPROCESS_FUNCS}

# Secret names are matched by word, so "tokenizer" is ignored but "api_key",
# "apiKey", "access_token" and "SECRET_KEY" are reported.
SECRET_WORDS = ("password", "passwd", "secret", "apikey", "privatekey")
NON_SECRET_SUFFIXES = ("_field", "_label", "_name", "_type", "_url", "_path", "_header", "_env", "_prompt")


def _is_secret_name(name):
    lowered = str(name).lower()
    if lowered.endswith(NON_SECRET_SUFFIXES):
        return False
    compact = lowered.replace("_", "").replace("-", "")
    if any(word in compact for word in SECRET_WORDS):
        return True
    return "token" in lowered.split("_") or compact.endswith("token")


class ASTSecurityAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []
        self.dynamic_values = set()   # names assigned from f-strings, concatenation, % or .format()
        self.constant_values = set()  # names assigned from a plain string literal
        self.aliases = {}             # import aliases: {"sp": "subprocess", "run": "subprocess.run"}

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
        self.dynamic_values = set()
        self.constant_values = set()
        self.aliases = {}
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return [normalize_finding({"cwe_id":"SYNTAX", "rule_id":"python-syntax", "type":"SyntaxError",
                "severity":"critical", "confidence":1.0, "line":exc.lineno or 0, "message":str(exc),
                "evidence":str(exc), "recommendation":"Fix the syntax error before security analysis."}, engine="ast", language="python")]
        self.visit(tree)
        return [normalize_finding(item, engine="ast", language="python") for item in self.vulnerabilities]

    # ---- helpers ---------------------------------------------------------
    @staticmethod
    def _is_dynamic(node):
        return isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Name))

    @staticmethod
    def _all_constants(node):
        return all(isinstance(n, (ast.Constant, ast.BinOp, ast.operator)) for n in ast.walk(node))

    def _is_dynamic_string(self, node):
        """True for f"..{x}", "a" + x, "a %s" % x and "a {}".format(x)."""
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(part, ast.FormattedValue) for part in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return not self._all_constants(node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
        return False

    def _sql_is_dynamic(self, call):
        query = call.args[0]
        has_params = len(call.args) > 1 or any(k.arg in {"params", "parameters", "args"} for k in call.keywords)
        if self._is_dynamic_string(query):
            return True  # parameters do not make an already-built string safe
        if isinstance(query, ast.Name):
            if query.id in self.dynamic_values:
                return True
            # Unknown variable: report it only when no parameters are passed (conservative).
            return not has_params and query.id not in self.constant_values
        return False

    def _qualname(self, func):
        """Return a dotted call name such as 'os.system', resolving import aliases."""
        parts = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if not isinstance(func, ast.Name):
            return None
        parts.append(self.aliases.get(func.id, func.id))
        return ".".join(reversed(parts))

    @staticmethod
    def _shell_enabled(call):
        return any(k.arg == "shell" and isinstance(k.value, ast.Constant) and bool(k.value.value) for k in call.keywords)

    def _check_secret(self, name, value, node):
        if name and _is_secret_name(name) and isinstance(value, ast.Constant) \
                and isinstance(value.value, str) and value.value:
            self._add(node, "CWE-798", "A credential-like variable contains a hardcoded string.")

    def _track_value(self, targets, value):
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            self.dynamic_values.discard(target.id)
            self.constant_values.discard(target.id)
            if self._is_dynamic_string(value):
                self.dynamic_values.add(target.id)
            elif isinstance(value, ast.Constant) and isinstance(value.value, str):
                self.constant_values.add(target.id)

    # ---- visitors --------------------------------------------------------
    def visit_Import(self, node):
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and not node.level:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = node.module + "." + alias.name
        self.generic_visit(node)

    def visit_Assign(self, node):
        self._track_value(node.targets, node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._check_secret(target.id, node.value, node)
            elif isinstance(target, ast.Attribute):
                self._check_secret(target.attr, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._track_value([node.target], node.value)
            if isinstance(node.target, ast.Name):
                self._check_secret(node.target.id, node.value, node)
            elif isinstance(node.target, ast.Attribute):
                self._check_secret(node.target.attr, node.value, node)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add) \
                and not isinstance(node.value, ast.Constant):
            self.dynamic_values.add(node.target.id)  # query += user_input
            self.constant_values.discard(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        f = node.func
        qual = self._qualname(f)
        for keyword in node.keywords:  # connect(password="...")
            self._check_secret(keyword.arg, keyword.value, node)
        if isinstance(f, ast.Name) and f.id == "save_upload" and node.args:
            self._add(node, "CWE-434", "Uploaded filename is passed to storage without visible validation.")
        if qual in EVAL_CALLS:
            self._add(node, "CWE-95", qual.split(".")[-1] + "() executes input as Python code.")
        if isinstance(f, ast.Name) and f.id == "open" and node.args and self._is_dynamic(node.args[0]):
            self._add(node, "CWE-22", "open() receives a dynamically constructed path.")
        if qual in OS_COMMAND_CALLS:
            self._add(node, "CWE-78", qual + "() executes a shell command and may allow command injection.")
        if isinstance(f, ast.Attribute) and f.attr in {"execute", "executemany"} and node.args and self._sql_is_dynamic(node):
            self._add(node, "CWE-89", "SQL execute() receives a dynamically constructed query.")
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            pair = (f.value.id, f.attr)
            if pair in (("pickle", "load"), ("pickle", "loads")):
                self._add(node, "CWE-502", "pickle.load(s) can execute attacker-controlled objects.")
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
        # subprocess with shell enabled; shell=False with an argument list is not reported.
        is_subprocess = (f.attr in SUBPROCESS_FUNCS) if isinstance(f, ast.Attribute) else (qual in SUBPROCESS_QUALNAMES)
        if is_subprocess and self._shell_enabled(node):
            self._add(node, "CWE-78", "subprocess executes with shell=True.")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        route = any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "route" for d in node.decorator_list)
        if route and not any(isinstance(d, ast.Name) and d.id in {"csrf_protect", "csrf_exempt"} for d in node.decorator_list):
            self._add(node, "CWE-352", "A routed endpoint has no visible CSRF protection.")
        self.generic_visit(node)

def analyze_code_string(code):
    return ASTSecurityAnalyzer().analyze(code)
