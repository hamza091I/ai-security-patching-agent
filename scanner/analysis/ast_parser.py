import ast


class ASTSecurityAnalyzer(ast.NodeVisitor):

  def __init__(self):
    self.vulnerabilities = []

  def analyze(self, code_string: str):
    self.vulnerabilities = []
    try:
      tree = ast.parse(code_string)
      self.visit(tree)
    except SyntaxError as e:
      self.vulnerabilities.append({
          "cwe_id": "SYNTAX",
          "type": "SyntaxError",
          "line": 0,
          "message": str(e),
      })
    return self.vulnerabilities

  def visit_Call(self, node):
    # 1. CWE-95: Eval Injection
    if isinstance(node.func, ast.Name) and node.func.id == "eval":
      self.vulnerabilities.append({
          "cwe_id": "CWE-95",
          "type": "Code Injection",
          "line": node.lineno,
          "message": (
              "Using the eval function allows the execution of unsafe code."
          ),
          "recommendation": (
              "Avoid eval(); use safer parsing alternatives like"
              " ast.literal_eval()."
          ),
      })

    # 2. CWE-78: Command Injection (os.system)
    elif isinstance(node.func, ast.Attribute):
      if (
          isinstance(node.func.value, ast.Name)
          and node.func.value.id == "os"
          and node.func.attr == "system"
      ):
        self.vulnerabilities.append({
            "cwe_id": "CWE-78",
            "type": "Command Injection",
            "line": node.lineno,
            "message": (
                "Using os.system exposes the system to OS command injection."
            ),
            "recommendation": (
                "Use the subprocess module with shell=False and pass arguments"
                " as a list."
            ),
        })

      # 3. CWE-89: SQL Injection (.execute with dynamic strings/f-strings)
      elif node.func.attr == "execute":
        if node.args:
          arg = node.args[0]
          # Check if argument is f-string (JoinedStr) or string concatenation (BinOp)
          if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
            self.vulnerabilities.append({
                "cwe_id": "CWE-89",
                "type": "SQL Injection",
                "line": node.lineno,
                "message": (
                    "SQL query uses dynamic string formatting or concatenation"
                    " without parameterization."
                ),
                "recommendation": (
                    "Use parameterized queries with placeholders (? or %s)"
                    " instead of string formatting."
                ),
            })

      # 4. CWE-502: Insecure Deserialization (pickle.loads / pickle.load)
      elif (
          isinstance(node.func.value, ast.Name)
          and node.func.value.id == "pickle"
          and node.func.attr in ("loads", "load")
      ):
        self.vulnerabilities.append({
            "cwe_id": "CWE-502",
            "type": "Insecure Deserialization",
            "line": node.lineno,
            "message": (
                "Using pickle for loading untrusted data can lead to arbitrary"
                " code execution."
            ),
            "recommendation": (
                "Use safer serialization formats like JSON instead of pickle"
                " for untrusted data."
            ),
        })

    # 5. CWE-22: Path Traversal (open with concatenated paths)
    if isinstance(node.func, ast.Name) and node.func.id == "open":
      if node.args and isinstance(node.args[0], (ast.BinOp, ast.JoinedStr)):
        self.vulnerabilities.append({
            "cwe_id": "CWE-22",
            "type": "Path Traversal",
            "line": node.lineno,
            "message": (
                "Opening files with unvalidated dynamic paths allows path"
                " traversal."
            ),
            "recommendation": (
                "Validate and sanitize file paths using os.path.abspath or"
                " pathlib."
            ),
        })

    self.generic_visit(node)

  def visit_Assign(self, node):
    # 6. CWE-798: Hardcoded Secrets (Detecting hardcoded password/secret assignment)
    for target in node.targets:
      if isinstance(target, ast.Name):
        target_name = target.id.lower()
        if any(
            secret_keyword in target_name
            for secret_keyword in ["password", "secret", "api_key", "token"]
        ):
          if isinstance(node.value, ast.Constant) and isinstance(
              node.value.value, str
          ):
            self.vulnerabilities.append({
                "cwe_id": "CWE-798",
                "type": "Hardcoded Secrets",
                "line": node.lineno,
                "message": (
                    "Hardcoded sensitive credentials detected in code variable."
                ),
                "recommendation": (
                    "Store sensitive keys and passwords in environment"
                    " variables (.env)."
                ),
            })
    self.generic_visit(node)


def analyze_code_string(code_string: str):
  # Helper function to wrap ASTSecurityAnalyzer for external modules like rag_engine.
  analyzer = ASTSecurityAnalyzer()
  return analyzer.analyze(code_string)