import ast


class PythonASTAnalyzer(ast.NodeVisitor):

    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):

        # Detect eval() and exec()
        if isinstance(node.func, ast.Name):
            if node.func.id in ["eval", "exec"]:
                self.vulnerabilities.append({
                    "line": node.lineno,
                    "issue": f"Dangerous use of function '{node.func.id}'",
                    "severity": "High",
                    "cwe": "CWE-95"
                })

        # Detect subprocess.call(), run(), Popen() with shell=True
        if isinstance(node.func, ast.Attribute):

            function_name = node.func.attr

            if function_name in ["call", "run", "Popen"]:
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        self.vulnerabilities.append({
                            "line": node.lineno,
                            "issue": "Subprocess called with shell=True",
                            "severity": "High",
                            "cwe": "CWE-78"
                        })

            # Detect os.system()
            if function_name == "system":
                self.vulnerabilities.append({
                    "line": node.lineno,
                    "issue": "Potential OS command injection using os.system()",
                    "severity": "High",
                    "cwe": "CWE-78"
                })

        self.generic_visit(node)


def analyze_code_string(code_string):

    try:
        tree = ast.parse(code_string)

        analyzer = PythonASTAnalyzer()
        analyzer.visit(tree)

        return analyzer.vulnerabilities

    except SyntaxError as e:
        return [{"error": f"Syntax error in code: {e}"}]