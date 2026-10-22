import ast

class ASTSecurityAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):
        # Check for the dangerous eval function usage (CWE-95)
        if isinstance(node.func, ast.Name) and node.func.id == 'eval':
            self.vulnerabilities.append({
                "cwe_id": "CWE-95",
                "type": "Code Injection",
                "line": node.lineno,
                "message": "Using the eval function allows the execution of unsafe code."
            })
        
        # Check for os.system usage leading to command injection (CWE-78)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os' and node.func.attr == 'system':
                self.vulnerabilities.append({
                    "cwe_id": "CWE-78",
                    "type": "Command Injection",
                    "line": node.lineno,
                    "message": "Using os.system exposes the system to OS command injection."
                })
        
        self.generic_visit(node)

def run_ast_analysis(code_str: str):
    """
    Function to run static AST analysis and return detected vulnerabilities.
    """
    try:
        tree = ast.parse(code_str)
        analyzer = ASTSecurityAnalyzer()
        analyzer.visit(tree)
        return {"has_error": False, "vulnerabilities": analyzer.vulnerabilities}
    except SyntaxError as e:
        return {"has_error": True, "message": f"Syntax Error: {e}"}