import ast

class PythonASTAnalyzer(ast.NodeVisitor):
    """
    AST (Abstract Syntax Tree) Analyzer for Python code.
    Inherits from ast.NodeVisitor to traverse the code structure and detect security issues.
    """
    def __init__(self):
        # List to store all detected vulnerabilities during the analysis
        self.vulnerabilities = []

    def visit_Call(self, node):
        """
        Triggered whenever a function call node is encountered in the AST.
        Checks if the called function is part of a blacklist of dangerous functions (e.g., eval, exec).
        """
        # Check if the function being called is a direct name and matches dangerous functions
        if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']:
            self.vulnerabilities.append({
                'line': node.lineno,
                'issue': f"Dangerous use of function '{node.func.id}' detected.",
                'severity': 'High'
            })
        
        # Continue traversing the child nodes within this call
        self.generic_visit(node)

def analyze_code_string(code_string):
    """
    Wrapper function to parse a raw Python code string into an AST 
    and run the analyzer visitor over it.
    """
    try:
        # Parse the source code string into an Abstract Syntax Tree
        tree = ast.parse(code_string)
        
        # Initialize and run the analyzer
        analyzer = PythonASTAnalyzer()
        analyzer.visit(tree)
        
        return analyzer.vulnerabilities
        
    except SyntaxError as e:
        # Handle syntax errors gracefully without crashing the application
        return [{'error': f"Syntax error in code: {e}"}]