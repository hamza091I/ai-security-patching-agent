import ast

# 1. قائمة الدوال الخطيرة التي نريد اكتشافها في الكود
DANGEROUS_FUNCTIONS = {
    "eval": "Critical: Execution of arbitrary code via eval()",
    "exec": "Critical: Execution of arbitrary code via exec()",
    "system": "High: Potential OS Command Injection via os.system()"
}

# 2. كلاس يقوم بالمرور على شجرة الكود (AST Visitor)
class SecurityScanner(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):
        func_name = None
        # استخراج اسم الدالة المستدعاة
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # التحقق إذا كانت الدالة خطيرة
        if func_name in DANGEROUS_FUNCTIONS:
            self.vulnerabilities.append({
                "function": func_name,
                "line": node.lineno,
                "description": DANGEROUS_FUNCTIONS[func_name]
            })

        # الاستمرار في تفقد باقي أجزاء الكود
        self.generic_visit(node)

# 3. دالة فحص الكود
def scan_code(source_code: str):
    tree = ast.parse(source_code)
    scanner = SecurityScanner()
    scanner.visit(tree)
    return scanner.vulnerabilities

# 4. تجربة الفاحص مباشرة
if __name__ == "__main__":
    test_code = """
import os

def calculate(user_input):
    # ثغرة خطيرة
    return eval(user_input)

def execute_cmd(cmd):
    # ثغرة أمر نظام
    os.system(cmd)
"""
    print("--- جارٍ فحص الكود التجريبي ---")
    results = scan_code(test_code)
    
    if results:
        for vuln in results:
            print(f"[!] تم اكتشاف ثغرة في السطر {vuln['line']}: {vuln['function']}")
            print(f"    الوصف: {vuln['description']}")
    else:
        print("[+] الكود آمن ولا يحتوي على ثغرات معروفة.")