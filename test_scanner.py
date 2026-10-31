from scanner.analysis.security_scanner import full_security_scan

# Test code containing two vulnerabilities: eval (detected by AST) and a hardcoded password (detected by Bandit)
fake_vulnerable_code = """
def bad_code():
    user_input = "print('Hello')"
    # Dangerous vulnerability detected by AST
    eval(user_input)
    
    # Hardcoded password vulnerability detected by Bandit
    password = "12345_super_secret_password"
"""

if __name__ == "__main__":
    print("--- Running test code security scan ---")
    results = full_security_scan(fake_vulnerable_code)
    
    print("\n[!] AST Vulnerabilities Results:")
    for vuln in results["ast_vulnerabilities"]:
        print(vuln)
        
    print("\n[!] Bandit Vulnerabilities Results:")
    for vuln in results["bandit_vulnerabilities"]:
        print(vuln)