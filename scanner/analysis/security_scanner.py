from scanner.analysis.ast_parser import analyze_code_string
from scanner.analysis.bandit_scanner import run_bandit_scan
import tempfile
import os

def full_security_scan(code_string):
    """
    This function combines both AST analysis and Bandit scanning together,
    and returns a comprehensive report of all vulnerabilities detected in the code.
    """
    # 1. Perform AST analysis directly from the code string
    ast_results = analyze_code_string(code_string)
    
    # 2. Bandit tool requires an actual file to read, so we create a temporary file
    bandit_results = []
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode="w", encoding="utf-8") as temp_file:
            temp_file.write(code_string)
            temp_file_path = temp_file.name
        
        # Run Bandit scan on the temporary file
        bandit_results = run_bandit_scan(temp_file_path)
        
    finally:
        # Delete the temporary file afterwards to avoid leaving random junk files
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            
    # 3. Combine the results into a single unified report
    return {
        "ast_vulnerabilities": ast_results,
        "bandit_vulnerabilities": bandit_results
    }