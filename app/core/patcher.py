import os
from scanner.rag.rag_engine import analyze_and_retrieve_fix

class CodePatcher:
    """
    CodePatcher class responsible for taking vulnerable code,
    analyzing it via RAG, and generating the safe patched version.
    """
    
    def __init__(self, code_string):
        self.code_string = code_string

    def generate_patch(self):
        """
        Runs the security scan and RAG retrieval, then constructs 
        a structured patching report containing the safe code structure.
        """
        # 1. Run analysis and retrieve fixes from RAG Knowledge Base
        scan_and_rag_results = analyze_and_retrieve_fix(self.code_string)
        
        vulnerabilities_found = scan_and_rag_results.get("enriched_vulnerabilities", [])
        
        if not vulnerabilities_found:
            return {
                "status": "Secure",
                "message": "No vulnerabilities detected. No patch needed.",
                "patched_code": self.code_string
            }
            
        # 2. Simulate patch application based on RAG recommendations
        patched_code = self.code_string
        applied_fixes = []
        
        for item in vulnerabilities_found:
            issue = item.get("detected_issue", {})
            fix_meta = item.get("rag_suggested_fix", {})
            
            # Handle if fix_meta is returned as a list from chroma db
            if isinstance(fix_meta, list):
                fix_meta = fix_meta[0] if fix_meta else {}
            
            issue_text = issue.get("issue", "")
            
            # If eval() vulnerability is detected, apply safety patch recommendation
            if "eval" in issue_text.lower():
                patched_code = patched_code.replace("eval(", "# SECURE PATCH: Replaced unsafe eval\nast.literal_eval(")
                applied_fixes.append({
                    "cwe": fix_meta.get("cwe", "CWE-95") if isinstance(fix_meta, dict) else "CWE-95",
                    "fix_applied": fix_meta.get("fix", "Use ast.literal_eval()") if isinstance(fix_meta, dict) else "Use ast.literal_eval()"
                })
            
            # If hardcoded password is found
            elif "password" in issue_text.lower():
                patched_code = patched_code.replace("= \"", "= os.getenv('SECURE_SECRET') # SECURE PATCH: Moved to env variable\n# ")
                applied_fixes.append({
                    "cwe": fix_meta.get("cwe", "CWE-798") if isinstance(fix_meta, dict) else "CWE-798",
                    "fix_applied": fix_meta.get("fix", "Use environment variables") if isinstance(fix_meta, dict) else "Use environment variables"
                })

        return {
            "status": "Patched",
            "original_code": self.code_string,
            "patched_code": patched_code,
            "applied_fixes": applied_fixes
        }

def run_patcher_on_code(code_string):
    """
    Helper function to initialize the patcher and return results.
    """
    patcher = CodePatcher(code_string)
    return patcher.generate_patch()