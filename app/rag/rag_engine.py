import sys
import os

# إضافة المسار الرئيسي للمشروع حتى يتعرف بايثون على كافة المجلدات بدون أخطاء
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, "../.."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# استيراد دالة البحث من vector_db الموجود في نفس المجلد
try:
    from app.rag.vector_db import search_security_fix
except ModuleNotFoundError:
    from vector_db import search_security_fix

def simple_ast_scan(code_string: str):
    """فحص الكود لاكتشاف الدوال غير الآمنة"""
    issues = []
    
    if "eval(" in code_string:
        issues.append({
            "issue": "Arbitrary code execution via eval()",
            "type": "eval",
            "cwe": "CWE-95"
        })
        
    if "exec(" in code_string:
        issues.append({
            "issue": "Dynamic code execution via exec()",
            "type": "exec",
            "cwe": "CWE-95"
        })

    if "password" in code_string.lower() and "=" in code_string:
        issues.append({
            "issue": "Hardcoded password detected",
            "type": "password",
            "cwe": "CWE-798"
        })

    return issues

def analyze_and_retrieve_fix(code_string: str):
    """
    الدالة المطلوبة في patcher.py
    """
    detected_issues = simple_ast_scan(code_string)
    enriched_vulnerabilities = []

    for issue in detected_issues:
        # البحث في ChromaDB عن حل مقترح
        search_result = search_security_fix(issue["issue"], n_results=1)

        metadata = {}
        if search_result and search_result.get("metadatas") and search_result["metadatas"][0]:
            metadata = search_result["metadatas"][0][0]

        enriched_vulnerabilities.append({
            "detected_issue": {
                "issue": issue["issue"],
                "type": issue["type"]
            },
            "rag_suggested_fix": {
                "cwe": metadata.get("cwe", issue["cwe"]),
                "fix": metadata.get("function", "Use ast.literal_eval()") if issue["type"] == "eval" else "Use environment variables"
            }
        })

    return {
        "enriched_vulnerabilities": enriched_vulnerabilities
    }

if __name__ == "__main__":
    # فحص عمل الدالة واسترجاع الترقيع
    sample_code = "user_input = eval(input('command: '))"
    output = analyze_and_retrieve_fix(sample_code)
    print("\n[+] تم الفحص والاسترجاع بنجاح:")
    print(output)