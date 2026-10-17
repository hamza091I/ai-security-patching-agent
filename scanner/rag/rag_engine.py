from scanner.rag.vector_db import initialize_knowledge_base, query_knowledge_base
from scanner.analysis.security_scanner import full_security_scan

# Initialize the knowledge base as soon as the module runs
initialize_knowledge_base()

def analyze_and_retrieve_fix(code_string):
    """
    This function:
    1. Scans the code and detects vulnerabilities (AST + Bandit).
    2. Takes the vulnerability description and searches for a ready-made fix via RAG (ChromaDB).
    """
    # 1. Comprehensive security scan
    scan_results = full_security_scan(code_string)
    
    all_issues = []
    all_issues.extend(scan_results.get("ast_vulnerabilities", []))
    all_issues.extend(scan_results.get("bandit_vulnerabilities", []))
    
    enriched_results = []

    # 2. For each detected vulnerability, query the RAG for the appropriate fix
    for issue in all_issues:
        # Formulate the search text based on the vulnerability description
        issue_text = issue.get("issue") or str(issue)
        
        # Retrieve the closest solution from ChromaDB (RAG Retrieval)
        rag_match = query_knowledge_base(query_text=issue_text, n_results=1)
        
        # Combine the detected vulnerability with the retrieved suggested fix
        enriched_results.append({
            "detected_issue": issue,
            "rag_suggested_fix": rag_match.get("metadatas", [{}])[0] if rag_match.get("metadatas") else "No direct fix found"
        })
        
    return {
        "code_scanned": code_string,
        "enriched_vulnerabilities": enriched_results
    }