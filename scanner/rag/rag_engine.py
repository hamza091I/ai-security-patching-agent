import os
import chromadb
from sentence_transformers import SentenceTransformer
from scanner.analysis.ast_parser import analyze_code_string

class SecurityRAGEngine:
    def __init__(self):
        # Initialize Sentence Transformer model for embeddings
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Initialize ChromaDB persistent client
        db_path = os.path.join(os.getcwd(), 'chroma_db')
        self.client = chromadb.PersistentClient(path=db_path)
        
        # Get or create the vector collection
        self.collection = self.client.get_or_create_collection(name="security_knowledge_base")

def analyze_and_retrieve_fix(code_string):
    """
    This function:
    1. Scans the code and detects vulnerabilities using AST static analysis.
    2. Queries ChromaDB via SecurityRAGEngine to retrieve secure code examples and fixes.
    """
    # 1. AST Static security scan
    vulnerabilities = analyze_code_string(code_string)
    
    # 2. Initialize RAG Engine for vector database queries
    rag = SecurityRAGEngine()
    
    enriched_results = []

    # 3. For each detected vulnerability, query the RAG for the appropriate fix
    for vuln in vulnerabilities:
        vuln_type = vuln.get('type', 'security issue')
        query_text = f"Vulnerability: {vuln_type} in code snippet"
        
        # Retrieve the closest solution from ChromaDB (RAG Retrieval)
        results = rag.collection.query(
            query_texts=[query_text],
            n_results=1
        )
        
        # Extract document/fix content safely
        fix_content = "No direct fix found"
        if results and results.get('documents') and len(results['documents'][0]) > 0:
            fix_content = results['documents'][0][0]
            
        # Combine the detected vulnerability with the retrieved suggested fix
        enriched_results.append({
            "detected_issue": vuln,
            "rag_suggested_fix": fix_content
        })
        
    return {
        "code_scanned": code_string,
        "enriched_vulnerabilities": enriched_results
    }