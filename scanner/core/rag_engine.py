import os
import chromadb
from sentence_transformers import SentenceTransformer
from scanner.models import SecurityKnowledgeBase

class SecurityRAGEngine:
    def __init__(self):
        # Define the local directory path for storing the vector database
        self.db_path = os.path.join(os.getcwd(), "chroma_db")
        self.client = chromadb.PersistentClient(path=self.db_path)
        
        # Load a fast and efficient embedding model
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Get or create the vector collection
        self.collection = self.client.get_or_create_collection(name="security_knowledge_base")

    def search_similar_fix(self, code_snippet: str):
        """
        Perform a semantic similarity search in ChromaDB for the closest vulnerability match 
        to the input code snippet, then retrieve full details, explanations, and recommendations 
        from the Django knowledge base table.
        """
        # Generate embeddings for the developer's input code snippet
        query_embedding = self.model.encode(code_snippet).tolist()
        
        # Search in ChromaDB and retrieve the closest match (top 1 result as a start)
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=1
        )
        
        # Check if any results were retrieved
        if results and results['metadatas'] and len(results['metadatas']) > 0:
            meta = results['metadatas'][0][0]
            cwe_id = meta.get("cwe")
            
            # Fetch actual vulnerability details and explanations from the database (SQLite / SecurityKnowledgeBase)
            try:
                kb_entry = SecurityKnowledgeBase.objects.get(cwe_id=cwe_id)
                return {
                    "found": True,
                    "cwe_id": kb_entry.cwe_id,
                    "type": kb_entry.title,
                    "vulnerable_example": kb_entry.vulnerable_example,
                    "secure_example": kb_entry.secure_example,
                    "description": kb_entry.explanation,
                    "recommendation": f"Replace the insecure code with the suggested secure format: {kb_entry.secure_example}"
                }
            except SecurityKnowledgeBase.DoesNotExist:
                pass

        # If no matching vulnerability was found
        return {
            "found": False,
            "cwe_id": "None",
            "type": "Secure / Unknown",
            "description": "The code appears safe or no matching vulnerabilities were found in the security knowledge base.",
            "recommendation": "No recommendations needed at this time."
        }