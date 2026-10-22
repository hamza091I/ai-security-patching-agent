import os
import chromadb
from sentence_transformers import SentenceTransformer

class SecurityRAGEngine:
    def __init__(self):
        # Define local vector database storage path
        self.db_path = os.path.join(os.getcwd(), "chroma_db")
        self.client = chromadb.PersistentClient(path=self.db_path)
        
        # Use a lightweight and fast model to convert texts into embeddings
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Create or get the dataset collection
        self.collection = self.client.get_or_create_collection(name="security_knowledge_base")
        
        # Populate initial data if the database is empty
        self._seed_initial_data()

    def _seed_initial_data(self):
        """Insert standard vulnerability examples and their fixes if the database is empty"""
        if self.collection.count() == 0:
            vulnerable_code_example = "eval(user_input)"
            secure_code_example = "ast.literal_eval(user_input)"
            
            # Generate the vector for the text
            embedding = self.model.encode(vulnerable_code_example).tolist()
            
            self.collection.add(
                documents=[f"Vulnerable: {vulnerable_code_example} | Secure Fix: {secure_code_example}"],
                embeddings=[embedding],
                metadatas=[{"cwe": "CWE-95", "type": "Code Injection"}],
                ids=["cwe_95_eval"]
            )

    def search_similar_fix(self, code_snippet: str):
        """Search for the closest security fix based on the input code"""
        query_embedding = self.model.encode(code_snippet).tolist()
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=1
        )
        return results