import chromadb
from chromadb.utils import embedding_functions

# 1. Setup local embedding model to convert texts into semantic vectors
embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)

# 2. Create a local ChromaDB client (persists data in a folder on your device)
client = chromadb.PersistentClient(path="./chroma_db_storage")

# 3. Create or get a collection dedicated to Python vulnerabilities and their solutions
collection = client.get_or_create_collection(
    name="python_vulnerabilities_kb",
    embedding_function=embedding_fn
)

def initialize_knowledge_base():
    """
    This function populates the database with initial examples of common vulnerabilities (like eval and hardcoded secrets)
    along with the vulnerable code and how to patch them (approved solution).
    """
    vulnerable_examples = [
        "eval() is dangerous because it executes arbitrary strings as python code leading to remote code injection.",
        "Hardcoding passwords or API keys in source code exposes credentials to anyone who reads the repository."
    ]
    
    fixed_examples = [
        "Solution: Avoid using eval(). Use safer alternatives like ast.literal_eval() or built-in parsing functions.",
        "Solution: Store sensitive keys and credentials in environment variables using os.environ or python-dotenv."
    ]
    
    metadata_list = [
        {"cwe": "CWE-95", "severity": "High", "fix": "Use ast.literal_eval()"},
        {"cwe": "CWE-798", "severity": "High", "fix": "Use environment variables"}
    ]
    
    ids = ["vuln_eval_01", "vuln_secret_02"]

    # Add data to the collection if it's empty to prevent duplication
    if collection.count() == 0:
        collection.add(
            documents=vulnerable_examples,
            metadatas=metadata_list,
            ids=ids
        )
        print("Knowledge base populated successfully!")
    else:
        print("Knowledge base already contains data.")

def query_knowledge_base(query_text, n_results=1):
    """
    This is the core RAG function: it receives the description of the detected vulnerability,
    and searches semantically in ChromaDB to fetch the closest solution and similar vulnerability.
    """
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results
    )
    return results