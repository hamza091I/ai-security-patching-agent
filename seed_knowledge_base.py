import os
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_project.settings')
django.setup()

from scanner.models import SecurityKnowledgeBase
from scanner.core.rag_engine import SecurityRAGEngine

def seed_database():
    initial_data = [
        {
            "cwe_id": "CWE-95",
            "title": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
            "vulnerable_example": "result = eval(user_input)",
            "secure_example": "import ast\nresult = ast.literal_eval(user_input)",
            "explanation": "Using the eval function allows users to execute arbitrary malicious code. The secure alternative for parsing simple literals and data is ast.literal_eval."
        },
        {
            "cwe_id": "CWE-89",
            "title": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "vulnerable_example": "query = f'SELECT * FROM users WHERE username = \"{username}\"'",
            "secure_example": "cursor.execute('SELECT * FROM users WHERE username = %s', (username,))",
            "explanation": "Concatenating user input directly into queries causes SQL Injection vulnerabilities. Parameterized queries should be used instead."
        },
        {
            "cwe_id": "CWE-78",
            "title": "Improper Neutralization of Special Elements used in an OS Command ('Command Injection')",
            "vulnerable_example": "import os\nos.system('ping ' + user_input)",
            "secure_example": "import subprocess\nsubprocess.run(['ping', user_input], check=True)",
            "explanation": "Using os.system executes OS commands directly. It is recommended to use the subprocess library with arguments passed as a list to avoid injection vulnerabilities."
        }
    ]

    rag = SecurityRAGEngine()

    for item in initial_data:
        obj, created = SecurityKnowledgeBase.objects.get_or_create(
            cwe_id=item["cwe_id"],
            defaults={
                "title": item["title"],
                "vulnerable_example": item["vulnerable_example"],
                "secure_example": item["secure_example"],
                "explanation": item["explanation"],
            }
        )
        if created:
            print(f"[+] Added to Database: {item['cwe_id']} - {item['title']}")
            # Sync and store embeddings in ChromaDB
            embedding = rag.model.encode(item["vulnerable_example"]).tolist()
            rag.collection.add(
                documents=[f"Vulnerable: {item['vulnerable_example']} | Secure: {item['secure_example']}"],
                embeddings=[embedding],
                metadatas=[{"cwe": item["cwe_id"], "type": item["title"]}],
                ids=[item["cwe_id"].lower().replace("-", "_")]
            )

if __name__ == "__main__":
    seed_database()