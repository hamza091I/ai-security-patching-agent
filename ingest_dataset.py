import os
import json
import django

# Configure Django Environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_project.settings')
django.setup()

from scanner.models import SecurityKnowledgeBase
from scanner.core.rag_engine import SecurityRAGEngine

def ingest_vulnerabilities():
    json_path = os.path.join(os.getcwd(), 'vulnerabilities_dataset.json')
    
    if not os.path.exists(json_path):
        print(f"[!] Error: Dataset file '{json_path}' not found.")
        return

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    rag = SecurityRAGEngine()
    added_count = 0

    for item in data:
        obj, created = SecurityKnowledgeBase.objects.get_or_create(
            cwe_id=item["cwe_id"],
            defaults={
                "title": item["title"],
                "vulnerable_example": item["vulnerable_example"],
                "secure_example": item["secure_example"],
                "explanation": item["explanation"],
            }
        )
        
        # Sync to ChromaDB
        embedding = rag.model.encode(item["vulnerable_example"]).tolist()
        
        # Check if item already exists in ChromaDB collection
        existing_ids = rag.collection.get(ids=[item["cwe_id"].lower().replace("-", "_")])["ids"]
        if not existing_ids:
            rag.collection.add(
                documents=[f"Vulnerable: {item['vulnerable_example']} | Secure: {item['secure_example']}"],
                embeddings=[embedding],
                metadatas=[{"cwe": item["cwe_id"], "type": item["title"]}],
                ids=[item["cwe_id"].lower().replace("-", "_")]
            )
            print(f"[+] Successfully ingested to ChromaDB & DB: {item['cwe_id']} - {item['title']}")
            added_count += 1
        else:
            print(f"[*] Already exists in ChromaDB: {item['cwe_id']}")

    print(f"\n[✔] Ingestion complete. Ingested {added_count} new entries.")

if __name__ == "__main__":
    ingest_vulnerabilities()