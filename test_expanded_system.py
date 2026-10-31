import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_project.settings')
django.setup()

from scanner.rag.rag_engine import analyze_and_retrieve_fix


vulnerable_code_sample = """
def evaluate_user_data(user_input):
    result = eval(user_input)
    return result
"""

print("[*] Running Dual-Engine Analysis (AST + ChromaDB RAG)...")
result = analyze_and_retrieve_fix(vulnerable_code_sample)

print("\n--- Final Enriched Scan & RAG Results ---")
print(json.dumps(result, indent=4, ensure_ascii=False))