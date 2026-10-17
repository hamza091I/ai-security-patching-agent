import json
from scanner.rag.rag_engine import analyze_and_retrieve_fix

# Vulnerable test code for trial
test_code = """
def unsafe_func():
    user_input = "2 + 2"
    eval(user_input)
"""

if __name__ == "__main__":
    print("--- Scanning code and retrieving fixes via RAG ---")
    result = analyze_and_retrieve_fix(test_code)
    
    print(json.dumps(result, indent=4))