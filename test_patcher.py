from app.core.patcher import run_patcher_on_code
import json

# Vulnerable test code snippet
sample_bad_code = """
def process_data():
    user_input = "10 + 20"
    result = eval(user_input)
    password = "12345_super_secret_password"
    return result
"""

if __name__ == "__main__":
    print("--- Running AI Code Patcher ---")
    patch_result = run_patcher_on_code(sample_bad_code)
    
    # Print clean JSON output of the patching process
    print(json.dumps(patch_result, indent=4))