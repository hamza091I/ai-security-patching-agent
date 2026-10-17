import subprocess
import json

def run_bandit_scan(file_path):
    """
    This function receives a Python file path, runs the Bandit tool on it programmatically,
    and returns the detected vulnerabilities as an ordered list.
    """
    try:
        # Python command to run bandit with JSON output format
        command = ["bandit", "-f", "json", file_path]
        
        # Execute the command internally through the terminal
        result = subprocess.run(command, capture_output=True, text=True)
        
        # If the output contains JSON data
        if result.stdout:
            data = json.loads(result.stdout)
            vulnerabilities = []
            
            # Extract vulnerability details clearly
            for issue in data.get("results", []):
                vulnerabilities.append({
                    "line": issue.get("line_number"),
                    "test_id": issue.get("test_id"),
                    "issue": issue.get("issue_text"),
                    "severity": issue.get("issue_severity"),
                    "confidence": issue.get("issue_confidence")
                })
            return vulnerabilities
        return []
        
    except Exception as e:
        return [{"error": str(e)}]