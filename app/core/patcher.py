"""Compatibility wrapper around the server's deep patch proposal engine."""
from scanner.core.patcher import propose_patch
from scanner.analysis.security_scanner import full_security_scan


class CodePatcher:
    """Keep the legacy app API while using the same 25-rule patch engine."""

    def __init__(self, code_string, filename="sample.py"):
        self.code_string = code_string
        self.filename = filename

    def generate_patch(self):
        proposal = propose_patch(self.code_string, self.filename)
        findings = full_security_scan(self.code_string, self.filename).get("all_findings", [])
        return {
            "status": "Patched" if proposal["changes"] else "Secure",
            "original_code": self.code_string,
            "patched_code": proposal["patched_code"],
            "applied_fixes": proposal["changes"],
            "changes": proposal["changes"],
            "validation": proposal["validation"],
            "vulnerabilities": findings,
        }


def run_patcher_on_code(code_string, filename="sample.py"):
    return CodePatcher(code_string, filename).generate_patch()
