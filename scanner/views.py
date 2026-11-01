from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny

from scanner.analysis.ast_parser import analyze_code_string
from scanner.core.patcher import run_patcher_on_code
from .models import CodeScan, VulnerabilityReport

try:
    from github import Github
    GITHUB_AVAILABLE = True
except ImportError:
    GITHUB_AVAILABLE = False


def home_view(request):
    return render(request, 'scanner/index.html')


@method_decorator(csrf_exempt, name='dispatch')
class ScanCodeAPIView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        code = request.data.get('code', '') or request.POST.get('code', '')

        github_config = request.data.get('github_config', {})
        push_to_github = github_config.get('enable_push', False)
        repo_name = github_config.get('repo', '')
        file_path = github_config.get('file_path', 'vulnerable_script.py')
        github_token = github_config.get('token', '')

        if not code.strip():
            return Response(
                {"status": "error", "message": "Please provide Python code to scan."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            raw_results = analyze_code_string(code)

            syntax_errors = [v for v in raw_results if "error" in v]
            if syntax_errors:
                return Response(
                    {"status": "error", "message": syntax_errors[0]["error"]},
                    status=status.HTTP_400_BAD_REQUEST
                )

            vulnerabilities_found = []

            for item in raw_results:
                cwe = item.get("cwe", "N/A")

                vulnerabilities_found.append({
                    "cwe_id": cwe,
                    "type": (
                        "Command Injection" if cwe == "CWE-78"
                        else "Code Injection" if cwe == "CWE-95"
                        else "Security Issue"
                    ),
                    "line": item.get("line"),
                    "description": item.get("issue", "Security vulnerability detected."),
                    "severity": item.get("severity", "High"),
                    "recommendation": (
                        "Avoid shell=True. Use subprocess with an argument list "
                        "and shell=False."
                        if cwe == "CWE-78"
                        else "Use ast.literal_eval() instead of eval() when parsing literal data."
                        if cwe == "CWE-95"
                        else "Review the code and apply secure coding practices."
                    )
                })

            is_vulnerable = len(vulnerabilities_found) > 0

            patched_code = code
            retrieved_fixes = []

            if is_vulnerable:
                patcher_result = run_patcher_on_code(code)
                patched_code = patcher_result.get("patched_code", code)
                retrieved_fixes = patcher_result.get("retrieved_fixes", [])

            github_status = {
                "success": False,
                "error": "Push not enabled or skipped."
            }

            if push_to_github and is_vulnerable and GITHUB_AVAILABLE:
                if not github_token or not repo_name or not file_path:
                    github_status = {
                        "success": False,
                        "error": "GitHub Token, Repository Name, and File Path are required."
                    }
                else:
                    try:
                        g = Github(github_token)
                        repo = g.get_repo(repo_name)

                        try:
                            file_obj = repo.get_contents(file_path)
                            commit = repo.update_file(
                                path=file_path,
                                message="AI Security Agent: Automated security patch",
                                content=patched_code,
                                sha=file_obj.sha
                            )
                        except Exception:
                            commit = repo.create_file(
                                path=file_path,
                                message="AI Security Agent: Created security patch",
                                content=patched_code
                            )

                        github_status = {"success": True}

                    except Exception as gh_err:
                        github_status = {
                            "success": False,
                            "error": str(gh_err)
                        }

            elif push_to_github and not GITHUB_AVAILABLE:
                github_status = {
                    "success": False,
                    "error": "PyGithub library is not installed."
                }

            scan_session = CodeScan.objects.create(
                original_code=code,
                patched_code=patched_code,
                status='SUCCESS',
                is_vulnerable=is_vulnerable
            )

            for vuln in vulnerabilities_found:
                VulnerabilityReport.objects.create(
                    scan=scan_session,
                    cwe_id=vuln["cwe_id"],
                    vulnerability_type=vuln["type"],
                    severity=vuln["severity"].upper(),
                    line_number=vuln.get("line"),
                    description=vuln["description"],
                    recommendation=vuln["recommendation"]
                )

            response_data = {
                "status": "success",
                "scan_id": scan_session.id,
                "is_vulnerable": is_vulnerable,
                "original_code": code,
                "patched_code": patched_code,
                "github_status": github_status,
                "vulnerabilities": vulnerabilities_found,
                "result": {
                    "cwe_id": vulnerabilities_found[0]["cwe_id"] if is_vulnerable else "None",
                    "type": vulnerabilities_found[0]["type"] if is_vulnerable else "Secure",
                    "description": vulnerabilities_found[0]["description"] if is_vulnerable else "No vulnerabilities detected.",
                    "recommendation": vulnerabilities_found[0]["recommendation"] if is_vulnerable else "No recommendations required.",
                    "vulnerabilities_count": len(vulnerabilities_found)
                }
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"status": "error", "message": f"Internal server error during analysis: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )