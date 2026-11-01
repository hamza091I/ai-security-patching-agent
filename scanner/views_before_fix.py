from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny

from scanner.analysis.ast_parser import analyze_code_string
from scanner.core.rag_engine import SecurityRAGEngine
from scanner.core.patcher import run_patcher_on_code
from .models import CodeScan, VulnerabilityReport

try:
    from github import Github
    GITHUB_AVAILABLE = True
except ImportError:
    GITHUB_AVAILABLE = False

rag_engine = SecurityRAGEngine()

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
            vulnerabilities_found = analyze_code_string(code)
            
            syntax_errors = [v for v in vulnerabilities_found if v.get("cwe_id") == "SYNTAX"]
            if syntax_errors:
                return Response(
                    {"status": "error", "message": syntax_errors[0].get("message", "Syntax error in code.")}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            is_vulnerable = len(vulnerabilities_found) > 0
            
            patcher_result = run_patcher_on_code(code)
            patched_code = patcher_result.get("patched_code", code)
            retrieved_fixes = patcher_result.get("retrieved_fixes", [])

            detected_cwe = "None"
            vulnerability_type = "Secure"
            description = "The code appears safe. No vulnerabilities detected in static analysis."
            recommendation = "No recommendations required. Code complies with basic security standards."
            github_status = {"success": False, "error": "Push not enabled or skipped."}

            if is_vulnerable:
                first_vuln = vulnerabilities_found[0]
                detected_cwe = first_vuln.get("cwe_id", "CWE-General")
                vulnerability_type = first_vuln.get("type", "Security Issue")
                description = f"{first_vuln.get('message', '')} (Line: {first_vuln.get('line', 0)})"
                
                if retrieved_fixes and len(retrieved_fixes) > 0:
                    recommendation = retrieved_fixes[0].get("recommended_fix", first_vuln.get("recommendation", "Apply secure coding standards."))
                else:
                    recommendation = first_vuln.get("recommendation", "Apply secure coding standards.")

            if push_to_github and is_vulnerable and GITHUB_AVAILABLE:
                if not github_token or not repo_name or not file_path:
                    github_status = {"success": False, "error": "GitHub Token, Repository Name, and File Path are required."}
                else:
                    try:
                        g = Github(github_token)
                        repo = g.get_repo(repo_name)
                        
                        try:
                            file_obj = repo.get_contents(file_path)
                            commit = repo.update_file(
                                path=file_path,
                                message=f"AI Security Agent: Automated patch for {detected_cwe}",
                                content=patched_code,
                                sha=file_obj.sha
                            )
                            commit_sha = commit.get('commit').sha if isinstance(commit, dict) else getattr(commit.get('commit'), 'sha', 'Pushed')
                            github_status = {"success": True, "commit_sha": commit_sha}
                        except Exception:
                            commit = repo.create_file(
                                path=file_path,
                                message=f"AI Security Agent: Created secure patch for {detected_cwe}",
                                content=patched_code
                            )
                            commit_sha = commit.get('commit').sha if isinstance(commit, dict) else getattr(commit.get('commit'), 'sha', 'Pushed')
                            github_status = {"success": True, "commit_sha": commit_sha}
                    except Exception as gh_err:
                        github_status = {"success": False, "error": str(gh_err)}
            elif push_to_github and not GITHUB_AVAILABLE:
                github_status = {"success": False, "error": "PyGithub library is not installed."}

            scan_session = CodeScan.objects.create(
                original_code=code,
                patched_code=patched_code,
                status='SUCCESS',
                is_vulnerable=is_vulnerable
            )

            if is_vulnerable:
                VulnerabilityReport.objects.create(
                    scan=scan_session,
                    cwe_id=detected_cwe,
                    vulnerability_type=vulnerability_type,
                    severity='CRITICAL',
                    description=description,
                    recommendation=recommendation
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
                    "cwe_id": detected_cwe,
                    "type": vulnerability_type,
                    "description": description,
                    "recommendation": recommendation,
                    "vulnerabilities_count": len(vulnerabilities_found)
                }
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"status": "error", "message": f"Internal server error during analysis: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )