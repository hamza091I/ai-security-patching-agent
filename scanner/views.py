from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

# Import RAG engine, AST parser, and database models
from .core.rag_engine import SecurityRAGEngine
from .core.ast_parser import run_ast_analysis
from .models import CodeScan, VulnerabilityReport

# Initialize a single instance of the RAG engine to optimize memory and performance
rag_engine = SecurityRAGEngine()

def home_view(request):
    """Render the main frontend HTML page."""
    return render(request, 'scanner/index.html')

@method_decorator(csrf_exempt, name='dispatch')
class ScanCodeAPIView(APIView):
    """
    API endpoint to receive Python code, scan it using AST parser first, then RAG, and return the report.
    """
    def post(self, request):
        code = request.data.get('code', '')
        
        if not code:
            return Response({"error": "Please provide Python code to scan."}, status=status.HTTP_400_BAD_REQUEST)

        # Step 1: Perform static analysis locally using the AST parser
        ast_result = run_ast_analysis(code)
        
        if ast_result["has_error"]:
            return Response({"error": ast_result["message"]}, status=status.HTTP_400_BAD_REQUEST)

        vulnerabilities_found = ast_result["vulnerabilities"]
        
        is_vulnerable = len(vulnerabilities_found) > 0
        patched_code = code
        detected_cwe = "None"
        vulnerability_type = "Secure"ء  
        description = "The code appears safe. No vulnerabilities detected in static analysis."
        recommendation = "No recommendations required."

        # Step 2: If AST detects a vulnerability, leverage the RAG engine to retrieve secure patches and explanations
        if is_vulnerable:
            first_vuln = vulnerabilities_found[0]
            detected_cwe = first_vuln["cwe_id"]
            
            # Search for the secure fix using the RAG engine
            rag_result = rag_engine.search_similar_fix(code)
            
            if rag_result["found"]:
                vulnerability_type = rag_result["type"]
                description = f"{first_vuln['message']} (Line: {first_vuln['line']})"
                recommendation = rag_result["recommendation"]
                if "secure_example" in rag_result:
                    patched_code = rag_result["secure_example"]
        else:
            # Fallback: Semantic search via RAG if AST didn't directly catch it
            rag_result = rag_engine.search_similar_fix(code)
            if rag_result["found"]:
                is_vulnerable = True
                detected_cwe = rag_result["cwe_id"]
                vulnerability_type = rag_result["type"]
                description = description if description != "The code appears safe. No vulnerabilities detected in static analysis." else rag_result["description"]
                recommendation = rag_result["recommendation"]
                if "secure_example" in rag_result:
                    patched_code = rag_result["secure_example"]

        # Step 3: Save the scan session and details into SQLite database
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

        # Step 4: Return the structured JSON response to the frontend UI
        response_data = {
            "scan_id": scan_session.id,
            "is_vulnerable": is_vulnerable,
            "original_code": code,
            "patched_code": patched_code,
            "vulnerability": {
                "cwe_id": detected_cwe,
                "type": vulnerability_type,
                "description": description,
                "recommendation": recommendation
            }
        }

        return Response(response_data, status=status.HTTP_200_OK)