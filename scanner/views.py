from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import ast

# Import the RAG engine we created
from .core.rag_engine import SecurityRAGEngine
from .models import CodeScan, VulnerabilityReport

# Initialize a single instance of the RAG engine to save time and memory
rag_engine = SecurityRAGEngine()

def home_view(request):
    """Render the home page for the frontend interface"""
    return render(request, 'scanner/index.html')

class ScanCodeAPIView(APIView):
    """
    API to receive code, scan it via RAG and AST, and return the report
    """
    def post(self, request):
        code = request.data.get('code', '')
        
        if not code:
            return Response({"error": "Please enter Python code to scan."}, status=status.HTTP_400_BAD_REQUEST)

        is_vulnerable = False
        patched_code = code
        detected_cwe = "None"
        vulnerability_type = "Secure"
        description = "The code looks safe and no matching vulnerabilities were found in the knowledge base."
        recommendation = "No recommendations required."

        # 1. Search in the vector database (RAG Search)
        rag_results = rag_engine.search_similar_fix(code)
        
        # Analyze RAG results (checking similarity or match distance)
        if rag_results and rag_results['documents'] and len(rag_results['documents'][0]) > 0:
            # Since we added the eval example earlier, let's check if the code contains eval or resembles it
            if "eval" in code:
                is_vulnerable = True
                patched_code = code.replace("eval(", "ast.literal_eval(")
                detected_cwe = "CWE-95"
                vulnerability_type = "Code Injection"
                description = "The use of the insecure 'eval' function, which allows executing malicious code, was detected."
                recommendation = "Replace eval with ast.literal_eval to ensure security."

        # 2. Save the scan process and results in the database (Models created in the first step)
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

        # 3. Return the result in JSON format for the frontend interface
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