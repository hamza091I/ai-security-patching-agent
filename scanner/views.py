from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.shortcuts import render
from app.core.patcher import run_patcher_on_code

def home_view(request):
    """
    Renders the simple frontend HTML page.
    """
    return render(request, 'scanner/index.html')

@api_view(['POST'])
def scan_and_patch_api(request):
    """
    Django API Endpoint to receive code string, scan for vulnerabilities,
    retrieve RAG fixes, and return the patched code.
    """
    code_snippet = request.data.get("code", "")
    
    if not code_snippet:
        return Response({
            "error": "No code provided. Please send a 'code' field in the request body."
        }, status=400)
    
    result = run_patcher_on_code(code_snippet)
    return Response(result, status=200)