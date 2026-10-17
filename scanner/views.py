from rest_framework.decorators import api_view
from rest_framework.response import Response
from app.core.patcher import run_patcher_on_code

@api_view(['POST'])
def scan_and_patch_api(request):
    """
    Django API Endpoint to receive code string, scan for vulnerabilities,
    retrieve RAG fixes, and return the patched code.
    """
    # 1. Get the code string from the incoming POST request
    code_snippet = request.data.get("code", "")
    
    if not code_snippet:
        return Response({
            "error": "No code provided. Please send a 'code' field in the request body."
        }, status=400)
    
    # 2. Run our core Patcher engine (which integrates AST, Bandit, and RAG)
    result = run_patcher_on_code(code_snippet)
    
    # 3. Return the structured JSON response
    return Response(result, status=200)