"""Optional Ollama provider; baseline scanning never requires a running LLM."""
import json,os,urllib.request
class LLMProvider:
    def analyze(self,code,language='python'): raise NotImplementedError
class OllamaProvider(LLMProvider):
    def __init__(self,model=None,base_url=None): self.model=model or os.getenv('OLLAMA_MODEL','llama3.2'); self.base_url=base_url or os.getenv('OLLAMA_BASE_URL','http://127.0.0.1:11434')
    def analyze(self,code,language='python'):
        payload={'model':self.model,'prompt':'Return JSON findings with cwe_id, rule_id, severity, confidence, line_start, line_end, message, recommendation. Language: '+language+'\n'+code,'stream':False}; req=urllib.request.Request(self.base_url.rstrip('/')+'/api/generate',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(req,timeout=30) as response: return json.loads(response.read().decode()).get('response','')
        except Exception as exc: return {'error':str(exc),'findings':[]}
