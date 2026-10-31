"""Optional RAG facade. Uses the local benchmark when Chroma/embeddings are unavailable."""
import json
from pathlib import Path
from scanner.analysis.ast_parser import analyze_code_string
class _Collection:
    def query(self, query_texts=None, n_results=1, **kwargs): return {'documents': [[]], 'metadatas': [[]]}
class SecurityRAGEngine:
    def __init__(self):
        self.collection=_Collection()
        self.records=[]
        path=Path(__file__).resolve().parents[2]/'vulnerabilities_dataset.json'
        if path.exists():
            try: self.records=json.loads(path.read_text(encoding='utf8'))
            except Exception: self.records=[]
    def find(self,cwe): return next((x for x in self.records if x.get('cwe_id')==cwe),None)
def analyze_and_retrieve_fix(code_string):
    rag=SecurityRAGEngine(); enriched=[]
    for vuln in analyze_code_string(code_string): enriched.append({'detected_issue':vuln,'rag_suggested_fix':rag.find(vuln.get('cwe_id')) or {}})
    return {'code_scanned':code_string,'enriched_vulnerabilities':enriched}
