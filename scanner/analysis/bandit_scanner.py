"""Optional Bandit adapter returning the shared Finding contract."""
import json, subprocess, tempfile, os
from scanner.contracts import normalize_finding
BANDIT_CWE={'B101':'CWE-489','B102':'CWE-78','B307':'CWE-95','B301':'CWE-502','B602':'CWE-78','B603':'CWE-78','B608':'CWE-89','B105':'CWE-798','B106':'CWE-798','B107':'CWE-798','B324':'CWE-327'}
def run_bandit_scan(file_path):
    try: result=subprocess.run(['bandit','-f','json','-q',file_path],capture_output=True,text=True,timeout=30); data=json.loads(result.stdout or '{}')
    except Exception as exc: return [] if isinstance(exc,FileNotFoundError) else [{'error':str(exc)}]
    out=[]
    for issue in data.get('results',[]):
        tid=issue.get('test_id','bandit-unknown'); raw={'cwe_id':BANDIT_CWE.get(tid,'UNKNOWN'),'rule_id':tid,'type':'Bandit: '+tid,'severity':str(issue.get('issue_severity','medium')).lower(),'confidence':{'HIGH':.95,'MEDIUM':.75,'LOW':.5}.get(str(issue.get('issue_confidence','MEDIUM')).upper(),.75),'line':issue.get('line_number',0),'message':issue.get('issue_text',''),'evidence':issue.get('code',''),'recommendation':'Review and remediate this Bandit finding.'}; out.append(normalize_finding(raw,engine='bandit',language='python'))
    return out
def scan_code(code):
    fd,path=tempfile.mkstemp(suffix='.py',text=True)
    try:
        with os.fdopen(fd,'w') as f: f.write(code)
        return run_bandit_scan(path)
    finally:
        if os.path.exists(path): os.unlink(path)
