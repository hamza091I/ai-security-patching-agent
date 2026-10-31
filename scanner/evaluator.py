"""Benchmark evaluator for finding-level and category-level metrics."""
import json
from collections import Counter
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scanner.analysis.orchestrator import scan_code

def evaluate_cases(cases, negative_cases=None):
    tp=fp=fn=tn=0; rows=[]
    for case in cases:
        result=scan_code(case.get('vulnerable_code',''), 'sample.' + ('js' if case.get('language') in {'javascript','typescript'} else 'py'))
        predicted={f['cwe_id'] for f in result['findings']}
        expected=case['expected']['cwe_id']
        hit=expected in predicted
        tp += int(hit); fn += int(not hit); fp += max(0,len(predicted-{expected}))
        rows.append({'id':case['id'],'expected':expected,'predicted':sorted(predicted),'detected':hit})
    precision=tp/(tp+fp) if tp+fp else 0.0; recall=tp/(tp+fn) if tp+fn else 0.0
    accuracy=tp/(tp+fn) if tp+fn else 0.0; f1=2*precision*recall/(precision+recall) if precision+recall else 0.0
    fpr=fp/(fp+tn) if fp+tn else 0.0
    negative_rows=[]
    for case in negative_cases or []:
        predicted=scan_code(case.get('secure_code',''), 'sample.' + ('js' if case.get('language') in {'javascript','typescript'} else 'py'))['findings']
        fp += len(predicted); tn += int(not predicted); negative_rows.append({'id':case['id'],'predicted':[f['cwe_id'] for f in predicted],'clean':not predicted})
    precision=tp/(tp+fp) if tp+fp else 0.0; recall=tp/(tp+fn) if tp+fn else 0.0; accuracy=(tp+tn)/(tp+tn+fp+fn) if tp+tn+fp+fn else 0.0; f1=2*precision*recall/(precision+recall) if precision+recall else 0.0; fpr=fp/(fp+tn) if fp+tn else 0.0
    return {'counts':{'tp':tp,'fp':fp,'fn':fn,'tn':tn},'metrics':{'precision':round(precision,4),'recall':round(recall,4),'accuracy':round(accuracy,4),'f1':round(f1,4),'false_positive_rate':round(fpr,4)},'cases':rows,'negative_cases':negative_rows}
def evaluate_file(path='benchmark-v0.json'):
    cases=json.loads(Path(path).read_text(encoding='utf8')); negative=Path(path).with_name('benchmark-negative-v0.json'); return evaluate_cases(cases, json.loads(negative.read_text(encoding='utf8')) if negative.exists() else [])
if __name__=='__main__': print(json.dumps(evaluate_file(),indent=2))
