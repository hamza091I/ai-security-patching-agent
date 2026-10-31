"""Evaluate the 80 catalog detectors with positive and secure snippets."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scanner.analysis.catalog_rules import RULES, analyze_catalog

def evaluate():
    rows=[]
    for rule in RULES:
        positive=analyze_catalog(rule['vulnerable_code'],rule['language']); secure=analyze_catalog(rule['secure_code'],rule['language'])
        rows.append({'rule_id':rule['id'],'cwe_id':rule['cwe_id'],'positive_detected':any(x['rule_id']==rule['id'] for x in positive),'secure_clean':not any(x['rule_id']==rule['id'] for x in secure)})
    return {'detector_count':len(rows),'positive_pass':sum(x['positive_detected'] for x in rows),'secure_pass':sum(x['secure_clean'] for x in rows),'positive_recall':sum(x['positive_detected'] for x in rows)/len(rows),'secure_specificity':sum(x['secure_clean'] for x in rows)/len(rows),'cases':rows}
if __name__=='__main__': print(json.dumps(evaluate(),indent=2))
