"""Shared JSON contract for every security analysis engine."""
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional
import uuid
SEVERITIES = {"critical", "high", "medium", "low", "info"}
ENGINES = {"ast", "bandit", "javascript", "llm", "hybrid"}
@dataclass
class Finding:
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    engine: str = "ast"; language: str = "python"; cwe_id: str = "UNKNOWN"; rule_id: str = "unknown-rule"
    severity: str = "medium"; confidence: float = 0.0; risk_score: float = 0.0; line_start: int = 0; line_end: int = 0
    message: str = ""; evidence: str = ""; recommendation: str = ""; patch: Optional[str] = None
    validation: Dict[str, Any] = field(default_factory=lambda: {"syntax": None, "rescan": None, "tests": None})
    def to_dict(self): return asdict(self)
def normalize_finding(raw: Dict[str, Any], *, engine="ast", language="python"):
    line = int(raw.get("line_start", raw.get("line", 0)) or 0); end = int(raw.get("line_end", line) or line)
    cwe = str(raw.get("cwe_id", "UNKNOWN")); sev = str(raw.get("severity", "medium")).lower()
    if sev not in SEVERITIES: sev = "medium"
    try: conf = max(0.0, min(1.0, float(raw.get("confidence", 1.0 if cwe == "SYNTAX" else .9))))
    except (TypeError, ValueError): conf = .0
    weights = {"critical":1., "high":.85, "medium":.6, "low":.3, "info":.1}
    item = Finding(finding_id=str(raw.get("finding_id") or uuid.uuid4()), engine=str(raw.get("engine", engine)), language=str(raw.get("language", language)), cwe_id=cwe, rule_id=str(raw.get("rule_id") or str(raw.get("type", "unknown-rule")).lower().replace(" ", "-")), severity=sev, confidence=conf, risk_score=round(100 * weights[sev] * conf, 2), line_start=max(0,line), line_end=max(line,end), message=str(raw.get("message", raw.get("issue", ""))), evidence=str(raw.get("evidence", raw.get("message", raw.get("issue", "")))), recommendation=str(raw.get("recommendation", "")), patch=raw.get("patch"), validation=raw.get("validation") or {"syntax":None,"rescan":None,"tests":None})
    out = item.to_dict(); out.update({"type":raw.get("type", "Security Issue"), "line":line}); return out
def validate_finding(finding):
    required = {"finding_id","engine","language","cwe_id","rule_id","severity","confidence","risk_score","line_start","line_end","message","evidence","recommendation","patch","validation"}
    errors = ["missing:" + x for x in sorted(required - set(finding))]
    if finding.get("severity") not in SEVERITIES: errors.append("invalid:severity")
    try:
        if not 0 <= float(finding["confidence"]) <= 1: errors.append("invalid:confidence")
        if not 0 <= float(finding["risk_score"]) <= 100: errors.append("invalid:risk_score")
    except (KeyError, TypeError, ValueError): errors.append("invalid:number")
    if set((finding.get("validation") or {}).keys()) != {"syntax","rescan","tests"}: errors.append("invalid:validation")
    return errors
