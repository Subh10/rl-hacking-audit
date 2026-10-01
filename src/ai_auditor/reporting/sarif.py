"""SARIF 2.1.0 export for GitHub code scanning and other SARIF consumers."""
from __future__ import annotations
from typing import Any
from .. import __version__
from ..findings.schema import Severity
from ..scan.models import ScanReport
_LEVEL={Severity.CRITICAL:"error",Severity.HIGH:"error",Severity.MEDIUM:"warning",Severity.LOW:"note",Severity.INFO:"note"}
_SECURITY_SEVERITY={Severity.CRITICAL:"9.5",Severity.HIGH:"8.0",Severity.MEDIUM:"5.5",Severity.LOW:"3.0",Severity.INFO:"0.0"}
def to_sarif(report,location_uri="ai-auditor.yml"):
    rules=[]; index={}
    for sid,meta in sorted(report.scenarios.items()):
        severity=Severity.parse(meta["severity"]); index[sid]=len(rules); rules.append({"id":sid,"name":meta["title"].title().replace(" ",""),"shortDescription":{"text":meta["title"]},"fullDescription":{"text":meta["description"]},"help":{"text":"Remediation:\n"+"\n".join(f"- {r}" for r in meta.get("remediation",[])) or meta["title"]},"defaultConfiguration":{"level":_LEVEL[severity]},"properties":{"tags":["security","ai-security",meta["category"],*meta.get("tags",[])],"security-severity":_SECURITY_SEVERITY[severity]}})
    results=[]
    for f in report.findings:
        sid=f.scenario_id or f.category; impact=f.impact; results.append({"ruleId":sid,**({"ruleIndex":index[sid]} if sid in index else {}),"level":_LEVEL[f.severity],"message":{"text":f"{f.title} on target '{f.target}': attack success rate {impact.get('asr',0):.0%} ({impact.get('successes','?')}/{impact.get('attempts','?')} attempts, 95% CI {impact.get('ci95',[0,1])[0]:.0%}-{impact.get('ci95',[0,1])[1]:.0%}). Evidence: {', '.join(e['attempt_id'] for e in f.evidence)}."},"locations":[{"physicalLocation":{"artifactLocation":{"uri":location_uri},"region":{"startLine":1}}}],"partialFingerprints":{"aiAuditorFingerprint/v1":f.fingerprint},"properties":{"confidence":f.confidence,"asr":impact.get("asr"),"evidence_root":report.evidence_root,"reproducibility":f.reproducibility}})
    return {"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"AI Auditor","version":__version__,"informationUri":"https://github.com/your-org/ai-auditor","rules":rules}},"results":results,"properties":{"target":report.meta.get("target"),"seed":report.meta.get("seed")}}]}
