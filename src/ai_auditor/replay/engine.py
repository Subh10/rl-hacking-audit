from __future__ import annotations
from dataclasses import dataclass,field
from typing import Any
from ..core.output import normalize
from ..core.target import Target
from ..core.trace import Trace
from ..oracles import build_oracle
@dataclass
class ReplayResult:
    replayed:int; reproduced:int; errors:int=0; details:list[dict[str,Any]]=field(default_factory=list)
    @property
    def rate(self):return self.reproduced/self.replayed if self.replayed else 0.0
@dataclass
class ReplayEngine:
    def replayable(self,trace):return [{"kind":e.kind,**e.payload} for e in trace.events if e.kind in {"attack.generated","attack.selected","target.response"}]
    def prompts(self,trace):return [str(e.payload["prompt"]) for e in trace.events if e.kind in {"attack.generated","attack.selected"} and "prompt" in e.payload]
    def replay(self,report,target,*,only_successes=True,repeats=1):
        replayed=reproduced=errors=0; details=[]; per_scenario={}
        for attempt in report.attempts:
            if (only_successes and not attempt.success) or attempt.error:continue
            for _ in range(max(1,repeats)):
                try:out=normalize(target.run(attempt.prompt,history=attempt.history or None,system=attempt.system,tools=attempt.tools))
                except Exception as exc:
                    errors+=1; details.append({"attempt_id":attempt.attempt_id,"error":f"{type(exc).__name__}: {exc}"}); continue
                ok=build_oracle(attempt.oracle).check(out).success; replayed+=1; reproduced+=ok; per_scenario.setdefault(attempt.scenario_id,[]).append(ok); details.append({"attempt_id":attempt.attempt_id,"scenario_id":attempt.scenario_id,"reproduced":ok})
        for f in report.findings:
            runs=per_scenario.get(f.scenario_id or "",[])
            if runs:f.reproducibility=sum(runs)/len(runs)
        return ReplayResult(replayed,reproduced,errors,details)
