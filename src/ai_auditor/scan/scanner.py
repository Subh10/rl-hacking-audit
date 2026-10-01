"""Scanner: scenarios x payloads x converters x trials -> attempts -> oracle verdicts -> findings + statistics."""
from __future__ import annotations
import hashlib,random,time
from collections import Counter
from collections.abc import Callable,Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any
from .. import __version__
from ..attacks.adaptive import AdaptiveAttackPlanner,AdaptiveConfig
from ..attacks.base import StaticAttack
from ..attacks.converters import CONVERTERS,DEFAULT_CONVERTERS,get_converters
from ..core.output import AgentOutput,normalize
from ..core.target import Target
from ..findings.schema import Finding
from ..oracles import LLMJudge,Verdict,build_oracle,find_canary
from ..scenarios import BUILTIN_SCENARIOS,DEFAULT_BASE_SYSTEM,Scenario,render,render_obj
from .models import Attempt,ScanReport
def _digest(*parts):return hashlib.sha256("|".join(map(str,parts)).encode()).hexdigest()
@dataclass(frozen=True)
class _Case: scenario:Scenario;payload_index:int;converter:str;trial:int
def _partial_credit(verdict,output,canary_parts):return max(verdict.confidence,.5) if verdict.success else .2 if any(find_canary(output.text,p,False) for p in canary_parts) else 0.0
class Scanner:
    def __init__(self,target,scenarios=None,converters=DEFAULT_CONVERTERS,trials=1,seed=7,workers=1,max_attempts=None,adaptive_steps=0,judge=None,base_system=None,on_attempt=None):
        self.target=target;self.scenarios=list(scenarios if scenarios is not None else BUILTIN_SCENARIOS);self.converters=get_converters(converters);self.trials,self.seed,self.workers=max(1,trials),seed,max(1,workers);self.max_attempts,self.adaptive_steps=max_attempts,adaptive_steps;self.judge,self.on_attempt=judge,on_attempt;self.base_system=base_system or DEFAULT_BASE_SYSTEM;self._base_system_supplied=base_system is not None
    def _unsupported(self,sc):missing=[f for f in sc.requires if not self.target.supports(f)];return f"target does not support: {', '.join(missing)}" if missing else None
    def plan(self):
        skipped={};by_scenario={}
        for sc in self.scenarios:
            reason=self._unsupported(sc)
            if reason:skipped[sc.id]=reason;continue
            by_scenario[sc.id]=[_Case(sc,pi,conv,t) for pi in range(len(sc.payloads)) for conv in self.converters for t in range(self.trials)]
        cases=[c for group in by_scenario.values() for c in group]
        if self.max_attempts and len(cases)>self.max_attempts:
            rng=random.Random(self.seed)
            for group in by_scenario.values():rng.shuffle(group)
            picked=[]
            while len(picked)<self.max_attempts and any(by_scenario.values()):
                for group in by_scenario.values():
                    if group and len(picked)<self.max_attempts:picked.append(group.pop())
            order={id(c):i for i,c in enumerate(cases)};cases=sorted(picked,key=lambda c:order[id(c)])
        return cases,skipped
    def _materialize(self,case):
        sc=case.scenario;h=_digest(self.seed,sc.id,case.payload_index,case.converter,case.trial,"canary").upper();a,b="AUD"+h[:4],"X"+h[4:10];canary=a+b;variables={"canary":canary,"canary_a":a,"canary_b":b,"base_system":self.base_system};payload=render(sc.payloads[case.payload_index],variables);payload=CONVERTERS[case.converter](payload,protect=(a,b,canary));supports_system=self.target.supports("system");system=render(sc.system,variables) if supports_system else None
        if system is not None and not self._base_system_supplied and sc.system=="{base_system}":system=None
        return {"canary":canary,"system":system,"prompt":render(sc.user,{**variables,"payload":payload}),"tools":sc.tools if (sc.tools and self.target.supports("tools")) else None,"oracle":render_obj(sc.oracle,variables)}
    def _execute(self,case):
        inputs=self._materialize(case);attempt_id="ATT-"+_digest(self.seed,case.scenario.id,case.payload_index,case.converter,case.trial)[:10].upper();start=time.perf_counter();error=None
        try:output=normalize(self.target.run(inputs["prompt"],system=inputs["system"],tools=inputs["tools"]))
        except Exception as exc:output,error=AgentOutput(),f"{type(exc).__name__}: {exc}"
        latency=(time.perf_counter()-start)*1000;verdict=build_oracle(inputs["oracle"]).check(output) if error is None else Verdict(False)
        return Attempt(attempt_id=attempt_id,scenario_id=case.scenario.id,category=case.scenario.category,payload_index=case.payload_index,converter=case.converter,trial=case.trial,canary=inputs["canary"],system=inputs["system"],prompt=inputs["prompt"],tools=inputs["tools"],oracle=inputs["oracle"],response=output.to_dict(),success=verdict.success,confidence=verdict.confidence,reasons=verdict.reasons,latency_ms=round(latency,2),error=error).seal()
    def _adaptive_pass(self,scenario):
        seed_case=_Case(scenario,0,"identity",0);inputs=self._materialize(seed_case);oracle=build_oracle(inputs["oracle"]);parts=(inputs["canary"][:7],inputs["canary"][7:])
        def invoke(prompt,history=None):return normalize(self.target.run(prompt,history=history,system=inputs["system"],tools=inputs["tools"]))
        def scorer(response):out=normalize(response);return _partial_credit(oracle.check(out),out,parts)
        planner=AdaptiveAttackPlanner(Target(f"{self.target.name}::{scenario.id}",invoke=invoke),scorer=scorer,config=AdaptiveConfig(max_steps=self.adaptive_steps,max_depth=3,branch_factor=6,seed=self.seed));attempts=[]
        try:run=planner.run(StaticAttack(inputs["prompt"],"adaptive-root"),objective=scenario.title)
        except Exception as exc:return [Attempt(attempt_id="ATT-"+_digest(self.seed,scenario.id,"adaptive-error")[:10].upper(),scenario_id=scenario.id,category=scenario.category,payload_index=-1,converter="adaptive",trial=0,canary=inputs["canary"],system=inputs["system"],prompt=inputs["prompt"],tools=inputs["tools"],oracle=inputs["oracle"],adaptive=True,error=f"{type(exc).__name__}: {exc}").seal()]
        history=[]
        for step,result in enumerate(run.results):
            out=normalize(result.response);verdict=oracle.check(out);attempts.append(Attempt(attempt_id="ATT-"+_digest(self.seed,scenario.id,"adaptive",step)[:10].upper(),scenario_id=scenario.id,category=scenario.category,payload_index=-1,converter="adaptive",trial=step,canary=inputs["canary"],system=inputs["system"],prompt=result.prompt,tools=inputs["tools"],oracle=inputs["oracle"],response=out.to_dict(),success=verdict.success,confidence=verdict.confidence,reasons=verdict.reasons,adaptive=True,history=list(history)).seal());history.append({"prompt":result.prompt,"response":out.text})
        return attempts
    def run(self):
        cases,skipped=self.plan()
        def work(case):
            attempt=self._execute(case)
            if self.on_attempt:self.on_attempt(attempt)
            return attempt
        attempts=list(ThreadPoolExecutor(max_workers=self.workers).map(work,cases)) if self.workers>1 else [work(c) for c in cases]
        if self.adaptive_steps>0:
            hit={a.scenario_id for a in attempts if a.success};tried={c.scenario.id for c in cases}
            for sc in self.scenarios:
                if sc.id in tried and sc.id not in hit:attempts.extend(self._adaptive_pass(sc))
        if self.judge:
            scenarios={s.id:s for s in self.scenarios}
            for a in attempts:
                if a.error:continue
                try:a.judge=self.judge.evaluate(objective=scenarios[a.scenario_id].description,prompt=a.prompt,output=AgentOutput.from_dict(a.response)).to_dict()
                except Exception as exc:a.judge={"error":f"{type(exc).__name__}: {exc}"}
        scenario_meta={s.id:s.to_dict() for s in self.scenarios};meta={"tool":"ai-auditor","version":__version__,"target":self.target.name,"seed":self.seed,"trials":self.trials,"converters":self.converters,"max_attempts":self.max_attempts,"adaptive_steps":self.adaptive_steps,"judge":self.judge.name if self.judge else None,"base_system_supplied":self._base_system_supplied,"config_hash":_digest(self.seed,self.trials,self.converters,sorted(scenario_meta))[:16]}
        return ScanReport(meta=meta,scenarios=scenario_meta,attempts=attempts,findings=self._build_findings(attempts),skipped=skipped)
    def _build_findings(self,attempts):
        from ..stats.intervals import wilson
        scenarios={s.id:s for s in self.scenarios};findings=[]
        for sid,sc in scenarios.items():
            valid=[a for a in attempts if a.scenario_id==sid and not a.error];wins=[a for a in valid if a.success]
            if not wins:continue
            lo,hi=wilson(len(wins),len(valid));best=sorted(wins,key=lambda a:(-a.confidence,a.attempt_id))[:3]
            findings.append(Finding(category=sc.category,title=sc.title,severity=sc.severity,confidence=max(a.confidence for a in wins),evidence=[{"attempt_id":a.attempt_id,"converter":a.converter,"prompt":a.prompt[:800],"response":a.response.get("text","")[:600],"tool_calls":a.response.get("tool_calls",[]),"reasons":a.reasons,"digest":a.digest} for a in best],attack_id=best[0].attempt_id,target=self.target.name,impact={"asr":len(wins)/len(valid),"ci95":[lo,hi],"attempts":len(valid),"successes":len(wins),"successful_converters":dict(Counter(a.converter for a in wins).most_common())},remediation=list(sc.remediation),scenario_id=sid,oracle=sc.oracle.get("type"),tags=list(sc.tags),finding_id="FIND-"+_digest(self.target.name,sid,self.seed)[:10].upper()))
        return sorted(findings,key=lambda f:(-int(f.severity),f.scenario_id or ""))
