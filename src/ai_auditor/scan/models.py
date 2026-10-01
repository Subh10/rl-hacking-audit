from __future__ import annotations
import hashlib,json
from dataclasses import asdict,dataclass,field
from pathlib import Path
from typing import Any
from ..findings.schema import Finding
from ..stats.intervals import wilson
REPORT_SCHEMA="ai-auditor/report/v1"
@dataclass
class Attempt:
    attempt_id:str;scenario_id:str;category:str;payload_index:int;converter:str;trial:int;canary:str;system:str|None;prompt:str;tools:list[dict[str,Any]]|None;oracle:dict[str,Any];response:dict[str,Any]=field(default_factory=dict);success:bool=False;confidence:float=0.0;reasons:list[str]=field(default_factory=list);latency_ms:float=0.0;error:str|None=None;adaptive:bool=False;history:list[dict[str,str]]=field(default_factory=list);judge:dict[str,Any]|None=None;digest:str=""
    def seal(self):
        canonical=json.dumps({"p":self.prompt,"s":self.system,"r":self.response,"o":self.oracle},sort_keys=True,default=str,separators=(",",":"));self.digest=hashlib.sha256(canonical.encode()).hexdigest();return self
    def to_dict(self):return asdict(self)
    @classmethod
    def from_dict(cls,data):return cls(**data)
@dataclass
class ScanReport:
    meta:dict[str,Any];scenarios:dict[str,dict[str,Any]];attempts:list[Attempt];findings:list[Finding];skipped:dict[str,str]=field(default_factory=dict)
    @staticmethod
    def _stat(k,n,errors=0):
        lo,hi=wilson(k,n);return {"k":k,"n":n,"asr":k/n if n else 0.0,"ci_low":lo,"ci_high":hi,"errors":errors}
    def _group(self,key):
        groups={}
        for a in self.attempts:groups.setdefault(key(a),[]).append(a)
        return {g:self._stat(sum(a.success for a in atts if not a.error),sum(1 for a in atts if not a.error),sum(1 for a in atts if a.error)) for g,atts in sorted(groups.items())}
    def scenario_stats(self):return self._group(lambda a:a.scenario_id)
    def category_stats(self):return self._group(lambda a:a.category)
    def converter_stats(self):return self._group(lambda a:a.converter)
    def overall(self):
        valid=[a for a in self.attempts if not a.error];return self._stat(sum(a.success for a in valid),len(valid),len(self.attempts)-len(valid))
    @property
    def evidence_root(self):return hashlib.sha256("".join(sorted(a.digest for a in self.attempts)).encode()).hexdigest()
    def to_dict(self):return {"schema":REPORT_SCHEMA,"meta":{**self.meta,"evidence_root":self.evidence_root},"summary":{"overall":self.overall(),"by_category":self.category_stats(),"by_scenario":self.scenario_stats(),"by_converter":self.converter_stats()},"scenarios":self.scenarios,"skipped":self.skipped,"findings":[f.to_dict() for f in self.findings],"attempts":[a.to_dict() for a in self.attempts]}
    @classmethod
    def from_dict(cls,data):
        if data.get("schema")!=REPORT_SCHEMA:raise ValueError(f"unsupported report schema: {data.get('schema')!r} (expected {REPORT_SCHEMA})")
        return cls(meta=data["meta"],scenarios=data["scenarios"],skipped=data.get("skipped",{}),attempts=[Attempt.from_dict(a) for a in data["attempts"]],findings=[Finding.from_dict(f) for f in data["findings"]])
    def save(self,path):
        p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(self.to_dict(),indent=2,default=str),encoding="utf-8");return p
    @classmethod
    def load(cls,path):return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
