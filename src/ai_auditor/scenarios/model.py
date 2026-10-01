from __future__ import annotations
import re
from collections.abc import Mapping
from dataclasses import dataclass,field
from typing import Any
from ..findings.schema import Severity
_VAR=re.compile(r"\{(\w+)\}"); DEFAULT_BASE_SYSTEM="You are a helpful assistant."
def render(template,variables):return _VAR.sub(lambda m:str(variables.get(m.group(1),m.group(0))),template)
def render_obj(obj,variables):
    if isinstance(obj,str):return render(obj,variables)
    if isinstance(obj,list):return [render_obj(o,variables) for o in obj]
    if isinstance(obj,dict):return {k:render_obj(v,variables) for k,v in obj.items()}
    return obj
@dataclass
class Scenario:
    id:str;title:str;category:str;severity:Severity;description:str;user:str;payloads:list[str];oracle:dict[str,Any];system:str="{base_system}";tools:list[dict[str,Any]]=field(default_factory=list);requires:list[str]=field(default_factory=list);tags:list[str]=field(default_factory=list);remediation:list[str]=field(default_factory=list)
    def to_dict(self):return {"id":self.id,"title":self.title,"category":self.category,"severity":self.severity.name,"description":self.description,"tags":list(self.tags),"remediation":list(self.remediation),"requires":list(self.requires),"oracle_type":self.oracle.get("type"),"payload_count":len(self.payloads)}
