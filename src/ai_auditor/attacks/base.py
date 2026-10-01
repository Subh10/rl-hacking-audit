import hashlib
from dataclasses import dataclass,field
from typing import Any,Protocol
@dataclass
class AttackContext:
    objective:str;history:list[dict[str,Any]]=field(default_factory=list);state:dict[str,Any]=field(default_factory=dict)
@dataclass
class AttackResult:
    attack_id:str;prompt:str;response:Any;metadata:dict[str,Any]=field(default_factory=dict)
class AttackStrategy(Protocol):
    name:str
    def generate(self,context:AttackContext)->str:...
@dataclass
class StaticAttack:
    prompt:str;name:str="static"
    def generate(self,context):return self.prompt
    def id(self):return "ATTACK-"+hashlib.sha256(self.prompt.encode()).hexdigest()[:10].upper()
