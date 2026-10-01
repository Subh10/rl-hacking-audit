from collections.abc import Iterable
from dataclasses import dataclass
from ..core.target import Target
from ..core.trace import Trace
from .base import AttackContext,AttackResult,AttackStrategy
@dataclass
class AttackEngine:
    target:Target
    def run(self,strategies:Iterable[AttackStrategy],objective:str):
        trace=Trace(target=self.target.name);results=[];context=AttackContext(objective=objective)
        for strategy in strategies:
            prompt=strategy.generate(context);trace.add("attack.generated",strategy=getattr(strategy,"name",type(strategy).__name__),prompt=prompt);response=self.target.run(prompt);result=AttackResult(attack_id=getattr(strategy,"id",lambda:"ATTACK")(),prompt=prompt,response=response);results.append(result);context.history.append({"prompt":prompt,"response":response});trace.add("target.response",attack_id=result.attack_id,response=response)
        return results,trace
