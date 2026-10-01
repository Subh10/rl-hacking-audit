from collections.abc import Iterable
from typing import Any
from ..findings.schema import Finding
from .rules import RuleEvaluator
class EvaluatorEnsemble:
    def __init__(self, evaluators: Iterable[Any] | None = None): self.evaluators=list(evaluators or [RuleEvaluator()])
    def evaluate(self,target,attack_id,prompt,response):
        findings=[]
        for evaluator in self.evaluators: findings.extend(evaluator.evaluate(target,attack_id,prompt,response))
        return findings
