from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Protocol
from ..core.output import AgentOutput
@dataclass
class Verdict:
    success: bool
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    def to_dict(self): return {"success":self.success,"confidence":self.confidence,"reasons":list(self.reasons),"evidence":dict(self.evidence)}
class Oracle(Protocol):
    type: str
    def check(self, output: AgentOutput) -> Verdict: ...
