import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any

class Severity(IntEnum):
    INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4
    @classmethod
    def parse(cls, value: "str | int | Severity") -> "Severity":
        if isinstance(value, Severity): return value
        if isinstance(value, int): return cls(value)
        return cls[str(value).strip().upper()]
@dataclass
class Finding:
    category: str; title: str; severity: Severity; confidence: float
    evidence: list[dict[str, Any]] = field(default_factory=list); attack_id: str | None = None; target: str | None = None
    impact: dict[str, Any] = field(default_factory=dict); remediation: list[str] = field(default_factory=list)
    reproducibility: float | None = None; finding_id: str = field(default_factory=lambda: "FIND-" + uuid.uuid4().hex[:10].upper())
    scenario_id: str | None = None; oracle: str | None = None; tags: list[str] = field(default_factory=list)
    def __post_init__(self):
        self.confidence=min(1.0,max(0.0,float(self.confidence)))
        if self.reproducibility is not None: self.reproducibility=min(1.0,max(0.0,float(self.reproducibility)))
    @property
    def fingerprint(self): return hashlib.sha256(f"{self.target}|{self.scenario_id or self.category}|{self.category}".encode()).hexdigest()[:16]
    def to_dict(self):
        data=asdict(self); data["severity"]=self.severity.name; data["fingerprint"]=self.fingerprint; return data
    @classmethod
    def from_dict(cls,data):
        data={k:v for k,v in data.items() if k!="fingerprint"}; data["severity"]=Severity.parse(data["severity"]); return cls(**data)
    def to_json(self): return json.dumps(self.to_dict(),indent=2,sort_keys=True)
