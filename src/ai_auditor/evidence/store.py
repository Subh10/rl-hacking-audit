from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

@dataclass
class EvidenceRecord:
    kind: str
    payload: dict[str, Any]
    digest: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        canonical = json.dumps(self.payload, sort_keys=True, default=str, separators=(",", ":"))
        self.digest = hashlib.sha256(canonical.encode()).hexdigest()

class EvidenceStore:
    """In-memory evidence store; serializable and intentionally provider-neutral."""
    def __init__(self):
        self.records: list[EvidenceRecord] = []

    def add(self, kind: str, **payload: Any) -> EvidenceRecord:
        record = EvidenceRecord(kind=kind, payload=payload)
        self.records.append(record)
        return record

    def export(self) -> list[dict[str, Any]]:
        return [asdict(r) for r in self.records]
