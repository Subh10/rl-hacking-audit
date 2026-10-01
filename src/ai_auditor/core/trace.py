import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
@dataclass
class TraceEvent:
    kind: str
    payload: dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
@dataclass
class Trace:
    target: str
    events: list[TraceEvent] = field(default_factory=list)
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    def add(self, kind: str, **payload: Any) -> TraceEvent:
        event=TraceEvent(kind=kind,payload=payload); self.events.append(event); return event
    def to_dict(self): return {"trace_id":self.trace_id,"target":self.target,"events":[{"kind":e.kind,"payload":e.payload,"timestamp":e.timestamp,"event_id":e.event_id} for e in self.events]}
