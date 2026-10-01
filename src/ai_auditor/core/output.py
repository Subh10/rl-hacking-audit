"""Provider-neutral normalisation of target responses."""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Any
@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    def to_dict(self) -> dict[str, Any]: return {"name": self.name, "arguments": self.arguments}
@dataclass
class AgentOutput:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None
    def to_dict(self) -> dict[str, Any]: return {"text": self.text, "tool_calls": [t.to_dict() for t in self.tool_calls]}
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentOutput:
        return cls(text=data.get("text", ""), tool_calls=[ToolCall(c["name"], c.get("arguments", {})) for c in data.get("tool_calls", [])])
def _parse_args(value: Any) -> dict[str, Any]:
    if isinstance(value, dict): return value
    if isinstance(value, str):
        try: parsed = json.loads(value)
        except ValueError: return {"_raw": value}
        return parsed if isinstance(parsed, dict) else {"_raw": value}
    return {}
def _tool_call_from(obj: Any) -> ToolCall | None:
    if isinstance(obj, ToolCall): return obj
    if isinstance(obj, dict):
        fn = obj["function"] if isinstance(obj.get("function"), dict) else obj
        name = fn.get("name") or obj.get("name")
        if not name: return None
        args = fn.get("arguments", fn.get("args", fn.get("input", obj.get("arguments", {}))))
        return ToolCall(str(name), _parse_args(args))
    name = getattr(obj, "name", None)
    if name: return ToolCall(str(name), _parse_args(getattr(obj, "arguments", {})))
    return None
def normalize(response: Any) -> AgentOutput:
    if isinstance(response, AgentOutput): return response
    if response is None: return AgentOutput()
    if isinstance(response, str): return AgentOutput(text=response, raw=response)
    if isinstance(response, dict):
        text = response.get("text") or response.get("content") or response.get("output") or ""
        if not isinstance(text, str): text = json.dumps(text, default=str)
        calls = [c for c in map(_tool_call_from, response.get("tool_calls") or []) if c]
        return AgentOutput(text=text, tool_calls=calls, raw=response)
    text = getattr(response, "text", None)
    if isinstance(text, str): return AgentOutput(text=text, tool_calls=[c for c in map(_tool_call_from, getattr(response, "tool_calls", None) or []) if c], raw=response)
    return AgentOutput(text=str(response), raw=response)
