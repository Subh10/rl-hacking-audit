import inspect
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
class TargetType(str, Enum):
    MODEL="model"; AGENT="agent"; RAG="rag"; RL_SYSTEM="rl_system"; HTTP="http"; MCP="mcp"
@dataclass
class Target:
    name: str
    target_type: TargetType = TargetType.MODEL
    invoke: Callable[..., Any] | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)
    def _params(self):
        try: return inspect.signature(self.invoke).parameters
        except (TypeError, ValueError): return {}
    def supports(self, feature: str) -> bool: return feature in self.capabilities or feature in self._params()
    def run(self, prompt: str, *, history: list[dict[str, Any]] | None = None, **extras: Any) -> Any:
        if self.invoke is None: raise RuntimeError("Target has no invoke callable. Provide Target(..., invoke=...).")
        params=self._params(); var_kw=any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()); kwargs={}
        if "history" in params or var_kw: kwargs["history"]=history or []
        for key,value in extras.items():
            if value is not None and (key in params or var_kw): kwargs[key]=value
        return self.invoke(prompt, **kwargs)
