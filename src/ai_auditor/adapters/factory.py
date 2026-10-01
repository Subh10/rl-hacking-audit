from __future__ import annotations
import importlib
import json
from typing import Any
from ..core.target import Target, TargetType
from .http import AnthropicMessages, GenericHTTP, OpenAICompatible
from .mock import hardened_agent, vulnerable_agent

def target_from_spec(spec: str, *, base_url: str | None = None, body: str | None = None, response_path: str | None = None, headers: dict[str, str] | None = None, max_tokens: int | None = None, temperature: float | None = None) -> Target:
    kind, _, rest = spec.partition(":")
    caps = ["system", "tools"]
    if kind == "demo":
        agents = {"vulnerable": vulnerable_agent, "hardened": hardened_agent}
        if rest not in agents: raise ValueError(f"unknown demo agent {rest!r}; choose from: {', '.join(agents)}")
        return Target(spec, TargetType.AGENT, invoke=agents[rest], capabilities=caps, metadata={"simulated": True})
    if kind == "openai":
        kwargs: dict[str, Any] = {"model": rest, "headers": headers or {}, "max_tokens": max_tokens, "temperature": temperature}
        if base_url: kwargs["base_url"] = base_url
        return Target(spec, TargetType.MODEL, invoke=OpenAICompatible(**kwargs), capabilities=caps)
    if kind == "anthropic":
        kwargs = {"model": rest, "headers": headers or {}, "temperature": temperature}
        if base_url: kwargs["base_url"] = base_url
        if max_tokens: kwargs["max_tokens"] = max_tokens
        return Target(spec, TargetType.MODEL, invoke=AnthropicMessages(**kwargs), capabilities=caps)
    if kind in {"http", "https"}:
        return Target(spec, TargetType.HTTP, invoke=GenericHTTP(url=f"{kind}:{rest}", body=json.loads(body) if body else {"prompt": "{prompt}"}, response_path=response_path or "response", headers=headers or {}))
    if kind == "py":
        module, _, attr = rest.partition(":")
        if not module or not attr: raise ValueError("python targets look like py:<module>:<callable>, e.g. py:myapp.agent:run")
        fn = getattr(importlib.import_module(module), attr)
        if isinstance(fn, Target): return fn
        return Target(spec, TargetType.AGENT, invoke=fn)
    raise ValueError(f"unknown target spec {spec!r}; expected demo:, openai:, anthropic:, http(s): or py:")
