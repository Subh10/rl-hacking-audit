from __future__ import annotations
from collections.abc import Mapping
from typing import Any
from .base import Oracle
from .canary import CanaryOracle, ForbiddenTokenOracle
from .tools import ExfilOracle, ToolPolicyOracle
class OracleSpecError(ValueError):pass
REQUIRED_KEYS={"canary":("value",),"forbidden_tokens":("tokens",),"tool_policy":(),"exfil":("secret",)}
def validate_spec(spec):
    kind=spec.get("type")
    if kind not in REQUIRED_KEYS:raise OracleSpecError(f"unknown oracle type: {kind!r} (expected one of {', '.join(REQUIRED_KEYS)})")
    missing=[k for k in REQUIRED_KEYS[kind] if k not in spec]
    if missing:raise OracleSpecError(f"oracle '{kind}' is missing required key(s): {', '.join(missing)}")
def build_oracle(spec):
    kind=spec.get("type")
    try:
        if kind=="canary":return CanaryOracle(value=spec["value"],encodings=spec.get("encodings",True))
        if kind=="forbidden_tokens":return ForbiddenTokenOracle(tokens=list(spec["tokens"]))
        if kind=="tool_policy":return ToolPolicyOracle(forbidden_tools=list(spec.get("forbidden_tools",[])),allowed_tools=spec.get("allowed_tools"),canary=spec.get("canary"))
        if kind=="exfil":return ExfilOracle(secret=spec["secret"])
    except KeyError as exc:raise OracleSpecError(f"oracle '{kind}' is missing required key {exc}") from exc
    raise OracleSpecError(f"unknown oracle type: {kind!r} (expected canary, forbidden_tokens, tool_policy, exfil)")
