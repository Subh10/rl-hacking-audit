from __future__ import annotations
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from ..findings.schema import Severity
from ..oracles.factory import OracleSpecError,validate_spec
from .model import Scenario
class ScenarioError(ValueError):pass
_REQUIRED=("id","title","category","severity","user","payloads","oracle")
def _from_dict(data,source):
    missing=[k for k in _REQUIRED if k not in data]
    if missing:raise ScenarioError(f"{source}: scenario {data.get('id','?')!r} is missing: {', '.join(missing)}")
    if not isinstance(data["payloads"],list) or not data["payloads"]:raise ScenarioError(f"{source}: scenario {data['id']!r} needs a non-empty 'payloads' list")
    try:severity=Severity.parse(data["severity"]);validate_spec(data["oracle"])
    except (KeyError,OracleSpecError) as exc:raise ScenarioError(f"{source}: scenario {data['id']!r}: {exc}") from exc
    known=set(Scenario.__dataclass_fields__);extra=set(data)-known
    if extra:raise ScenarioError(f"{source}: scenario {data['id']!r} has unknown field(s): {', '.join(sorted(extra))}")
    return Scenario(**{**data,"severity":severity,"description":data.get("description",data["title"])})
def load_scenarios(path):
    p=Path(path)
    if p.is_dir():
        out=[]
        for f in sorted(p.iterdir()):
            if f.suffix.lower() in {".json",".yaml",".yml"}:out.extend(load_scenarios(f))
        return out
    text=p.read_text(encoding="utf-8")
    if p.suffix.lower()==".json":data=json.loads(text)
    else:
        try:import yaml
        except ImportError as exc:raise ScenarioError("YAML scenarios need PyYAML: pip install 'ai-auditor[yaml]'") from exc
        data=yaml.safe_load(text)
    items=data if isinstance(data,list) else data.get("scenarios",[data]) if isinstance(data,dict) else []
    return [_from_dict(dict(item),str(p)) for item in items]
