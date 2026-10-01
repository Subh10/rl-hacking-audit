"""Zero-dependency HTTP adapters (stdlib ``urllib``): OpenAI-compatible, Anthropic Messages, generic JSON.

OpenAI-compatible covers OpenAI and any server that speaks the same wire format (vLLM, Ollama, LM Studio,
OpenRouter, Together, Groq ...). Every adapter is a plain callable ``(prompt, history, system, tools) -> AgentOutput``
so it drops straight into ``Target(invoke=...)``.
"""
from __future__ import annotations
import json, os, time, urllib.error, urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from ..core.output import AgentOutput, ToolCall, normalize
Transport = Callable[[str, dict[str,str], dict[str,Any], float], dict[str,Any]]
_RETRY_CODES={408,409,429,500,502,503,504}
class AdapterError(RuntimeError): pass
def urllib_transport(url,headers,body,timeout):
    request=urllib.request.Request(url,data=json.dumps(body).encode(),headers=headers,method="POST")
    with urllib.request.urlopen(request,timeout=timeout) as response:return json.loads(response.read().decode("utf-8"))
def post_json(url,headers,body,*,timeout=60.0,retries=3,backoff=1.0,transport=None,sleep=time.sleep):
    if not url.lower().startswith(("http://","https://")):raise AdapterError(f"refusing non-HTTP URL: {url!r}")
    send=transport or urllib_transport; last=None
    for attempt in range(max(1,retries)):
        try:return send(url,{"Content-Type":"application/json",**headers},body,timeout)
        except urllib.error.HTTPError as exc:
            detail=exc.read().decode("utf-8","replace")[:300] if hasattr(exc,"read") else ""; last=AdapterError(f"HTTP {exc.code} from {url}: {detail}")
            if exc.code not in _RETRY_CODES: raise last from exc
        except (urllib.error.URLError,TimeoutError,ConnectionError) as exc:last=AdapterError(f"network error calling {url}: {exc}")
        if attempt<retries-1:sleep(backoff*(2**attempt))
    raise last or AdapterError("request failed")
def _history_turns(history):return [(str(h.get("prompt","")),normalize(h.get("response","")).text) for h in history or []]
def _dig(data,path):
    for part in path.split("."):data=data[int(part)] if isinstance(data,list) else data[part]
    return data
@dataclass
class OpenAICompatible:
    model:str; base_url:str="https://api.openai.com/v1"; api_key:str|None=None; api_key_env:str="OPENAI_API_KEY"; temperature:float|None=None; max_tokens:int|None=None; timeout:float=60.0; headers:dict[str,str]=field(default_factory=dict); transport:Transport|None=None
    def _key(self):
        key=self.api_key or os.environ.get(self.api_key_env)
        if not key and "api.openai.com" in self.base_url:raise AdapterError(f"set {self.api_key_env} (or pass api_key) to call {self.base_url}")
        return key
    def __call__(self,prompt,history=None,system=None,tools=None):
        messages=[{"role":"system","content":system}] if system else []
        for user,assistant in _history_turns(history):messages += [{"role":"user","content":user},{"role":"assistant","content":assistant}]
        messages.append({"role":"user","content":prompt}); body={"model":self.model,"messages":messages}
        if self.temperature is not None:body["temperature"]=self.temperature
        if self.max_tokens is not None:body["max_tokens"]=self.max_tokens
        if tools:body["tools"]=[{"type":"function","function":{"name":t["name"],"description":t.get("description",""),"parameters":t.get("parameters",{"type":"object","properties":{}})}} for t in tools]
        key=self._key(); data=post_json(self.base_url.rstrip("/")+"/chat/completions",{**({"Authorization":f"Bearer {key}"} if key else {}),**self.headers},body,timeout=self.timeout,transport=self.transport)
        try:message=data["choices"][0]["message"]
        except (KeyError,IndexError,TypeError) as exc:raise AdapterError(f"unexpected response shape: {str(data)[:200]}") from exc
        return AgentOutput(text=message.get("content") or "",tool_calls=normalize({"tool_calls":message.get("tool_calls") or []}).tool_calls,raw=data)
@dataclass
class AnthropicMessages:
    model:str; base_url:str="https://api.anthropic.com/v1"; api_key:str|None=None; api_key_env:str="ANTHROPIC_API_KEY"; max_tokens:int=1024; temperature:float|None=None; timeout:float=60.0; version:str="2023-06-01"; headers:dict[str,str]=field(default_factory=dict); transport:Transport|None=None
    def __call__(self,prompt,history=None,system=None,tools=None):
        key=self.api_key or os.environ.get(self.api_key_env)
        if not key:raise AdapterError(f"set {self.api_key_env} (or pass api_key) to call the Anthropic API")
        messages=[]
        for user,assistant in _history_turns(history):messages += [{"role":"user","content":user},{"role":"assistant","content":assistant or "(no text)"}]
        messages.append({"role":"user","content":prompt}); body={"model":self.model,"max_tokens":self.max_tokens,"messages":messages}
        if system:body["system"]=system
        if self.temperature is not None:body["temperature"]=self.temperature
        if tools:body["tools"]=[{"name":t["name"],"description":t.get("description",""),"input_schema":t.get("parameters",{"type":"object","properties":{}})} for t in tools]
        data=post_json(self.base_url.rstrip("/")+"/messages",{"x-api-key":key,"anthropic-version":self.version,**self.headers},body,timeout=self.timeout,transport=self.transport)
        text=[]; calls=[]
        for block in data.get("content",[]):
            if block.get("type")=="text":text.append(block.get("text",""))
            elif block.get("type")=="tool_use":calls.append(ToolCall(block.get("name",""),block.get("input") or {}))
        return AgentOutput(text="".join(text),tool_calls=calls,raw=data)
def _fill(obj,prompt):
    if isinstance(obj,str):return obj.replace("{prompt}",prompt)
    if isinstance(obj,list):return [_fill(o,prompt) for o in obj]
    if isinstance(obj,dict):return {k:_fill(v,prompt) for k,v in obj.items()}
    return obj
@dataclass
class GenericHTTP:
    url:str; body:dict[str,Any]=field(default_factory=lambda:{"prompt":"{prompt}"}); response_path:str="response"; headers:dict[str,str]=field(default_factory=dict); timeout:float=60.0; transport:Transport|None=None
    def __call__(self,prompt,history=None):
        data=post_json(self.url,self.headers,_fill(self.body,prompt),timeout=self.timeout,transport=self.transport)
        try:value=_dig(data,self.response_path)
        except (KeyError,IndexError,TypeError,ValueError) as exc:raise AdapterError(f"response_path {self.response_path!r} not found in: {str(data)[:200]}") from exc
        return normalize(value if isinstance(value,(str,dict)) else str(value))