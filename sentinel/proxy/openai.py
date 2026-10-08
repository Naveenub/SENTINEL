"""Model-traffic proxy: an OpenAI-compatible /v1/chat/completions front for any upstream
(OpenAI, vLLM, Ollama, LiteLLM, ...). The agent talks to SENTINEL instead of the provider and holds
no provider key; SENTINEL holds it (SENTINEL_UPSTREAM_KEY).

  request:   user messages -> L1 scan (block); tool-result messages -> L1 scan + wrapped <untrusted>
  response:  assistant text -> L4 scan (credentials withhold, PII/exfil redact)
             proposed tool_calls -> L2 preflight (allowlist, schema, hosts, OPA); any denial blocks the
             response. Rate limits and human approval still happen when the runtime executes the call.
  audit:     one "model" event per request (hashes only unless SENTINEL_LOG_CONTENT=1)

Not supported (fail closed): stream=true, because output cannot be scanned before it is sent.
Not scanned: non-text content parts (images, audio), system/assistant history, reasoning fields.
"""
import copy
import hashlib
import json
import logging
import os
from collections import OrderedDict

import httpx

from sentinel.input_filter.tagger import tag
from sentinel.models import Item, ScanRequest
from sentinel.pipeline import Pipeline
from sentinel.secrets.scanner import scan_output

_SOURCE = {"user": "user", "tool": "external", "function": "external"}
_CACHE_MAX = 4096


def _err(status: int, code: str, message: str, **extra):
    return status, {"error": {"type": "sentinel_blocked" if status == 403 else "sentinel_error",
                              "code": code, "message": message, **extra}}


class ModelProxy:
    def __init__(self, pipe: Pipeline, upstream_url: str, api_key: str = "", client: httpx.Client | None = None,
                 timeout: float = 120.0, block_mode: str = "error", toolcalls: str = "enforce"):
        if block_mode not in ("error", "refusal") or toolcalls not in ("enforce", "off"):
            raise ValueError("block_mode must be error|refusal and toolcalls must be enforce|off")
        base = upstream_url.rstrip("/")
        self.url = base + ("/chat/completions" if base.endswith("/v1") else "/v1/chat/completions")
        self.pipe, self.api_key, self.block_mode, self.toolcalls = pipe, api_key, block_mode, toolcalls
        self.client = client or httpx.Client(timeout=timeout)
        self._clean: OrderedDict[str, None] = OrderedDict()  # hashes of text that scanned with zero findings

    # -- helpers
    def _blocked(self, code: str, message: str, model: str, **extra):
        if self.block_mode == "error":
            return _err(403, code, message, **extra)
        # refusal mode: look like a normal completion so eval harnesses (garak) score it as a refusal
        return 200, {"id": "sentinel-block", "object": "chat.completion", "model": model or "sentinel",
                     "choices": [{"index": 0, "finish_reason": "content_filter",
                                  "message": {"role": "assistant", "content": f"[SENTINEL] blocked: {code}"}}],
                     "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                     "sentinel": {"code": code, **extra}}

    def _texts(self, msg: dict):
        """Yield (setter, text) for each text span in a message's content."""
        c = msg.get("content")
        if isinstance(c, str):
            yield (lambda v, m=msg: m.__setitem__("content", v)), c
        elif isinstance(c, list):
            for part in c:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    yield (lambda v, p=part: p.__setitem__("text", v)), part["text"]

    def _audit(self, agent: str, body: dict, decision: str, reason: str, **kw):
        raw = json.dumps(body, sort_keys=True, default=str)
        self.pipe.log.append({"type": "model", "agent": agent, "model": body.get("model"), "decision": decision,
                              "reason": reason, "req_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                              **kw, **({"request": body} if self.pipe.log_content else {})})

    # -- main entry
    def handle(self, agent: str, body: dict) -> tuple[int, dict]:
        model = str(body.get("model") or "")
        if not self.pipe.engine.has_agent(agent):
            self._audit(agent, body, "deny", "unknown agent")
            return _err(403, "unknown_agent", "agent is not defined in policy")
        if body.get("stream"):
            return _err(400, "streaming_unsupported", "stream=true is not supported through SENTINEL")
        msgs = body.get("messages")
        if not isinstance(msgs, list) or not all(isinstance(m, dict) for m in msgs):
            return _err(400, "bad_request", "messages must be a list of objects")

        # 1. inbound: scan what has not already scanned clean, then wrap tool results as untrusted data
        body = copy.deepcopy(body)
        msgs = body["messages"]  # from here on, only the copy is rewritten and forwarded
        todo: list[Item] = []
        for m in msgs:
            src = _SOURCE.get(m.get("role"))
            if not src:
                continue
            for _, text in self._texts(m):
                if hashlib.sha256(f"{src}|{text}".encode()).hexdigest() not in self._clean:
                    todo.append(Item(source=src, ref=f"model-proxy:{m.get('role')}", text=text))
        if todo:
            scan = self.pipe.scan(ScanRequest(agent=agent, items=todo))
            if scan.verdict == "block":
                rules = sorted({f.rule for f in scan.findings})
                self._audit(agent, body, "deny", "input blocked", in_findings=rules)
                return self._blocked("input_blocked", "request blocked by input filter", model, findings=rules)
            if not scan.findings:  # only cache fully clean text: ML-degraded passes get rescanned
                for it in todo:
                    self._clean[hashlib.sha256(f"{it.source}|{it.text}".encode()).hexdigest()] = None
                while len(self._clean) > _CACHE_MAX:
                    self._clean.popitem(last=False)
        for m in msgs:
            if m.get("role") in ("tool", "function"):
                for setter, text in list(self._texts(m)):
                    setter(tag(Item(source="external", ref=f"tool:{m.get('name') or m.get('tool_call_id') or 'result'}", text=text)))

        # 2. upstream (the agent's own credentials are never forwarded)
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            r = self.client.post(self.url, json=body, headers=headers)
        except httpx.HTTPError:
            logging.getLogger("sentinel.proxy").exception("upstream request failed")
            self._audit(agent, body, "allow", "upstream unreachable")
            return _err(502, "upstream_unreachable", "upstream model endpoint unreachable")
        try:
            data = r.json()
        except ValueError:
            data = None
        if r.status_code >= 400 or not isinstance(data, dict):
            self._audit(agent, body, "allow", f"upstream status {r.status_code}")
            return (r.status_code if r.status_code >= 400 else 502,
                    data if isinstance(data, dict) else _err(502, "bad_upstream", "upstream returned non-JSON")[1])

        # 3. outbound: scan text, preflight proposed tool calls
        out_findings: list[str] = []
        proposed: list[str] = []
        for choice in data.get("choices") or []:
            msg = choice.get("message") or {}
            for setter, text in list(self._texts(msg)):
                out = scan_output(text, [])
                out_findings += out.findings
                if out.block:
                    self._audit(agent, body, "deny", "output withheld", out_findings=sorted(set(out_findings)))
                    return self._blocked("output_withheld", "model output withheld by output scanner", model,
                                         findings=sorted(set(out_findings)))
                setter(out.text)
            for tc in (msg.get("tool_calls") or []) if self.toolcalls == "enforce" else []:
                fn = (tc or {}).get("function") or {}
                name = str(fn.get("name") or "")
                proposed.append(name)
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                    if not isinstance(args, dict):
                        raise ValueError
                except ValueError:
                    reason, ok = "tool call arguments are not a JSON object", False
                else:
                    d = self.pipe.engine.preflight(agent, name, args)
                    reason, ok = d.reason, d.decision == "allow"
                if not ok:
                    # recorded as a denied tool event so deny_spike / tool_after_blocked_input can see it
                    self.pipe.log.append({"type": "tool", "agent": agent, "tool": name, "decision": "deny",
                                          "reason": reason, "via": "model_proxy", "hosts": []})
                    self._audit(agent, body, "deny", "tool call denied", tool_calls=proposed)
                    return self._blocked("tool_denied", f"model proposed a tool call that policy forbids: {name}",
                                         model, tool=name, reason=reason)

        self._audit(agent, body, "allow", "ok", tool_calls=proposed, out_findings=sorted(set(out_findings)))
        return r.status_code, data


def from_env(pipe: Pipeline, client: httpx.Client | None = None) -> ModelProxy | None:
    url = os.getenv("SENTINEL_UPSTREAM_URL")
    if not url:
        return None
    return ModelProxy(pipe, url, os.getenv("SENTINEL_UPSTREAM_KEY", ""), client,
                      float(os.getenv("SENTINEL_UPSTREAM_TIMEOUT", "120")),
                      os.getenv("SENTINEL_PROXY_BLOCK_MODE", "error"),
                      os.getenv("SENTINEL_PROXY_TOOLCALLS", "enforce"))
