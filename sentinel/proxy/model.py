"""Model-traffic proxy for OpenAI-compatible (/v1/chat/completions) and Anthropic (/v1/messages) APIs.
The agent talks to SENTINEL instead of the provider and holds no provider key; SENTINEL holds it
(SENTINEL_UPSTREAM_KEY).

  request:   user text -> L1 scan (block); tool results -> L1 scan + wrapped <untrusted>
  response:  model text -> L4 scan (credentials withhold, PII/exfil redact)
             proposed tool calls -> L2 preflight (allowlist, schema, hosts, OPA); any denial blocks the
             response. Rate limits and human approval still happen when the runtime executes the call.
  audit:     one "model" event per request (hashes only unless SENTINEL_LOG_CONTENT=1)

stream=true is served as *buffered streaming* (SENTINEL_PROXY_STREAM=buffered, the default): the upstream is
called non-streaming, the whole reply is scanned and preflighted, and only then re-emitted to the agent as SSE in
the caller's format. Nothing unscanned is ever sent, but there is no time-to-first-token benefit. Real pass-through
streaming cannot be made safe for credential withholding. SENTINEL_PROXY_STREAM=reject restores the old 400.
Blocks and upstream errors on a stream request are returned as ordinary JSON errors (status 403/502/...), as the
providers themselves do for failures before the first event.
Not scanned: non-text content (images, audio, documents), system prompt, assistant history, reasoning.
One upstream serves both formats only if it speaks both (e.g. LiteLLM); otherwise use the one you run.
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
from sentinel.proxy.formats import FORMATS
from sentinel.secrets.scanner import scan_output

_CACHE_MAX = 4096


class ModelProxy:
    def __init__(self, pipe: Pipeline, upstream_url: str, api_key: str = "", client: httpx.Client | None = None,
                 timeout: float = 120.0, block_mode: str = "error", toolcalls: str = "enforce",
                 stream: str = "buffered"):
        if block_mode not in ("error", "refusal") or toolcalls not in ("enforce", "off") \
                or stream not in ("buffered", "reject"):
            raise ValueError("block_mode must be error|refusal, toolcalls enforce|off, stream buffered|reject")
        self.stream = stream
        self.base = upstream_url.rstrip("/")
        self.pipe, self.api_key, self.block_mode, self.toolcalls = pipe, api_key, block_mode, toolcalls
        self.client = client or httpx.Client(timeout=timeout)
        self._clean: OrderedDict[str, None] = OrderedDict()  # hashes of text that scanned with zero findings

    def _url(self, fmt) -> str:
        return self.base + fmt.path if self.base.endswith("/v1") else f"{self.base}/v1{fmt.path}"

    def _blocked(self, fmt, code: str, message: str, model: str, **extra):
        if self.block_mode == "error":
            return 403, fmt.error(403, code, message, **extra)
        # refusal mode: look like a normal reply so eval harnesses (garak) score it as a refusal
        return 200, fmt.refusal(code, model, extra)

    def streams(self, body: dict, status: int, payload: dict, api: str) -> bool:
        """True when this response should go out as SSE: the caller asked for a stream and the result is a
        normal message (including a refusal-mode block). Errors stay plain JSON."""
        return bool(body.get("stream")) and self.stream == "buffered" and status == 200 \
            and isinstance(payload, dict) and FORMATS[api].is_message(payload)

    def events(self, api: str, payload: dict, body: dict):
        return FORMATS[api].sse(payload, body)

    def _audit(self, fmt, agent: str, body: dict, decision: str, reason: str, **kw):
        raw = json.dumps(body, sort_keys=True, default=str)
        self.pipe.log.append({"type": "model", "api": fmt.name, "agent": agent, "model": body.get("model"),
                              "decision": decision, "reason": reason,
                              "req_sha256": hashlib.sha256(raw.encode()).hexdigest(), **kw,
                              **({"request": body} if self.pipe.log_content else {})})

    def handle(self, agent: str, body: dict, api: str = "openai", version: str = "") -> tuple[int, dict]:
        fmt = FORMATS[api]
        model = str(body.get("model") or "")
        stream = bool(body.get("stream"))
        ex = {"stream": "buffered"} if stream and self.stream == "buffered" else {}
        aud = lambda d, r, **k: self._audit(fmt, agent, body, d, r, **ex, **k)  # noqa: E731 (body rebinds below)
        if not self.pipe.engine.has_agent(agent):
            aud("deny", "unknown agent")
            return 403, fmt.error(403, "unknown_agent", "agent is not defined in policy")
        if stream and self.stream == "reject":
            return 400, fmt.error(400, "streaming_unsupported", "stream=true is not supported through SENTINEL")
        if not fmt.valid(body):
            return 400, fmt.error(400, "bad_request", "messages must be a list of objects")

        # 1. inbound: scan what has not already scanned clean, then wrap tool results as untrusted data
        body = copy.deepcopy(body)  # from here on, only the copy is rewritten and forwarded
        if stream:  # upstream is always called non-streaming; the reply is re-emitted after scanning
            body.pop("stream", None)
            body.pop("stream_options", None)
        spans = fmt.inbound(body)
        key = lambda s: hashlib.sha256(f"{s.source}|{s.text}".encode()).hexdigest()  # noqa: E731
        todo = [s for s in spans if key(s) not in self._clean]
        if todo:
            scan = self.pipe.scan(ScanRequest(agent=agent, items=[Item(source=s.source, ref=s.ref, text=s.text) for s in todo]))
            if scan.verdict == "block":
                rules = sorted({f.rule for f in scan.findings})
                aud("deny", "input blocked", in_findings=rules)
                return self._blocked(fmt, "input_blocked", "request blocked by input filter", model, findings=rules)
            if not scan.findings:  # only cache fully clean text: ML-degraded passes get rescanned
                for s in todo:
                    self._clean[key(s)] = None
                while len(self._clean) > _CACHE_MAX:
                    self._clean.popitem(last=False)
        for s in spans:
            if s.wrap:
                s.set(tag(Item(source="external", ref=s.ref, text=s.text)))

        # 2. upstream (the agent's own credentials are never forwarded)
        try:
            r = self.client.post(self._url(fmt), json=body, headers=fmt.upstream_headers(self.api_key, version))
        except httpx.HTTPError:
            logging.getLogger("sentinel.proxy").exception("upstream request failed")
            aud("allow", "upstream unreachable")
            return 502, fmt.error(502, "upstream_unreachable", "upstream model endpoint unreachable")
        try:
            data = r.json()
        except ValueError:
            data = None
        if r.status_code >= 400 or not isinstance(data, dict):
            aud("allow", f"upstream status {r.status_code}")
            return (r.status_code, data) if r.status_code >= 400 and isinstance(data, dict) else \
                (502, fmt.error(502, "bad_upstream", "upstream returned non-JSON"))

        # 3. outbound: scan text, preflight proposed tool calls
        out_findings: list[str] = []
        for setter, text in list(fmt.outbound_texts(data)):
            out = scan_output(text, [])
            out_findings += out.findings
            if out.block:
                aud("deny", "output withheld", out_findings=sorted(set(out_findings)))
                return self._blocked(fmt, "output_withheld", "model output withheld by output scanner", model,
                                     findings=sorted(set(out_findings)))
            setter(out.text)
        proposed: list[str] = []
        for name, args in (list(fmt.tool_calls(data)) if self.toolcalls == "enforce" else []):
            proposed.append(name)
            if args is None:
                reason, ok = "tool call arguments are not a JSON object", False
            else:
                d = self.pipe.engine.preflight(agent, name, args)
                reason, ok = d.reason, d.decision == "allow"
            if not ok:
                # recorded as a denied tool event so deny_spike / tool_after_blocked_input can see it
                self.pipe.log.append({"type": "tool", "agent": agent, "tool": name, "decision": "deny",
                                      "reason": reason, "via": "model_proxy", "hosts": []})
                aud("deny", "tool call denied", tool_calls=proposed)
                return self._blocked(fmt, "tool_denied", f"model proposed a tool call that policy forbids: {name}",
                                     model, tool=name, reason=reason)

        aud("allow", "ok", tool_calls=proposed, out_findings=sorted(set(out_findings)))
        return r.status_code, data


def from_env(pipe: Pipeline, client: httpx.Client | None = None) -> ModelProxy | None:
    url = os.getenv("SENTINEL_UPSTREAM_URL")
    if not url:
        return None
    return ModelProxy(pipe, url, os.getenv("SENTINEL_UPSTREAM_KEY", ""), client,
                      float(os.getenv("SENTINEL_UPSTREAM_TIMEOUT", "120")),
                      os.getenv("SENTINEL_PROXY_BLOCK_MODE", "error"),
                      os.getenv("SENTINEL_PROXY_TOOLCALLS", "enforce"),
                      os.getenv("SENTINEL_PROXY_STREAM", "buffered"))
