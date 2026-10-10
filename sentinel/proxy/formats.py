"""Wire formats the model proxy understands. A format knows where text and tool calls live in a
request/response; the proxy core (model.py) does the scanning, wrapping, preflight and audit."""
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterator


@dataclass
class Span:
    source: str          # "user" | "external"   (what L1 should treat it as)
    ref: str
    text: str
    set: Callable[[str], None]
    wrap: bool = False   # rewrite as <untrusted> data before forwarding


def _text_parts(content, put_str):
    """(setter, text) for a str content or each {"type":"text"} part of a list content."""
    if isinstance(content, str):
        yield put_str, content
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                yield (lambda v, p=part: p.__setitem__("text", v)), part["text"]


def _leaves(obj):
    """(setter, text) for every string value and object key in nested dicts/lists (tool-call inputs).
    Key setters are no-ops: keys are scanned, never rewritten."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield (lambda x: None), k
            if isinstance(v, str):
                yield (lambda x, o=obj, k=k: o.__setitem__(k, x)), v
            else:
                yield from _leaves(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                yield (lambda x, o=obj, i=i: o.__setitem__(i, x)), v
            else:
                yield from _leaves(v)


def _call_args(raw):
    """Decoded string leaves of a JSON-encoded arguments string (so escapes cannot hide text); raw string if not JSON."""
    if not isinstance(raw, str) or not raw:
        return
    try:
        obj = json.loads(raw)
    except ValueError:
        yield (lambda v: None), raw
        return
    if isinstance(obj, str):
        yield (lambda v: None), obj
    else:
        for _, text in _leaves(obj):
            yield (lambda v: None), text


def _kinds(content, text_types=("text",)):
    """Types of non-text parts in a content value (a plain str has none)."""
    if not isinstance(content, list):
        return []
    return [str(p.get("type") or "unknown") if isinstance(p, dict) else "unknown"
            for p in content if not (isinstance(p, dict) and p.get("type") in text_types)]


CHUNK = 32  # characters per emitted delta, so client UIs see token-like streaming (cosmetic; reply is already scanned)


def _slices(text: str, n: int = CHUNK):
    return [text[i:i + n] for i in range(0, len(text), n)] or [""]


def _sse(data: dict, event: str | None = None) -> bytes:
    head = f"event: {event}\n" if event else ""
    return f"{head}data: {json.dumps(data, separators=(',', ':'))}\n\n".encode()


class OpenAIFormat:
    name = "openai"
    path = "/chat/completions"

    def valid(self, body: dict) -> bool:
        m = body.get("messages")
        return isinstance(m, list) and all(isinstance(x, dict) for x in m)

    def upstream_headers(self, api_key: str, version: str) -> dict:
        return {"Authorization": f"Bearer {api_key}"} if api_key else {}

    def inbound(self, body: dict, extra: frozenset = frozenset()) -> list[Span]:
        out = []
        for m in body["messages"]:
            role = m.get("role")
            kind = "system" if role in ("system", "developer") else role
            if kind in extra:  # opt-in (agents.yaml `scan`): scanned, never rewritten
                # system is developer-set (user tolerance); replayed assistant turns are external (stricter)
                src = "user" if kind == "system" else "external"
                for setter, text in _text_parts(m.get("content"), lambda v, m=m: m.__setitem__("content", v)):
                    out.append(Span(src, f"model-proxy:{kind}", text, setter))
                if kind == "assistant":  # replayed tool-call arguments (JSON strings) and legacy function_call
                    calls = [(tc or {}).get("function") or {} for tc in m.get("tool_calls") or []]
                    if isinstance(m.get("function_call"), dict):
                        calls.append(m["function_call"])
                    for fn in calls:
                        for setter, text in _call_args(fn.get("arguments") if isinstance(fn, dict) else None):
                            out.append(Span(src, "model-proxy:assistant", text, setter))
                continue
            src = {"user": "user", "tool": "external", "function": "external"}.get(role)
            if not src:
                continue
            ref = f"tool:{m.get('name') or m.get('tool_call_id') or 'result'}" if src == "external" else "model-proxy:user"
            for setter, text in _text_parts(m.get("content"), lambda v, m=m: m.__setitem__("content", v)):
                out.append(Span(src, ref, text, setter, wrap=src == "external"))
        return out

    def non_text(self, body: dict) -> list[str]:
        """Non-text part types in scanned roles (user, tool, function), e.g. image_url, input_audio, file."""
        out: list[str] = []
        for m in body["messages"]:
            if m.get("role") in ("user", "tool", "function"):
                out += _kinds(m.get("content"))
        return sorted(set(out))

    def outbound_texts(self, data: dict):
        for c in data.get("choices") or []:
            msg = c.get("message") or {}
            yield from _text_parts(msg.get("content"), lambda v, m=msg: m.__setitem__("content", v))

    def tool_calls(self, data: dict):
        """(name, args | None); None = arguments were not a JSON object."""
        import json
        for c in data.get("choices") or []:
            for tc in (c.get("message") or {}).get("tool_calls") or []:
                fn = (tc or {}).get("function") or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    args = None
                yield str(fn.get("name") or ""), args if isinstance(args, dict) else None


    def is_message(self, data: dict) -> bool:
        return isinstance(data.get("choices"), list)

    def sse(self, data: dict, request: dict) -> Iterator[bytes]:
        """Re-emit a complete, already-scanned chat.completion as chat.completion.chunk SSE events."""
        base = {"id": data.get("id") or "sentinel-stream", "object": "chat.completion.chunk",
                "created": data.get("created") or int(time.time()), "model": data.get("model") or request.get("model") or ""}
        if data.get("system_fingerprint"):
            base["system_fingerprint"] = data["system_fingerprint"]

        def chunk(choices, **extra):
            return _sse({**base, "choices": choices, **extra})

        choices = [c for c in data.get("choices") or [] if isinstance(c, dict)]
        for i, c in enumerate(choices):
            idx = c.get("index", i)
            msg = c.get("message") or {}
            first = {"role": msg.get("role") or "assistant"}
            # fields we do not interpret (reasoning_content, annotations, ...) ride along with the role chunk
            first.update({k: v for k, v in msg.items() if k not in ("role", "content", "tool_calls", "function_call")})
            if "content" in msg and msg["content"] is not None:
                first["content"] = ""
            yield chunk([{"index": idx, "delta": first, "finish_reason": None}])
            content = msg.get("content")
            if isinstance(content, list):  # content parts: flatten text for the delta stream
                content = "".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
            if isinstance(content, str) and content:
                for piece in _slices(content):
                    yield chunk([{"index": idx, "delta": {"content": piece}, "finish_reason": None}])
            for j, tc in enumerate(msg.get("tool_calls") or []):
                fn = (tc or {}).get("function") or {}
                args = fn.get("arguments") or ""
                yield chunk([{"index": idx, "finish_reason": None, "delta": {"tool_calls": [{
                    "index": j, "id": (tc or {}).get("id"), "type": (tc or {}).get("type") or "function",
                    "function": {"name": fn.get("name") or "", "arguments": ""}}]}}])
                for piece in _slices(args) if args else []:
                    yield chunk([{"index": idx, "finish_reason": None, "delta": {"tool_calls": [{
                        "index": j, "function": {"arguments": piece}}]}}])
            if isinstance(msg.get("function_call"), dict):
                yield chunk([{"index": idx, "delta": {"function_call": msg["function_call"]}, "finish_reason": None}])
            yield chunk([{"index": idx, "delta": {}, "finish_reason": c.get("finish_reason") or "stop"}])
        opts = request.get("stream_options")
        if isinstance(opts, dict) and opts.get("include_usage"):
            yield chunk([], usage=data.get("usage") or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
        yield b"data: [DONE]\n\n"

    def error(self, status: int, code: str, message: str, **extra) -> dict:
        return {"error": {"type": "sentinel_blocked" if status == 403 else "sentinel_error",
                          "code": code, "message": message, **extra}}

    def refusal(self, code: str, model: str, extra: dict) -> dict:
        return {"id": "sentinel-block", "object": "chat.completion", "model": model or "sentinel",
                "choices": [{"index": 0, "finish_reason": "content_filter",
                             "message": {"role": "assistant", "content": f"[SENTINEL] blocked: {code}"}}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "sentinel": {"code": code, **extra}}


class AnthropicFormat:
    """Anthropic Messages API. `system` is trusted (developer-set) and not scanned unless the agent opts in with `scan: [system]`; tool_result blocks
    are external data; assistant turns are skipped unless the agent opts in with `scan: [assistant]` (text, tool_use inputs, thinking); image/document blocks are not scanned (block them per agent with non_text: block)."""
    name = "anthropic"
    path = "/messages"
    DEFAULT_VERSION = "2023-06-01"

    def valid(self, body: dict) -> bool:
        m = body.get("messages")
        return isinstance(m, list) and all(isinstance(x, dict) for x in m)

    def upstream_headers(self, api_key: str, version: str) -> dict:
        # the agent's own x-api-key and anthropic-beta are never forwarded
        return {"anthropic-version": version or self.DEFAULT_VERSION, **({"x-api-key": api_key} if api_key else {})}

    def inbound(self, body: dict, extra: frozenset = frozenset()) -> list[Span]:
        out = []
        if "system" in extra:  # opt-in: top-level system prompt (str or text blocks); developer-set, user tolerance
            for setter, text in _text_parts(body.get("system"), lambda v: body.__setitem__("system", v)):
                out.append(Span("user", "model-proxy:system", text, setter))
        for m in body["messages"]:
            if m.get("role") == "assistant" and "assistant" in extra:  # replayed history: external tolerance
                for setter, text in _text_parts(m.get("content"), lambda v, m=m: m.__setitem__("content", v)):
                    out.append(Span("external", "model-proxy:assistant", text, setter))
                for blk in (m.get("content") if isinstance(m.get("content"), list) else []):
                    if not isinstance(blk, dict):
                        continue
                    if blk.get("type") in ("tool_use", "server_tool_use"):  # replayed tool inputs
                        for setter, text in _leaves(blk.get("input")):
                            out.append(Span("external", "model-proxy:assistant", text, setter))
                    elif blk.get("type") == "thinking" and isinstance(blk.get("thinking"), str):
                        out.append(Span("external", "model-proxy:assistant", blk["thinking"],
                                        lambda v, b=blk: b.__setitem__("thinking", v)))
                continue
            if m.get("role") != "user":
                continue
            c = m.get("content")
            for setter, text in _text_parts(c, lambda v, m=m: m.__setitem__("content", v)):
                out.append(Span("user", "model-proxy:user", text, setter))
            for blk in (c if isinstance(c, list) else []):
                if isinstance(blk, dict) and blk.get("type") == "tool_result":
                    ref = f"tool:{blk.get('tool_use_id') or 'result'}"
                    for setter, text in _text_parts(blk.get("content"), lambda v, b=blk: b.__setitem__("content", v)):
                        out.append(Span("external", ref, text, setter, wrap=True))
        return out

    def non_text(self, body: dict) -> list[str]:
        """Non-text block types in user turns, including inside tool_result content (image, document, ...)."""
        out: list[str] = []
        for m in body["messages"]:
            if m.get("role") != "user":
                continue
            c = m.get("content")
            out += _kinds(c, ("text", "tool_result"))
            for blk in (c if isinstance(c, list) else []):
                if isinstance(blk, dict) and blk.get("type") == "tool_result":
                    out += _kinds(blk.get("content"))
        return sorted(set(out))

    def outbound_texts(self, data: dict):
        for blk in data.get("content") or []:
            if isinstance(blk, dict) and blk.get("type") == "text" and isinstance(blk.get("text"), str):
                yield (lambda v, b=blk: b.__setitem__("text", v)), blk["text"]

    def tool_calls(self, data: dict):
        for blk in data.get("content") or []:
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                args: Any = blk.get("input", {})
                yield str(blk.get("name") or ""), args if isinstance(args, dict) else None


    def is_message(self, data: dict) -> bool:
        return data.get("type") == "message"

    def sse(self, data: dict, request: dict) -> Iterator[bytes]:
        """Re-emit a complete, already-scanned message as the Messages streaming event sequence."""
        usage = data.get("usage") or {}
        start = {**{k: v for k, v in data.items() if k not in ("content", "stop_reason", "stop_sequence", "usage")},
                 "content": [], "stop_reason": None, "stop_sequence": None, "usage": {**usage, "output_tokens": 0}}
        yield _sse({"type": "message_start", "message": start}, "message_start")
        yield _sse({"type": "ping"}, "ping")
        blocks = [b for b in data.get("content") or [] if isinstance(b, dict)]
        for i, b in enumerate(blocks):
            t = b.get("type")

            def delta(d, i=i):
                return _sse({"type": "content_block_delta", "index": i, "delta": d}, "content_block_delta")

            if t == "text":
                yield _sse({"type": "content_block_start", "index": i,
                            "content_block": {"type": "text", "text": ""}}, "content_block_start")
                for piece in _slices(b["text"]) if b.get("text") else []:
                    yield delta({"type": "text_delta", "text": piece})
                for cit in b.get("citations") or []:
                    yield delta({"type": "citations_delta", "citation": cit})
            elif t in ("tool_use", "server_tool_use"):
                yield _sse({"type": "content_block_start", "index": i,
                            "content_block": {**{k: v for k, v in b.items() if k != "input"}, "input": {}}},
                           "content_block_start")
                for piece in _slices(json.dumps(b.get("input", {}))):
                    yield delta({"type": "input_json_delta", "partial_json": piece})
            elif t == "thinking":
                yield _sse({"type": "content_block_start", "index": i,
                            "content_block": {"type": "thinking", "thinking": ""}}, "content_block_start")
                for piece in _slices(b["thinking"]) if b.get("thinking") else []:
                    yield delta({"type": "thinking_delta", "thinking": piece})
                if b.get("signature"):
                    yield delta({"type": "signature_delta", "signature": b["signature"]})
            else:  # redacted_thinking, *_tool_result and anything newer arrive whole in content_block_start
                yield _sse({"type": "content_block_start", "index": i, "content_block": b}, "content_block_start")
            yield _sse({"type": "content_block_stop", "index": i}, "content_block_stop")
        yield _sse({"type": "message_delta", "delta": {"stop_reason": data.get("stop_reason"),
                                                       "stop_sequence": data.get("stop_sequence")},
                    "usage": {"output_tokens": usage.get("output_tokens", 0)}}, "message_delta")
        yield _sse({"type": "message_stop"}, "message_stop")

    def error(self, status: int, code: str, message: str, **extra) -> dict:
        return {"type": "error", "error": {"type": "sentinel_blocked" if status == 403 else "sentinel_error",
                                           "code": code, "message": message, **extra}}

    def refusal(self, code: str, model: str, extra: dict) -> dict:
        return {"id": "msg_sentinel_block", "type": "message", "role": "assistant", "model": model or "sentinel",
                "content": [{"type": "text", "text": f"[SENTINEL] blocked: {code}"}],
                "stop_reason": "refusal", "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0}, "sentinel": {"code": code, **extra}}


FORMATS = {"openai": OpenAIFormat(), "anthropic": AnthropicFormat()}
