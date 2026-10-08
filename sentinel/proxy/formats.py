"""Wire formats the model proxy understands. A format knows where text and tool calls live in a
request/response; the proxy core (model.py) does the scanning, wrapping, preflight and audit."""
from dataclasses import dataclass
from typing import Any, Callable


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


class OpenAIFormat:
    name = "openai"
    path = "/chat/completions"

    def valid(self, body: dict) -> bool:
        m = body.get("messages")
        return isinstance(m, list) and all(isinstance(x, dict) for x in m)

    def upstream_headers(self, api_key: str, version: str) -> dict:
        return {"Authorization": f"Bearer {api_key}"} if api_key else {}

    def inbound(self, body: dict) -> list[Span]:
        out = []
        for m in body["messages"]:
            role = m.get("role")
            src = {"user": "user", "tool": "external", "function": "external"}.get(role)
            if not src:
                continue
            ref = f"tool:{m.get('name') or m.get('tool_call_id') or 'result'}" if src == "external" else "model-proxy:user"
            for setter, text in _text_parts(m.get("content"), lambda v, m=m: m.__setitem__("content", v)):
                out.append(Span(src, ref, text, setter, wrap=src == "external"))
        return out

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
    """Anthropic Messages API. `system` is trusted (developer-set) and not scanned; tool_result blocks
    are external data; assistant turns are skipped; image/document blocks are not scanned."""
    name = "anthropic"
    path = "/messages"
    DEFAULT_VERSION = "2023-06-01"

    def valid(self, body: dict) -> bool:
        m = body.get("messages")
        return isinstance(m, list) and all(isinstance(x, dict) for x in m)

    def upstream_headers(self, api_key: str, version: str) -> dict:
        # the agent's own x-api-key and anthropic-beta are never forwarded
        return {"anthropic-version": version or self.DEFAULT_VERSION, **({"x-api-key": api_key} if api_key else {})}

    def inbound(self, body: dict) -> list[Span]:
        out = []
        for m in body["messages"]:
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

    def outbound_texts(self, data: dict):
        for blk in data.get("content") or []:
            if isinstance(blk, dict) and blk.get("type") == "text" and isinstance(blk.get("text"), str):
                yield (lambda v, b=blk: b.__setitem__("text", v)), blk["text"]

    def tool_calls(self, data: dict):
        for blk in data.get("content") or []:
            if isinstance(blk, dict) and blk.get("type") == "tool_use":
                args: Any = blk.get("input", {})
                yield str(blk.get("name") or ""), args if isinstance(args, dict) else None

    def error(self, status: int, code: str, message: str, **extra) -> dict:
        return {"type": "error", "error": {"type": "sentinel_blocked" if status == 403 else "sentinel_error",
                                           "code": code, "message": message, **extra}}

    def refusal(self, code: str, model: str, extra: dict) -> dict:
        return {"id": "msg_sentinel_block", "type": "message", "role": "assistant", "model": model or "sentinel",
                "content": [{"type": "text", "text": f"[SENTINEL] blocked: {code}"}],
                "stop_reason": "refusal", "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0}, "sentinel": {"code": code, **extra}}


FORMATS = {"openai": OpenAIFormat(), "anthropic": AnthropicFormat()}
