"""Live check that `redacted_thinking: strip` is safe: an extended-thinking tool loop must still return 200,
and a stale redacted_thinking block must be stripped (audit shows redacted_thinking_stripped).

Run against a running SENTINEL whose upstream is the real Anthropic API, with `redacted_thinking: strip` on AGENT:
  SENTINEL_AUDIT_DB=sentinel_audit.db python scripts/verify_thinking_loop.py [http://localhost:8080] [agent] [model]
Optional env: SENTINEL_AGENT_TOKEN (if agent auth is on). The agent must allow a `web_fetch` tool (research-bot does);
tool results are stubbed, nothing is fetched. Exit 0 = both checks passed.
"""
import os
import sys

import httpx

from sentinel.audit.log import AuditLog

URL = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080").rstrip("/")
AGENT = sys.argv[2] if len(sys.argv) > 2 else "research-bot"
MODEL = sys.argv[3] if len(sys.argv) > 3 else os.getenv("VERIFY_MODEL", "claude-sonnet-4-5")
ENDPOINT = f"{URL}/proxy/{AGENT}/v1/messages"
HDRS = {"anthropic-version": "2023-06-01", "content-type": "application/json",
        **({"x-sentinel-agent-token": os.environ["SENTINEL_AGENT_TOKEN"]} if os.getenv("SENTINEL_AGENT_TOKEN") else {})}
THINK = {"type": "enabled", "budget_tokens": 1024}
TOOLS = [{"name": "web_fetch", "description": "Fetch a URL and return its text.",
          "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}]
db = AuditLog(os.getenv("SENTINEL_AUDIT_DB", "sentinel_audit.db"), os.environ["SENTINEL_AUDIT_KEY"].encode())


def post(messages, **kw):
    return httpx.post(ENDPOINT, headers=HDRS, timeout=300,
                      json={"model": MODEL, "max_tokens": 4096, "thinking": THINK, "messages": messages, **kw})


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


# 1. extended-thinking tool loop, every round replayed in full through the proxy
msgs = [{"role": "user", "content": "Fetch https://docs.python.org/3/ first. Only after you see its result, fetch "
                                    "https://docs.python.org/3/library/ . Then reply with the single word done."}]
rounds = 0
for _ in range(8):
    r = post(msgs, tools=TOOLS)
    if r.status_code != 200:
        fail(f"tool loop round {rounds + 1}: HTTP {r.status_code} {r.text[:300]}")
    data = r.json()
    msgs.append({"role": "assistant", "content": data["content"]})  # unmodified, as the API requires
    uses = [b for b in data["content"] if b.get("type") == "tool_use"]
    if not uses:
        break
    rounds += 1
    msgs.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": b["id"], "content": "ok (stub)"}
                                             for b in uses]})
if rounds < 2:
    fail(f"model made {rounds} tool call round(s); need >= 2 to exercise the loop (rerun or adjust the prompt)")
print(f"OK  tool loop: {rounds} tool rounds, all 200")

# 2. stale redacted_thinking in an earlier turn must be stripped before it reaches upstream
before = len(db.recent("model", 1000))
r = post([{"role": "user", "content": "hi"},
          {"role": "assistant", "content": [{"type": "redacted_thinking", "data": "STALE-SYNTHETIC"},
                                            {"type": "text", "text": "hello"}]},
          {"role": "user", "content": "reply with the single word ok"}])
if r.status_code != 200:
    fail(f"stale redacted_thinking: HTTP {r.status_code} {r.text[:300]} (is `redacted_thinking: strip` set on {AGENT}?)")
ev = db.recent("model", 1)[0]
if ev.get("redacted_thinking_stripped", 0) < 1:
    fail(f"200, but audit event lacks redacted_thinking_stripped: {ev}")
print(f"OK  stale redacted_thinking stripped ({ev['redacted_thinking_stripped']}), upstream accepted the request")
