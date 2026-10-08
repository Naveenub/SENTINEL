"""L5 anomaly detection over audit events. Pure logic: feed events in, get alerts out.

Rules: deny_spike, call_spike, tool_after_blocked_input, output_withheld, and (after a learning
period of allowed calls per agent) new_domain and unusual_sequence. Denied calls never teach the
baseline, so an attacker cannot normalise a new domain by failing against it first.
# ponytail: baselines are rebuilt from the audit log at startup (see main.py), but the learning
# period is call-count based, not time based; tune SENTINEL_LEARN_CALLS for your traffic.
"""
import time
from collections import defaultdict, deque


class Detector:
    def __init__(self, learn=50, call_limit=60, deny_limit=10, window=60.0, block_window=60.0,
                 cooldown=60.0, clock=time.time):
        self.learn, self.call_limit, self.deny_limit = learn, call_limit, deny_limit
        self.window, self.block_window, self.cooldown, self.clock = window, block_window, cooldown, clock
        self._calls, self._denies = defaultdict(deque), defaultdict(deque)
        self._hosts, self._pairs = defaultdict(set), defaultdict(set)
        self._n: dict[str, int] = defaultdict(int)
        self._last_tool: dict[str, str] = {}
        self._last_block: dict[str, float] = {}
        self._last_alert: dict[tuple, float] = {}

    def _bump(self, q: deque, now: float) -> int:
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        return len(q)

    def observe(self, ev: dict, now: float | None = None, emit: bool = True) -> list[dict]:
        kind = ev.get("type")
        if kind not in ("scan", "tool", "run"):  # includes "alert": never react to our own output
            return []
        now = self.clock() if now is None else now
        agent, tool = ev.get("agent", "?"), ev.get("tool", "")
        out: list[dict] = []

        def alert(rule: str, severity: str, detail: str, key: str = ""):
            k = (rule, agent, key)
            if now - self._last_alert.get(k, -1e18) >= self.cooldown:
                self._last_alert[k] = now
                out.append({"rule": rule, "severity": severity, "agent": agent, "detail": detail})

        if kind == "scan":
            if ev.get("verdict") == "block":
                self._last_block[agent] = now
            return out if emit else []

        denied = ev.get("decision") == "deny"
        if denied:
            n = self._bump(self._denies[agent], now)
            if n >= self.deny_limit:
                alert("deny_spike", "high", f"{n} denied calls in {int(self.window)}s")
        if kind == "run":
            if ev.get("withheld"):
                alert("output_withheld", "high", f"{tool}: output withheld ({', '.join(ev.get('findings', []))})", tool)
            return out if emit else []

        lb = self._last_block.get(agent)
        if lb is not None and now - lb <= self.block_window:
            alert("tool_after_blocked_input", "high", f"{tool} requested {int(now - lb)}s after input was blocked", tool)
        n = self._bump(self._calls[agent], now)
        if n > self.call_limit:
            alert("call_spike", "medium", f"{n} tool calls in {int(self.window)}s")
        if denied:
            return out if emit else []

        self._n[agent] += 1
        learning = self._n[agent] <= self.learn
        for h in ev.get("hosts", []):
            if h not in self._hosts[agent]:
                if not learning:
                    alert("new_domain", "medium", f"first request to {h}", h)
                self._hosts[agent].add(h)
        prev, self._last_tool[agent] = self._last_tool.get(agent), tool
        if prev and (prev, tool) not in self._pairs[agent]:
            if not learning:
                alert("unusual_sequence", "medium", f"{prev} -> {tool} never seen before", f"{prev}>{tool}")
            self._pairs[agent].add((prev, tool))
        return out if emit else []
