"""L5 anomaly detection over audit events. Pure logic: feed events in, get alerts out.

Rules: policy_backend_degraded (OPA down/invalid), auth_failure_spike (per client, fed directly by observe_auth so the
audit-log throttle does not hide floods), deny_spike, call_spike, tool_after_blocked_input, output_withheld, and (after a learning
period of allowed calls per agent) new_domain and unusual_sequence. Denied calls never teach the
baseline, so an attacker cannot normalise a new domain by failing against it first.
Learning period: call-count based by default (`learn`). With `learn_seconds` > 0 it is time based instead: an
agent learns for that many seconds after its first allowed call, however many calls it makes (so a burst of calls
cannot end the period early). Baselines and first-seen times are rebuilt from the audit log at startup (see main.py).
"""
import time
from collections import defaultdict, deque


class Detector:
    def __init__(self, learn=50, call_limit=60, deny_limit=10, window=60.0, block_window=60.0,
                 cooldown=60.0, clock=time.time, auth_limit=10, learn_seconds=0.0):
        self.learn, self.call_limit, self.deny_limit, self.auth_limit = learn, call_limit, deny_limit, auth_limit
        self.learn_seconds = learn_seconds
        self._first: dict[str, float] = {}
        self.window, self.block_window, self.cooldown, self.clock = window, block_window, cooldown, clock
        self._calls, self._denies = defaultdict(deque), defaultdict(deque)
        self._auth_fails: dict[str, deque] = defaultdict(deque)
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

    def observe_auth(self, client: str, agent: str = "", now: float | None = None) -> list[dict]:
        """Count one failed authentication, keyed by client address (an attacker rotates claimed agent names).
        Called for every failure, before any log throttling. Never replayed from the log."""
        now = self.clock() if now is None else now
        if len(self._auth_fails) > 4096:
            self._auth_fails = defaultdict(deque, {k: q for k, q in self._auth_fails.items() if q and now - q[-1] <= self.window})
        n = self._bump(self._auth_fails[client], now)
        k = ("auth_failure_spike", client, "")
        if n >= self.auth_limit and now - self._last_alert.get(k, -1e18) >= self.cooldown:
            self._last_alert[k] = now
            return [{"rule": "auth_failure_spike", "severity": "high", "agent": agent or "?",
                     "detail": f"{n} failed authentications from {client} in {int(self.window)}s"}]
        return []

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
            if any(str(f.get("rule", "")).startswith("classifier_") for f in ev.get("findings", [])):
                alert("classifier_degraded", "high", "ML classifier failed; input screening may be rules-only")
            return out if emit else []

        denied = ev.get("decision") == "deny"
        if kind == "tool" and str(ev.get("reason", "")).startswith("opa "):
            alert("policy_backend_degraded", "high", f"OPA problem: {ev['reason']}")
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
        first = self._first.setdefault(agent, now)  # first *allowed* call; denied calls never start the clock
        learning = now - first < self.learn_seconds if self.learn_seconds > 0 else self._n[agent] <= self.learn
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
