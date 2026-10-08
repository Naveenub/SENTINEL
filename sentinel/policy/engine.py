import hashlib
import json
import secrets
import threading
import time
from collections import defaultdict, deque

import yaml
from jsonschema import Draft202012Validator

from sentinel.models import ToolDecision
from sentinel.policy.approvals import ApprovalStore
from sentinel.policy.hosts import extract_hosts
from sentinel.sandbox.egress import EgressAllowlist

_UNITS = {"sec": 1, "min": 60, "hour": 3600}


def _rate(s: str) -> tuple[int, int]:
    n, unit = s.split("/")
    return int(n), _UNITS[unit]


def _fp(agent: str, tool: str, args: dict) -> str:
    return hashlib.sha256(json.dumps([agent, tool, args], sort_keys=True, default=str).encode()).hexdigest()


class PolicyEngine:
    """Deny-by-default. Order: allowlist -> arg schema -> rate limit -> human approval."""

    def __init__(self, path: str, opa=None, approvals: ApprovalStore | None = None):
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
        self._opa = opa  # None = YAML decides; else OPA must also allow (see policy/opa.py)
        self._agents = set((cfg.get("agents") or {}).keys())
        self._tools: dict[tuple[str, str], dict] = {}
        for agent, a in (cfg.get("agents") or {}).items():
            for tool, spec in (a.get("tools") or {}).items():
                if "schema" not in spec:  # fail closed at load, not at call time
                    raise ValueError(f"{agent}.{tool}: 'schema' is required")
                Draft202012Validator.check_schema(spec["schema"])
                sb = spec.get("sandbox")
                if sb is not None and not (sb.get("image") and isinstance(sb.get("command"), list)):
                    raise ValueError(f"{agent}.{tool}: sandbox needs 'image' and a 'command' list")
                if sb is not None and sb.get("network", "none") not in ("none", "proxy"):
                    raise ValueError(f"{agent}.{tool}: sandbox.network must be none or proxy")
                if spec.get("secrets") and sb is None:
                    raise ValueError(f"{agent}.{tool}: 'secrets' requires a sandbox")
                self._tools[(agent, tool)] = {
                    "sandbox": sb,
                    "secrets": list(spec.get("secrets") or []),
                    "token_ttl": int(spec.get("token_ttl", 60)),
                    "hosts": EgressAllowlist(spec["allowed_hosts"]) if "allowed_hosts" in spec else None,
                    "validator": Draft202012Validator(spec["schema"]),
                    "rate": _rate(spec["rate_limit"]) if "rate_limit" in spec else None,
                    "approval": spec.get("approval") == "required",
                }
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self._approvals = approvals or ApprovalStore()  # in-memory unless the caller passes a persistent store
        self._lock = threading.Lock()

    def has_agent(self, agent: str) -> bool:
        return agent in self._agents

    def _check(self, agent: str, tool: str, args: dict) -> tuple[ToolDecision | None, bool]:
        """Side-effect-free checks: allowlist -> schema -> hosts -> OPA. Returns (deny | None, approval_needed)."""
        spec = self._tools.get((agent, tool))
        if spec is None:
            return ToolDecision(decision="deny", reason="not in allowlist"), False
        errs = sorted(e.message for e in spec["validator"].iter_errors(args))
        if errs:
            return ToolDecision(decision="deny", reason=f"schema: {errs[0]}"), False
        if spec["hosts"] is not None:  # every URL in the args must point at an allowed host
            bad = [h for h in extract_hosts(args) if not spec["hosts"].allows(h)]
            if bad:
                return ToolDecision(decision="deny", reason=f"host not allowed: {bad[0]}"), False
        need = spec["approval"]
        if self._opa is not None:
            effect, reason = self._opa.decide(agent, tool, args, extract_hosts(args))
            if effect == "deny":
                return ToolDecision(decision="deny", reason=reason), False
            need = need or effect == "approve"  # stricter wins
        return None, need

    def preflight(self, agent: str, tool: str, args: dict) -> ToolDecision:
        """Can this call ever be allowed? No rate limit, no approval record: used on model-proposed
        tool calls, which are authorized again (for real) when the runtime executes them."""
        deny, _ = self._check(agent, tool, args)
        return deny or ToolDecision(decision="allow", reason="preflight ok")

    def authorize(self, agent: str, tool: str, args: dict, approval_id: str | None = None) -> ToolDecision:
        deny, need_approval = self._check(agent, tool, args)
        if deny:
            return deny
        spec = self._tools[(agent, tool)]
        with self._lock:
            if spec["rate"]:
                n, window = spec["rate"]
                q, now = self._hits[(agent, tool)], time.monotonic()
                while q and now - q[0] > window:
                    q.popleft()
                if len(q) >= n:
                    return ToolDecision(decision="deny", reason="rate limit exceeded")
                q.append(now)
            if not need_approval:
                return ToolDecision(decision="allow", reason="policy ok")
            fp = _fp(agent, tool, args)
            if approval_id is None:
                aid = secrets.token_urlsafe(12)
                if not self._approvals.create(aid, fp, agent, tool, args):
                    return ToolDecision(decision="deny", reason="too many pending approvals")
                return ToolDecision(decision="pending", reason="human approval required", approval_id=aid)
            rec = self._approvals.get(approval_id)
            if rec is None or rec["fp"] != fp:
                return ToolDecision(decision="deny", reason="approval does not match this call")
            if rec["state"] == "pending":
                return ToolDecision(decision="pending", reason="awaiting approval", approval_id=approval_id)
            state = self._approvals.consume(approval_id)  # single use
            if state is None:
                return ToolDecision(decision="deny", reason="approval does not match this call")
            if state == "approved":
                return ToolDecision(decision="allow", reason="human approved")
            return ToolDecision(decision="deny", reason="human denied")

    def exec_spec(self, agent: str, tool: str) -> dict | None:
        """Sandbox config for a tool, or None if it is unknown or has no sandbox (so /run denies it)."""
        spec = self._tools.get((agent, tool))
        if not spec or spec["sandbox"] is None:
            return None
        return {"sandbox": spec["sandbox"], "secrets": spec["secrets"], "token_ttl": spec["token_ttl"]}

    def resolve(self, approval_id: str, approve: bool) -> bool:
        return self._approvals.resolve(approval_id, approve)

    def pending(self) -> list[dict]:
        return self._approvals.pending()
