"""Optional per-agent authentication for the agent-facing endpoints.

Off unless tokens are configured. When on, every agent-facing endpoint (/v1/scan, /v1/tool/*, and the
model proxy) requires a token that belongs to the agent it claims to act as, so agent A cannot use
agent B's policy, rate limits, approvals or audit identity. Admin and verifier endpoints keep their own
credentials; /healthz accepts any valid agent token or the admin token and reports only {"ok": true}.

Configure with SENTINEL_AGENT_TOKENS="research-bot=<token>,garak-target=<token>" and/or
SENTINEL_AGENT_TOKENS_FILE=<json>, e.g. {"research-bot": "<token>", "garak-target": ["<new>", "<old>"]}
(a list allows rotation: both work until you remove the old one). Both sources are merged.

Presented as `Authorization: Bearer <token>`, `x-api-key: <token>` or `X-Sentinel-Agent-Token: <token>`,
so the OpenAI and Anthropic SDKs only need `api_key=<agent token>`. The proxy never forwards these
headers upstream.

Fail closed: once auth is on, an agent with no token configured cannot authenticate at all. Startup
refuses tokens that are short, belong to an unknown agent, are shared by two agents, or equal the admin
or verifier token (an agent must never be able to approve its own requests).

Expiry (optional): in the token file a token may be an object, {"token": "<t>", "expires": "2026-12-31T00:00:00Z"}
(ISO 8601; no timezone means UTC). An expired token is rejected like an invalid one. Env tokens take the same
end date as a suffix: SENTINEL_AGENT_TOKENS="research-bot=<token>;expires=2026-12-31T00:00:00Z". Set
SENTINEL_REQUIRE_TOKEN_EXPIRY=1 to refuse to start with any token (env or file) that has no expiry.

Lockout: FailureLimiter blocks a client address after repeated *invalid* tokens (guessing), with 429 + Retry-After.
Missing tokens and valid-token-wrong-agent (403) do not count.
"""
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone

from sentinel.limits import LimitStore

MIN_LEN = 16
_HEADERS = ("x-sentinel-agent-token", "authorization", "x-api-key")


def _parse_env(raw: str) -> dict[str, list]:
    out: dict[str, list] = {}
    for part in filter(None, (p.strip() for p in raw.split(","))):
        agent, sep, tok = part.partition("=")
        tok, _, exp = tok.partition(";expires=")
        if not sep or not agent.strip() or not tok.strip():
            raise ValueError("SENTINEL_AGENT_TOKENS entries must look like agent=token or agent=token;expires=<ISO 8601>")
        entry = (tok.strip(), _parse_expiry(exp.strip(), agent.strip())) if exp.strip() else tok.strip()
        out.setdefault(agent.strip(), []).append(entry)
    return out


def _parse_expiry(v: str, agent: str) -> float:
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"expires for {agent!r} must be an ISO 8601 timestamp, got {v!r}") from None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()


def _parse_file(path: str) -> dict[str, list]:
    """agent -> list of token strings or (token, expires_epoch) pairs."""
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("SENTINEL_AGENT_TOKENS_FILE must be a JSON object of agent -> token | [tokens]")
    out: dict[str, list] = {}
    for agent, v in data.items():
        items = v if isinstance(v, list) else [v]
        toks: list = []
        for t in items:
            if isinstance(t, str):
                toks.append(t)
            elif isinstance(t, dict) and isinstance(t.get("token"), str) and isinstance(t.get("expires"), str):
                toks.append((t["token"], _parse_expiry(t["expires"], str(agent))))
            else:
                raise ValueError(f"tokens for {agent!r} must be strings or {{\"token\", \"expires\"}} objects")
        out[str(agent)] = toks
    return out


class FailureLimiter:
    """Blocks a client after `max_failures` invalid tokens within `window` seconds, for `lockout` seconds.
    Keyed by client address, not agent, so an attacker cannot lock a legitimate agent out by guessing its name.
    Behind a reverse proxy every caller shares the proxy's address; enforce per-client limits there as well.
    State lives in `store` (SQLite when a path is given), so lockouts survive a restart."""

    def __init__(self, max_failures: int = 10, window: float = 60.0, lockout: float = 300.0, clock=time.time,
                 store: LimitStore | None = None):
        self.max_failures, self.window, self.lockout, self.clock = max_failures, window, lockout, clock
        self.store = store or LimitStore()

    def retry_after(self, client: str) -> int:
        """Seconds the client must wait (0 = not locked out)."""
        now = self.clock()
        left = self.store.locked_until(client, now) - now
        return int(left) + 1 if left > 0 else 0

    def failure(self, client: str) -> None:
        self.store.record_failure(client, self.max_failures, self.window, self.lockout, self.clock())

    @classmethod
    def from_env(cls, store: LimitStore | None = None) -> "FailureLimiter":
        return cls(int(os.getenv("SENTINEL_AUTH_MAX_FAILURES", "10")),
                   float(os.getenv("SENTINEL_AUTH_FAILURE_WINDOW", "60")),
                   float(os.getenv("SENTINEL_AUTH_LOCKOUT_SECONDS", "300")), store=store)


class AgentAuth:
    def __init__(self, tokens: dict[str, list], agents: set[str], reserved: list[bytes] = (), now=time.time):
        self._now = now
        seen: dict[str, str] = {}
        expiries: dict[tuple[str, str], float] = {}
        for agent, toks in tokens.items():
            if agent not in agents:
                raise ValueError(f"agent token configured for {agent!r}, which is not defined in policy")
            norm = []
            for t in toks:
                if isinstance(t, tuple):
                    t, exp = t
                    expiries[(agent, t)] = exp
                norm.append(t)
            tokens[agent] = toks = norm
            for t in toks:
                if len(t) < MIN_LEN:
                    raise ValueError(f"token for {agent!r} is shorter than {MIN_LEN} characters")
                if t in seen and seen[t] != agent:
                    raise ValueError(f"the same token is configured for {seen[t]!r} and {agent!r}")
                if any(r and hmac.compare_digest(t.encode(), r) for r in reserved):
                    raise ValueError(f"token for {agent!r} must differ from the admin and verifier tokens")
                seen[t] = agent
        self._pairs = [(a, t.encode(), expiries.get((a, t))) for a, toks in tokens.items() for t in toks]
        missing = sorted(agents - set(tokens))
        if missing:
            logging.getLogger("sentinel.auth").warning(
                "agent auth is on and these policy agents have no token (they cannot authenticate): %s", ", ".join(missing))

    @classmethod
    def from_env(cls, agents: set[str], reserved: list[bytes] = ()) -> "AgentAuth | None":
        tokens: dict[str, list] = {}
        sources = [_parse_env(os.getenv("SENTINEL_AGENT_TOKENS", ""))]
        if os.getenv("SENTINEL_AGENT_TOKENS_FILE"):
            sources.append(_parse_file(os.environ["SENTINEL_AGENT_TOKENS_FILE"]))
        for src in sources:
            for agent, toks in src.items():
                tokens.setdefault(agent, []).extend(toks)
        if os.getenv("SENTINEL_REQUIRE_TOKEN_EXPIRY") == "1":
            bare = sorted(a for a, toks in tokens.items() if any(isinstance(t, str) for t in toks))
            if bare:  # fail closed at startup, like short or shared tokens
                raise ValueError(f"SENTINEL_REQUIRE_TOKEN_EXPIRY=1: tokens without an expiry for {bare}")
        return cls(tokens, agents, reserved) if tokens else None

    def identify(self, headers) -> tuple[str | None, bool]:
        """(agent the presented token belongs to | None, whether any token was presented)."""
        presented = None
        for h in _HEADERS:
            v = headers.get(h)
            if v:
                presented = v[7:] if h == "authorization" and v[:7].lower() == "bearer " else v
                break
        if not presented:
            return None, False
        p, who, now = presented.encode(), None, self._now()
        for agent, tok, exp in self._pairs:  # no early exit: every token is compared
            if hmac.compare_digest(p, tok) and (exp is None or exp > now):
                who = agent
        return who, True

    def expired(self, headers) -> bool:
        """True when the presented token is a configured one past its expiry (for a clearer audit reason)."""
        for h in _HEADERS:
            v = headers.get(h)
            if v:
                p = (v[7:] if h == "authorization" and v[:7].lower() == "bearer " else v).encode()
                now = self._now()
                return any(hmac.compare_digest(p, tok) and exp is not None and exp <= now for _, tok, exp in self._pairs)
        return False
