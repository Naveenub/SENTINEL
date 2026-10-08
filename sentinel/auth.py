"""Optional per-agent authentication for the agent-facing endpoints.

Off unless tokens are configured. When on, every agent-facing endpoint (/v1/scan, /v1/tool/*, and the
model proxy) requires a token that belongs to the agent it claims to act as, so agent A cannot use
agent B's policy, rate limits, approvals or audit identity. Admin and verifier endpoints keep their own
credentials; /healthz stays open but reports only {"ok": true}.

Configure with SENTINEL_AGENT_TOKENS="research-bot=<token>,garak-target=<token>" and/or
SENTINEL_AGENT_TOKENS_FILE=<json>, e.g. {"research-bot": "<token>", "garak-target": ["<new>", "<old>"]}
(a list allows rotation: both work until you remove the old one). Both sources are merged.

Presented as `Authorization: Bearer <token>`, `x-api-key: <token>` or `X-Sentinel-Agent-Token: <token>`,
so the OpenAI and Anthropic SDKs only need `api_key=<agent token>`. The proxy never forwards these
headers upstream.

Fail closed: once auth is on, an agent with no token configured cannot authenticate at all. Startup
refuses tokens that are short, belong to an unknown agent, are shared by two agents, or equal the admin
or verifier token (an agent must never be able to approve its own requests).
"""
import hmac
import json
import logging
import os

MIN_LEN = 16
_HEADERS = ("x-sentinel-agent-token", "authorization", "x-api-key")


def _parse_env(raw: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in filter(None, (p.strip() for p in raw.split(","))):
        agent, sep, tok = part.partition("=")
        if not sep or not agent.strip() or not tok.strip():
            raise ValueError("SENTINEL_AGENT_TOKENS entries must look like agent=token")
        out.setdefault(agent.strip(), []).append(tok.strip())
    return out


def _parse_file(path: str) -> dict[str, list[str]]:
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("SENTINEL_AGENT_TOKENS_FILE must be a JSON object of agent -> token | [tokens]")
    out: dict[str, list[str]] = {}
    for agent, v in data.items():
        toks = [v] if isinstance(v, str) else v
        if not isinstance(toks, list) or not all(isinstance(t, str) for t in toks):
            raise ValueError(f"tokens for {agent!r} must be a string or a list of strings")
        out[str(agent)] = toks
    return out


class AgentAuth:
    def __init__(self, tokens: dict[str, list[str]], agents: set[str], reserved: list[bytes] = ()):
        seen: dict[str, str] = {}
        for agent, toks in tokens.items():
            if agent not in agents:
                raise ValueError(f"agent token configured for {agent!r}, which is not defined in policy")
            for t in toks:
                if len(t) < MIN_LEN:
                    raise ValueError(f"token for {agent!r} is shorter than {MIN_LEN} characters")
                if t in seen and seen[t] != agent:
                    raise ValueError(f"the same token is configured for {seen[t]!r} and {agent!r}")
                if any(r and hmac.compare_digest(t.encode(), r) for r in reserved):
                    raise ValueError(f"token for {agent!r} must differ from the admin and verifier tokens")
                seen[t] = agent
        self._pairs = [(a, t.encode()) for a, toks in tokens.items() for t in toks]
        missing = sorted(agents - set(tokens))
        if missing:
            logging.getLogger("sentinel.auth").warning(
                "agent auth is on and these policy agents have no token (they cannot authenticate): %s", ", ".join(missing))

    @classmethod
    def from_env(cls, agents: set[str], reserved: list[bytes] = ()) -> "AgentAuth | None":
        tokens: dict[str, list[str]] = {}
        sources = [_parse_env(os.getenv("SENTINEL_AGENT_TOKENS", ""))]
        if os.getenv("SENTINEL_AGENT_TOKENS_FILE"):
            sources.append(_parse_file(os.environ["SENTINEL_AGENT_TOKENS_FILE"]))
        for src in sources:
            for agent, toks in src.items():
                tokens.setdefault(agent, []).extend(toks)
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
        p, who = presented.encode(), None
        for agent, tok in self._pairs:  # no early exit: every token is compared
            if hmac.compare_digest(p, tok):
                who = agent
        return who, True
