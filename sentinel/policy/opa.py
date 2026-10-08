"""L2 policy backend: Open Policy Agent over its REST API.

YAML still says what a tool IS (JSON Schema, sandbox, secrets, rate limit). OPA says who may call it:
it must return {"effect": "allow"|"deny"|"approve", "reason": str} from SENTINEL_OPA_PATH.
Fail closed: any error, timeout, undefined result or unknown effect is a deny. OPA can only add
restrictions on top of the YAML checks (schema, allowed_hosts, approval: required still apply).
"""
import logging

import httpx

EFFECTS = ("allow", "deny", "approve")


class OPAClient:
    def __init__(self, url: str, path: str = "sentinel/authz/decision", timeout: float = 2.0,
                 token: str = "", client: httpx.Client | None = None):
        self.url = f"{url.rstrip('/')}/v1/data/{path.strip('/')}"
        self.base = url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.client = client or httpx.Client(timeout=timeout)
        self.name = "opa"

    def ping(self) -> None:
        """Raises if OPA is unreachable or the decision document is undefined. Run at startup."""
        r = self.client.get(f"{self.base}/health", headers=self.headers)
        r.raise_for_status()
        r = self.client.post(self.url, json={"input": {}}, headers=self.headers)
        r.raise_for_status()
        if "result" not in r.json():
            raise RuntimeError(f"OPA decision document is undefined at {self.url}; is the policy loaded?")

    def decide(self, agent: str, tool: str, args: dict, hosts: list[str]) -> tuple[str, str]:
        try:
            r = self.client.post(self.url, headers=self.headers,
                                 json={"input": {"agent": agent, "tool": tool, "args": args, "hosts": hosts}})
            r.raise_for_status()
            res = r.json().get("result")
        except Exception:  # details to the server log only, never to the caller
            logging.getLogger("sentinel.opa").exception("OPA request failed")
            return "deny", "opa unavailable (fail closed)"
        if not isinstance(res, dict) or res.get("effect") not in EFFECTS:
            return "deny", "opa returned no valid decision"
        return res["effect"], str(res.get("reason") or f"opa: {res['effect']}")
