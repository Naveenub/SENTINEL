"""L4: short-lived, scoped, signed tokens. Issued per tool call and injected into the sandbox
environment only; they never enter the prompt, the model context, or the audit log.

Tokens are bearer credentials signed with a key derived from SENTINEL_AUDIT_KEY (domain-separated).
Services that trust SENTINEL verify them with the same key. For third-party APIs, exchange the token
for a vendor credential inside a service you control.
# ponytail: stateless, so no single-use/revocation; add a jti denylist if you need revocation.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time

MAX_TTL = 300


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class TokenBroker:
    def __init__(self, master_key: bytes):
        self._key = hmac.new(master_key, b"sentinel-token-v1", hashlib.sha256).digest()

    def _sig(self, body: str) -> str:
        return _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())

    def issue(self, agent: str, tool: str, scopes: list[str], ttl: int = 60) -> tuple[str, str]:
        jti = secrets.token_hex(8)
        claims = {"agent": agent, "tool": tool, "scopes": sorted(scopes), "jti": jti,
                  "exp": int(time.time()) + max(1, min(ttl, MAX_TTL))}
        body = _b64(json.dumps(claims, sort_keys=True).encode())
        return f"snt1.{body}.{self._sig(body)}", jti

    def verify(self, token: str, scope: str | None = None) -> dict | None:
        try:
            prefix, body, sig = token.split(".")
            if prefix != "snt1" or not hmac.compare_digest(sig, self._sig(body)):
                return None
            claims = json.loads(_unb64(body))
        except Exception:
            return None
        if claims["exp"] < time.time() or (scope and scope not in claims["scopes"]):
            return None
        return claims
