"""L4: short-lived, scoped, signed tokens. Issued per tool call and injected into the sandbox
environment only; they never enter the prompt, the model context, or the audit log.

Tokens are bearer credentials signed with a key derived from SENTINEL_AUDIT_KEY (domain-separated).
Services that trust SENTINEL verify them with the same key. For third-party APIs, exchange the token
for a vendor credential inside a service you control.
Revocation: verify() consults a RevocationStore (jti denylist + per-agent cutoff), so a token can be
killed before it expires. Services must verify through the gateway (POST /v1/token/verify) to see
revocations; verifying offline with the shared key checks signature and expiry only.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time

from sentinel.secrets.revocation import RevocationStore

MAX_TTL = 300


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class TokenBroker:
    def __init__(self, master_key: bytes, store: RevocationStore | None = None):
        self._key = hmac.new(master_key, b"sentinel-token-v1", hashlib.sha256).digest()
        self.store = store or RevocationStore()  # in-memory unless the caller supplies a persistent one

    def revoke(self, jti: str, reason: str = "") -> None:
        self.store.revoke_jti(jti, reason)

    def revoke_agent(self, agent: str) -> float:
        return self.store.revoke_agent(agent)

    def _sig(self, body: str) -> str:
        return _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())

    def issue(self, agent: str, tool: str, scopes: list[str], ttl: int = 60) -> tuple[str, str]:
        jti = secrets.token_hex(8)
        now = time.time()
        claims = {"agent": agent, "tool": tool, "scopes": sorted(scopes), "jti": jti,
                  "iat": round(now, 3), "exp": int(now) + max(1, min(ttl, MAX_TTL))}
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
        if self.store.is_revoked(claims["jti"], claims["agent"], claims.get("iat", 0.0)):
            return None
        return claims
