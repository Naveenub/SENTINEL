import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.main import create_app
from sentinel.sandbox.runner import RunResult
from sentinel.secrets.broker import TokenBroker
from sentinel.secrets.revocation import RevocationStore

POLICY = str(Path(__file__).parents[2] / "policies" / "agents.yaml")
ADMIN = {"X-Sentinel-Admin-Token": "adm"}


def test_revoke_jti_kills_only_that_token():
    b = TokenBroker(b"k" * 32)
    t1, j1 = b.issue("a", "t", ["s"]); t2, _ = b.issue("a", "t", ["s"])
    assert b.verify(t1) and b.verify(t2)
    b.revoke(j1)
    assert b.verify(t1) is None and b.verify(t2) is not None


def test_revoke_agent_kills_earlier_tokens_not_later_ones(monkeypatch):
    b = TokenBroker(b"k" * 32)
    t_old, _ = b.issue("a", "t", ["s"]); t_other, _ = b.issue("b", "t", ["s"])
    time.sleep(0.01)
    b.revoke_agent("a")
    time.sleep(0.01)
    t_new, _ = b.issue("a", "t", ["s"])
    assert b.verify(t_old) is None and b.verify(t_new) and b.verify(t_other)


def test_revocations_persist_across_restart(tmp_path):
    path = str(tmp_path / "r.db")
    b1 = TokenBroker(b"k" * 32, RevocationStore(path))
    tok, jti = b1.issue("a", "t", ["s"]); tok2, _ = b1.issue("z", "t", ["s"])
    time.sleep(0.01)
    b1.revoke(jti); b1.revoke_agent("z")
    b2 = TokenBroker(b"k" * 32, RevocationStore(path))   # new process, same file
    assert b2.verify(tok) is None and b2.verify(tok2) is None


def test_denylist_entries_are_pruned_after_they_could_matter():
    s = RevocationStore()
    s.revoke_jti("j", now=1000.0); s.revoke_agent("a", now=1000.0)
    assert s.is_revoked("j", "a", 999.0)
    s.revoke_jti("other", now=1000.0 + 400)               # any write prunes
    rows = s.db.execute("SELECT jti FROM revoked_jti").fetchall()
    assert rows == [("other",)] and s.db.execute("SELECT count(*) FROM revoked_agent").fetchone()[0] == 0


def test_token_without_iat_still_verifies_but_jti_revocation_applies():
    b = TokenBroker(b"k" * 32)
    tok, jti = b.issue("a", "t", [])
    b.revoke(jti)
    assert b.verify(tok) is None


class Rec:
    def __init__(self): self.env = None
    def run(self, spec, stdin, env):
        self.env = env
        return RunResult(0, "ok", "", False)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_AUDIT_KEY", "k" * 32)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "adm")
    monkeypatch.setenv("SENTINEL_VERIFIER_TOKEN", "ver")
    monkeypatch.setenv("SENTINEL_AUDIT_DB", str(tmp_path / "a.db"))
    monkeypatch.setenv("SENTINEL_POLICY", POLICY)
    sb = Rec()
    c = TestClient(create_app(sandbox=sb)); c.sb = sb
    return c


def test_token_is_revoked_when_the_tool_call_ends(client):
    r = client.post("/v1/tool/run", json={"agent": "research-bot", "tool": "summarize_report", "args": {"text": "x"}}).json()
    assert r["decision"] == "allow"
    tok = client.sb.env["SENTINEL_TOKEN"]
    v = client.post("/v1/token/verify", json={"token": tok}, headers={"X-Sentinel-Verifier-Token": "ver"}).json()
    assert v == {"valid": False, "claims": None}


def test_admin_revoke_endpoints_and_verify_auth(client):
    b = client.app  # same key as the gateway
    tok, jti = TokenBroker(b"k" * 32).issue("research-bot", "t", ["reports:read"])
    assert client.post("/v1/token/verify", json={"token": tok}).status_code == 403            # no credential
    assert client.post("/v1/token/verify", json={"token": tok}, headers={"X-Sentinel-Verifier-Token": "bad"}).status_code == 403
    ok = client.post("/v1/token/verify", json={"token": tok, "scope": "reports:read"}, headers={"X-Sentinel-Verifier-Token": "ver"}).json()
    assert ok["valid"] and ok["claims"]["jti"] == jti
    assert client.post(f"/v1/tokens/{jti}/revoke").status_code == 403                         # agents cannot revoke
    assert client.post(f"/v1/tokens/{jti}/revoke", headers=ADMIN).json()["revoked"] is True
    assert client.post("/v1/token/verify", json={"token": tok}, headers=ADMIN).json()["valid"] is False
    assert client.post("/v1/agents/research-bot/revoke-tokens", headers=ADMIN).status_code == 200
    kinds = [e["type"] for e in client.app.state.log.recent("revoke", 10)]
    assert kinds == ["revoke", "revoke"]                                                        # audited
    assert client.get("/v1/audit/verify", headers=ADMIN).json()["ok"] is True
