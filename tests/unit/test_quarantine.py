from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.main import create_app

ADMIN = {"X-Sentinel-Admin-Token": "adm"}
POLICY = str(Path(__file__).parents[2] / "policies" / "agents.yaml")
OK = {"agent": "research-bot", "tool": "web_fetch", "args": {"url": "https://example.com"}}
BAD = {"agent": "research-bot", "tool": "nope", "args": {}}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_AUDIT_KEY", "k" * 32)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "adm")
    monkeypatch.setenv("SENTINEL_AUDIT_DB", str(tmp_path / "a.db"))
    monkeypatch.setenv("SENTINEL_POLICY", POLICY)
    monkeypatch.setenv("SENTINEL_ALERT_BLOCK", "deny_spike")
    monkeypatch.setenv("SENTINEL_DENY_LIMIT", "3")
    return monkeypatch


def authorize(c, body=OK):
    return c.post("/v1/tool/authorize", json=body).json()


def trip(c):
    for _ in range(3):
        authorize(c, BAD)


def test_alert_quarantines_agent_across_tool_scan_and_restart(env):
    c = TestClient(create_app())
    assert authorize(c)["decision"] == "allow"
    trip(c)
    d = authorize(c)
    assert d["decision"] == "deny" and d["reason"] == "agent quarantined (deny_spike)"
    scan = c.post("/v1/scan", json={"agent": "research-bot", "items": [{"source": "user", "text": "hi"}]}).json()
    assert scan["verdict"] == "block" and scan["findings"][0]["rule"] == "agent_quarantined"
    assert [q["agent"] for q in c.get("/v1/quarantine", headers=ADMIN).json()] == ["research-bot"]
    c2 = TestClient(create_app())                       # restart: quarantine is not an amnesty
    assert authorize(c2)["decision"] == "deny"


def test_release_restores_access(env):
    c = TestClient(create_app())
    trip(c)
    assert c.post("/v1/agents/research-bot/release", headers=ADMIN).status_code == 200
    assert authorize(c)["decision"] == "allow"
    assert c.post("/v1/agents/research-bot/release", headers=ADMIN).status_code == 404
    assert c.post("/v1/agents/research-bot/release").status_code in (401, 403)   # admin only


def test_quarantine_does_not_extend_itself(env):
    c = TestClient(create_app())
    trip(c)
    until = c.get("/v1/quarantine", headers=ADMIN).json()[0]["until"]
    for _ in range(10):
        authorize(c)                                    # denied by the quarantine, must not re-arm it
    assert c.get("/v1/quarantine", headers=ADMIN).json()[0]["until"] == until


def test_off_by_default_and_bad_rule_rejected(env):
    env.delenv("SENTINEL_ALERT_BLOCK")
    c = TestClient(create_app())
    trip(c)
    assert authorize(c)["decision"] == "allow"          # notify only
    env.setenv("SENTINEL_ALERT_BLOCK", "auth_failure_spike")
    with pytest.raises(ValueError):
        create_app()
