import json
import shutil
import socket
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from sentinel.main import create_app
from sentinel.policy.opa import OPAClient

ROOT = Path(__file__).parents[2]
POLICY = str(ROOT / "policies" / "agents.yaml")


def _client(handler) -> OPAClient:
    return OPAClient("http://opa.test", client=httpx.Client(transport=httpx.MockTransport(handler)))


def _app(tmp_path, monkeypatch, opa):
    monkeypatch.setenv("SENTINEL_AUDIT_KEY", "k" * 32)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "adm")
    monkeypatch.setenv("SENTINEL_AUDIT_DB", str(tmp_path / "a.db"))
    monkeypatch.setenv("SENTINEL_POLICY", POLICY)
    return TestClient(create_app(opa=opa))


def call(c, tool, args, approval_id=None):
    return c.post("/v1/tool/authorize", json={"agent": "research-bot", "tool": tool, "args": args,
                                              "approval_id": approval_id}).json()


def decide(effect, reason="r"):
    return lambda req: httpx.Response(200, json={"result": {"effect": effect, "reason": reason}})


def test_opa_deny_wins_over_yaml_allow(tmp_path, monkeypatch):
    c = _app(tmp_path, monkeypatch, _client(decide("deny", "nope")))
    d = call(c, "web_fetch", {"url": "https://a.test"})
    assert d["decision"] == "deny" and d["reason"] == "nope"


def test_opa_allow_still_needs_yaml_tool_schema(tmp_path, monkeypatch):
    c = _app(tmp_path, monkeypatch, _client(decide("allow")))
    assert call(c, "web_fetch", {"url": "https://a.test"})["decision"] == "allow"
    assert call(c, "web_fetch", {"url": "http://a.test"})["decision"] == "deny"      # schema
    assert call(c, "not_a_tool", {})["decision"] == "deny"                           # opa allow cannot invent a tool
    assert call(c, "fetch_docs", {"url": "https://evil.test/x"})["decision"] == "deny"  # yaml allowed_hosts still applies


def test_opa_approve_creates_pending_approval(tmp_path, monkeypatch):
    c = _app(tmp_path, monkeypatch, _client(decide("approve")))
    d = call(c, "web_fetch", {"url": "https://a.test"})
    assert d["decision"] == "pending" and d["approval_id"]


def test_yaml_approval_still_required_when_opa_allows(tmp_path, monkeypatch):
    c = _app(tmp_path, monkeypatch, _client(decide("allow")))
    assert call(c, "shell", {"cmd": "ls"})["decision"] == "pending"


@pytest.mark.parametrize("handler", [
    lambda req: httpx.Response(500),
    lambda req: httpx.Response(200, json={}),                                      # undefined result
    lambda req: httpx.Response(200, json={"result": {"effect": "maybe"}}),         # unknown effect
    lambda req: httpx.Response(200, json={"result": True}),                        # wrong shape
    lambda req: (_ for _ in ()).throw(httpx.ConnectError("down")),
])
def test_opa_failures_fail_closed_and_alert(tmp_path, monkeypatch, handler):
    c = _app(tmp_path, monkeypatch, _client(handler))
    d = call(c, "web_fetch", {"url": "https://a.test"})
    assert d["decision"] == "deny" and d["reason"].startswith("opa ")
    alerts = c.get("/v1/alerts", headers={"X-Sentinel-Admin-Token": "adm"}).json()
    assert any(a["rule"] == "policy_backend_degraded" for a in alerts)


def test_opa_receives_parsed_hosts_and_args(tmp_path, monkeypatch):
    seen = []

    def h(req):
        seen.append(json.loads(req.content)["input"])
        return httpx.Response(200, json={"result": {"effect": "allow", "reason": "ok"}})
    c = _app(tmp_path, monkeypatch, _client(h))
    call(c, "web_fetch", {"url": "https://allowed.com@evil.test/x"})
    assert seen[0]["hosts"] == ["evil.test"] and seen[0]["tool"] == "web_fetch" and seen[0]["agent"] == "research-bot"


def test_startup_fails_if_opa_unreachable(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_POLICY_BACKEND", "opa")
    monkeypatch.setenv("SENTINEL_OPA_URL", "http://127.0.0.1:1")
    with pytest.raises(Exception):
        _app(tmp_path, monkeypatch, None)


# ---- against a real OPA server running policies/opa (skipped when the binary is absent)
@pytest.fixture(scope="module")
def real_opa():
    exe = shutil.which("opa")
    if not exe:
        pytest.skip("opa binary not on PATH")
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    p = subprocess.Popen([exe, "run", "--server", f"--addr=127.0.0.1:{port}", str(ROOT / "policies" / "opa")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            if httpx.get(f"{url}/health").status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    yield OPAClient(url)
    p.terminate(); p.wait(5)


def test_real_opa_policy(tmp_path, monkeypatch, real_opa):
    c = _app(tmp_path, monkeypatch, real_opa)
    assert call(c, "web_fetch", {"url": "https://a.test"})["decision"] == "allow"
    assert call(c, "fetch_docs", {"url": "https://docs.python.org/3/"})["decision"] == "allow"
    assert call(c, "shell", {"cmd": "ls"})["decision"] == "pending"
    d = call(c, "shell", {"cmd": "rm -rf /tmp/x"})
    assert d["decision"] == "deny" and "recursive delete" in d["reason"]
    assert c.get("/healthz").json()["policy_backend"] == "opa"
