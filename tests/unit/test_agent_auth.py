import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from sentinel.main import create_app

POLICY = str(Path(__file__).parents[2] / "policies" / "agents.yaml")
RB, GT = "rb-token-0123456789abcdef", "gt-token-0123456789abcdef"      # research-bot, garak-target
ADMIN = {"X-Sentinel-Admin-Token": "adm"}


class Upstream:
    def __init__(self):
        self.seen = []

    def __call__(self, req: httpx.Request):
        self.seen.append(dict(req.headers))
        if req.url.path.endswith("/messages"):
            return httpx.Response(200, json={"id": "m", "type": "message", "role": "assistant", "model": "m",
                                             "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
                                             "usage": {"input_tokens": 1, "output_tokens": 1}})
        return httpx.Response(200, json={"id": "x", "object": "chat.completion", "model": "m", "choices": [
            {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "hi"}}]})


@pytest.fixture
def make(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_AUDIT_KEY", "k" * 32)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "adm")
    monkeypatch.setenv("SENTINEL_AUDIT_DB", str(tmp_path / "a.db"))
    monkeypatch.setenv("SENTINEL_POLICY", POLICY)
    monkeypatch.setenv("SENTINEL_UPSTREAM_URL", "http://model.test")
    monkeypatch.setenv("SENTINEL_UPSTREAM_KEY", "sk-upstream-secret-value")
    monkeypatch.setenv("SENTINEL_AGENT_TOKENS", f"research-bot={RB},garak-target={GT}")

    def build(**env):
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        up = Upstream()
        c = TestClient(create_app(model_client=httpx.Client(transport=httpx.MockTransport(up))))
        c.up = up
        return c
    return build


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


SCAN = {"agent": "research-bot", "items": [{"source": "user", "ref": "r", "text": "hello"}]}
AUTHZ = {"agent": "research-bot", "tool": "web_fetch", "args": {"url": "https://a.test"}}


# ---------------------------------------------------------------- plain endpoints

def test_missing_and_invalid_token_are_401_on_every_agent_endpoint(make):
    c = make()
    for path, body in (("/v1/scan", SCAN), ("/v1/tool/authorize", AUTHZ), ("/v1/tool/run", AUTHZ)):
        assert c.post(path, json=body).status_code == 401
        r = c.post(path, json=body, headers=bearer("wrong-token-0123456789"))
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    assert c.post("/v1/tool/authorize", json={}).status_code == 401       # schema is not revealed to the unauthenticated


def test_valid_token_all_three_header_styles(make):
    c = make()
    for h in (bearer(RB), {"x-api-key": RB}, {"X-Sentinel-Agent-Token": RB}):
        assert c.post("/v1/scan", json=SCAN, headers=h).status_code == 200
    assert c.post("/v1/tool/authorize", json=AUTHZ, headers=bearer(RB)).json()["decision"] == "allow"


def test_token_cannot_act_as_another_agent(make):
    c = make()
    r = c.post("/v1/tool/authorize", json=AUTHZ, headers=bearer(GT))      # garak-target's token, research-bot's tools
    assert r.status_code == 403
    assert c.post("/v1/tool/authorize", json={**AUTHZ, "agent": "ghost"}, headers=bearer(RB)).status_code == 403
    # unauthenticated callers cannot probe which agents exist
    assert c.post("/v1/tool/authorize", json={**AUTHZ, "agent": "ghost"}).status_code == 401


def test_open_endpoints_and_separate_admin_credential(make):
    c = make()
    assert c.get("/healthz").status_code == 401
    assert c.get("/healthz", headers=bearer("wrong-token-0123456789")).status_code == 401
    assert c.get("/healthz", headers={"X-Sentinel-Admin-Token": "nope"}).status_code == 401
    for h in (bearer(RB), {"x-api-key": GT}, ADMIN):
        assert c.get("/healthz?detail=1", headers=h).json() == {"ok": True}   # liveness only; a query flag does not unlock detail
    assert c.get("/v1/status").status_code == 403
    assert c.get("/v1/status", headers=bearer(RB)).status_code == 403   # an agent token is not an admin token
    st = c.get("/v1/status", headers=ADMIN).json()
    assert st["ok"] is True and {"classifier", "classifier_on_error", "policy_backend", "model_proxy"} <= st.keys()
    assert c.get("/v1/approvals", headers=ADMIN).status_code == 200
    assert c.get("/v1/approvals", headers=bearer(RB)).status_code == 403   # an agent token is not an admin token
    assert c.get("/v1/approvals", headers={"X-Sentinel-Admin-Token": RB}).status_code == 403


def test_auth_is_off_without_tokens(make, monkeypatch):
    monkeypatch.delenv("SENTINEL_AGENT_TOKENS")
    c = make()
    assert c.get("/healthz").status_code == 401 and c.get("/healthz", headers=ADMIN).status_code == 200
    assert make().post("/v1/scan", json=SCAN).status_code == 200


def test_agent_without_a_token_fails_closed(make):
    c = make(SENTINEL_AGENT_TOKENS=f"research-bot={RB}")
    assert c.post("/v1/scan", json={**SCAN, "agent": "garak-target"}, headers=bearer(RB)).status_code == 403
    assert c.post("/v1/scan", json={**SCAN, "agent": "garak-target"}).status_code == 401


# ---------------------------------------------------------------- audit

def test_failures_are_audited_throttled_and_never_record_the_token(make):
    c = make()
    for _ in range(5):
        c.post("/v1/scan", json=SCAN, headers=bearer("guess-0123456789abcdef"))
    ev = c.app.state.log.recent("auth", 20)
    assert len(ev) == 1 and ev[0]["decision"] == "deny" and ev[0]["reason"] == "invalid agent token"
    assert "guess-0123456789abcdef" not in json.dumps(ev)
    c.post("/v1/scan", json=SCAN, headers=bearer(GT))                      # a different reason is its own entry
    assert [e["reason"] for e in c.app.state.log.recent("auth", 20)][0].startswith("token belongs to a different agent")
    assert c.get("/v1/audit/verify", headers=ADMIN).json()["ok"] is True


# ---------------------------------------------------------------- model proxy

def test_proxy_error_shapes_and_forwarding(make):
    c = make()
    oai = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
    ant = {"model": "m", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}]}
    r = c.post("/proxy/research-bot/v1/chat/completions", json=oai)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    r = c.post("/proxy/research-bot/v1/messages", json=ant)
    assert r.status_code == 401 and r.json()["type"] == "error"
    assert c.post("/proxy/research-bot/v1/messages", json=ant, headers=bearer(GT)).status_code == 403
    assert c.post("/proxy/research-bot/v1/messages", json=ant, headers={"x-api-key": RB}).status_code == 200
    # the agent token is never forwarded; the upstream sees only the gateway's own key
    assert len(c.up.seen) == 1 and c.up.seen[0]["x-api-key"] == "sk-upstream-secret-value"
    assert RB not in json.dumps(c.up.seen)
    c.post("/proxy/research-bot/v1/chat/completions", json=oai, headers=bearer(RB))
    assert c.up.seen[1]["authorization"] == "Bearer sk-upstream-secret-value" and RB not in json.dumps(c.up.seen)


def test_header_route_infers_agent_from_token_and_still_binds(make):
    c = make()
    ant = {"model": "m", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}]}
    assert c.post("/v1/messages", json=ant, headers={"x-api-key": RB}).status_code == 200      # no X-Sentinel-Agent needed
    assert c.post("/v1/messages", json=ant, headers={"x-api-key": RB, "X-Sentinel-Agent": "garak-target"}).status_code == 403
    assert c.post("/v1/messages", json=ant).status_code == 401


def test_official_sdks_authenticate_with_api_key(make):
    anthropic, openai = pytest.importorskip("anthropic"), pytest.importorskip("openai")
    c = make()
    a = anthropic.Anthropic(base_url="http://testserver/proxy/research-bot", api_key=RB, http_client=c)
    assert a.messages.create(model="m", max_tokens=8, messages=[{"role": "user", "content": "hi"}]).content[0].text == "hi"
    o = openai.OpenAI(base_url="http://testserver/proxy/research-bot/v1", api_key=RB, http_client=c)
    assert o.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}]).choices[0].message.content == "hi"
    bad = anthropic.Anthropic(base_url="http://testserver/proxy/research-bot", api_key="nope-0123456789abcdef",
                              http_client=c, max_retries=0)
    with pytest.raises(anthropic.AuthenticationError):
        bad.messages.create(model="m", max_tokens=8, messages=[{"role": "user", "content": "hi"}])
    wrong = openai.OpenAI(base_url="http://testserver/proxy/research-bot/v1", api_key=GT, http_client=c, max_retries=0)
    with pytest.raises(openai.PermissionDeniedError):
        wrong.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])


# ---------------------------------------------------------------- configuration

def test_token_file_and_rotation(make, tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_AGENT_TOKENS")
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"research-bot": [RB, "rb-old-token-0123456789"], "garak-target": GT}))
    c = make(SENTINEL_AGENT_TOKENS_FILE=str(f))
    for t in (RB, "rb-old-token-0123456789"):                              # both rotation tokens work
        assert c.post("/v1/scan", json=SCAN, headers=bearer(t)).status_code == 200
    assert c.post("/v1/scan", json={**SCAN, "agent": "garak-target"}, headers=bearer(GT)).status_code == 200


@pytest.mark.parametrize("value,msg", [
    ("research-bot=short", "shorter than"),
    ("ghost=ghost-token-0123456789", "not defined in policy"),
    (f"research-bot={RB},garak-target={RB}", "same token"),
    ("research-bot", "agent=token"),
])
def test_bad_configuration_refuses_to_start(make, value, msg):
    with pytest.raises(ValueError, match=msg):
        make(SENTINEL_AGENT_TOKENS=value)


def test_token_equal_to_admin_or_verifier_token_is_refused(make):
    with pytest.raises(ValueError, match="admin and verifier"):
        make(SENTINEL_ADMIN_TOKEN="a" * 20, SENTINEL_AGENT_TOKENS=f"research-bot={'a' * 20}")
    with pytest.raises(ValueError, match="admin and verifier"):
        make(SENTINEL_VERIFIER_TOKEN="v" * 20, SENTINEL_AGENT_TOKENS=f"research-bot={'v' * 20}")


# ---------------------------------------------------------------- lockout and expiry

def test_lockout_after_repeated_invalid_tokens_then_recovers(make):
    c = make(SENTINEL_AUTH_MAX_FAILURES="3", SENTINEL_AUTH_LOCKOUT_SECONDS="60")
    now = [1000.0]
    c.app.state.limiter.clock = lambda: now[0]
    for _ in range(3):
        assert c.post("/v1/scan", json=SCAN, headers=bearer("guess-0123456789abcdef")).status_code == 401
    r = c.post("/v1/scan", json=SCAN, headers=bearer(RB))                  # even a valid token is refused while locked out
    assert r.status_code == 429 and 1 <= int(r.headers["retry-after"]) <= 61
    assert c.get("/healthz", headers=ADMIN).status_code == 429
    assert c.post("/proxy/research-bot/v1/messages", json={}, headers={"x-api-key": RB}).json()["error"]["code"] == "too_many_attempts"
    now[0] += 61
    assert c.post("/v1/scan", json=SCAN, headers=bearer(RB)).status_code == 200


def test_missing_token_and_wrong_agent_do_not_trigger_lockout(make):
    c = make(SENTINEL_AUTH_MAX_FAILURES="2")
    for _ in range(5):
        assert c.post("/v1/scan", json=SCAN).status_code == 401
        assert c.post("/v1/scan", json=SCAN, headers=bearer(GT)).status_code == 403
    assert c.post("/v1/scan", json=SCAN, headers=bearer(RB)).status_code == 200


def test_failures_outside_the_window_are_forgotten(make):
    c = make(SENTINEL_AUTH_MAX_FAILURES="3", SENTINEL_AUTH_FAILURE_WINDOW="10")
    now = [0.0]
    c.app.state.limiter.clock = lambda: now[0]
    for _ in range(2):
        c.post("/v1/scan", json=SCAN, headers=bearer("guess-0123456789abcdef"))
    now[0] += 11
    c.post("/v1/scan", json=SCAN, headers=bearer("guess-0123456789abcdef"))
    assert c.post("/v1/scan", json=SCAN, headers=bearer(RB)).status_code == 200


def test_token_expiry(make, tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_AGENT_TOKENS")
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"research-bot": [{"token": RB, "expires": "2999-01-01T00:00:00Z"},
                                              {"token": "rb-old-token-0123456789", "expires": "2000-01-01T00:00:00"}],
                             "garak-target": GT}))
    c = make(SENTINEL_AGENT_TOKENS_FILE=str(f))
    assert c.post("/v1/scan", json=SCAN, headers=bearer(RB)).status_code == 200
    assert c.post("/v1/scan", json=SCAN, headers=bearer("rb-old-token-0123456789")).status_code == 401
    assert c.app.state.log.recent("auth", 5)[0]["reason"] == "expired agent token"


def test_bad_expiry_refuses_to_start(make, tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_AGENT_TOKENS")
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"research-bot": [{"token": RB, "expires": "tomorrow"}]}))
    with pytest.raises(ValueError, match="ISO 8601"):
        make(SENTINEL_AGENT_TOKENS_FILE=str(f))
    f.write_text(json.dumps({"research-bot": [{"token": RB}]}))
    with pytest.raises(ValueError, match="expires"):
        make(SENTINEL_AGENT_TOKENS_FILE=str(f))


def test_failure_flood_alerts_even_though_the_audit_log_is_throttled(make):
    c = make(SENTINEL_AUTH_ALERT_LIMIT="5", SENTINEL_AUTH_MAX_FAILURES="1000")
    for _ in range(5):
        c.post("/v1/scan", json=SCAN, headers=bearer("guess-0123456789abcdef"))
    assert len(c.app.state.log.recent("auth", 20)) == 1                    # throttled to one entry
    al = c.app.state.log.recent("alert", 20)
    assert [a["rule"] for a in al] == ["auth_failure_spike"] and al[0]["severity"] == "high"
    assert "guess-0123456789abcdef" not in json.dumps(al)
    assert c.get("/v1/audit/verify", headers=ADMIN).json()["ok"] is True


# ---- env token expiry
def test_env_token_expiry_parsed_and_enforced(monkeypatch):
    from sentinel.auth import AgentAuth
    monkeypatch.setenv("SENTINEL_AGENT_TOKENS", "a=" + "x" * 20 + ";expires=2030-01-01T00:00:00Z,b=" + "y" * 20)
    monkeypatch.delenv("SENTINEL_AGENT_TOKENS_FILE", raising=False)
    monkeypatch.delenv("SENTINEL_REQUIRE_TOKEN_EXPIRY", raising=False)
    assert AgentAuth.from_env({"a", "b"}) is not None
    monkeypatch.setenv("SENTINEL_AGENT_TOKENS", "a=" + "x" * 20 + ";expires=not-a-date")
    import pytest
    with pytest.raises(ValueError):
        AgentAuth.from_env({"a"})


def test_require_token_expiry_fails_startup_on_bare_token(monkeypatch):
    import pytest
    from sentinel.auth import AgentAuth
    monkeypatch.delenv("SENTINEL_AGENT_TOKENS_FILE", raising=False)
    monkeypatch.setenv("SENTINEL_REQUIRE_TOKEN_EXPIRY", "1")
    monkeypatch.setenv("SENTINEL_AGENT_TOKENS", "a=" + "x" * 20)
    with pytest.raises(ValueError, match="without an expiry"):
        AgentAuth.from_env({"a"})
    monkeypatch.setenv("SENTINEL_AGENT_TOKENS", "a=" + "x" * 20 + ";expires=2030-01-01T00:00:00Z")
    assert AgentAuth.from_env({"a"}) is not None
