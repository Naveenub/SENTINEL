from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.audit.detect import Detector
from sentinel.main import create_app
from sentinel.policy.hosts import extract_hosts

ADMIN = {"X-Sentinel-Admin-Token": "adm"}
POLICY = str(Path(__file__).parents[2] / "policies" / "agents.yaml")


def tool(agent="a", name="web_fetch", decision="allow", hosts=()):
    return {"type": "tool", "agent": agent, "tool": name, "decision": decision, "hosts": list(hosts)}


def rules(alerts):
    return [a["rule"] for a in alerts]


# ---- detector logic
def test_auth_failure_spike_is_per_client_and_cooled_down():
    d = Detector(auth_limit=3)
    got = [x for i in range(6) for x in d.observe_auth("1.2.3.4", f"bot{i}", now=i)]
    assert rules(got) == ["auth_failure_spike"] and "1.2.3.4" in got[0]["detail"]   # rotating agent names do not evade it
    assert d.observe_auth("5.6.7.8", "x", now=7) == []                              # another client has its own count
    assert d.observe({"type": "auth", "decision": "deny", "agent": "x"}) == []      # log entries never double-count


def test_deny_spike_alerts_once_per_cooldown():
    d = Detector(deny_limit=3)
    got = [x for i in range(6) for x in d.observe(tool(decision="deny"), now=i)]
    assert rules(got) == ["deny_spike"]
    later = [x for i in range(100, 103) for x in d.observe(tool(decision="deny"), now=i)]
    assert rules(later) == ["deny_spike"]                          # old denies aged out, new burst, cooldown over


def test_call_spike():
    d = Detector(call_limit=5, learn=1000)
    got = [x for i in range(10) for x in d.observe(tool(), now=i)]
    assert rules(got) == ["call_spike"]


def test_new_domain_only_after_learning():
    d = Detector(learn=2)
    assert d.observe(tool(hosts=["a.test"]), now=0) == []         # learning
    assert d.observe(tool(hosts=["b.test"]), now=1) == []         # learning
    assert rules(d.observe(tool(hosts=["evil.test"]), now=2)) == ["new_domain"]
    assert d.observe(tool(hosts=["evil.test"]), now=3) == []      # now baseline (alert is on record)
    assert d.observe(tool(hosts=["a.test"]), now=4) == []


def test_denied_calls_do_not_poison_baseline():
    d = Detector(learn=2)
    d.observe(tool(hosts=["a.test"]), now=0)
    d.observe(tool(hosts=["a.test"]), now=0.5)                     # learns the web_fetch->web_fetch pair too
    d.observe(tool(decision="deny", hosts=["evil.test"]), now=1)  # failed attempt
    assert rules(d.observe(tool(hosts=["evil.test"]), now=2)) == ["new_domain"]


def test_unusual_sequence():
    d = Detector(learn=3)
    for i, t in enumerate(["read", "summarize", "read", "summarize"]):
        d.observe(tool(name=t), now=i)
    assert d.observe(tool(name="read"), now=10) == []             # read->summarize? no: summarize->read seen
    assert rules(d.observe(tool(name="shell"), now=11)) == ["unusual_sequence"]


def test_tool_call_right_after_blocked_input():
    d = Detector(learn=1000)
    d.observe({"type": "scan", "agent": "a", "verdict": "block"}, now=0)
    assert rules(d.observe(tool(), now=5)) == ["tool_after_blocked_input"]
    assert d.observe(tool(agent="other"), now=6) == []            # other agents unaffected
    d2 = Detector(learn=1000)
    d2.observe({"type": "scan", "agent": "a", "verdict": "block"}, now=0)
    assert d2.observe(tool(), now=500) == []                      # outside window


def test_withheld_output_alert_and_replay_is_silent():
    ev = {"type": "run", "agent": "a", "tool": "t", "decision": "allow", "withheld": True, "findings": ["aws_access_key"]}
    assert rules(Detector().observe(ev, now=0)) == ["output_withheld"]
    assert Detector().observe(ev, now=0, emit=False) == []
    assert Detector().observe({"type": "alert", "agent": "a"}) == []  # ignores its own alerts


# ---- integration
@pytest.fixture
def env(tmp_path, monkeypatch):
    for k, v in {"SENTINEL_AUDIT_KEY": "k" * 32, "SENTINEL_ADMIN_TOKEN": "adm", "SENTINEL_POLICY": POLICY,
                 "SENTINEL_AUDIT_DB": str(tmp_path / "a.db"), "SENTINEL_LEARN_CALLS": "2"}.items():
        monkeypatch.setenv(k, v)


def fetch(c, url, tool="web_fetch"):
    return c.post("/v1/tool/authorize", json={"agent": "research-bot", "tool": tool, "args": {"url": url}}).json()


def test_alerts_land_in_signed_log_and_endpoint(env):
    c = TestClient(create_app())
    fetch(c, "https://a.test/x"); fetch(c, "https://b.test/x")
    assert c.get("/v1/alerts", headers=ADMIN).json() == []
    fetch(c, "https://evil.test/x")
    alerts = c.get("/v1/alerts", headers=ADMIN).json()
    assert [a["rule"] for a in alerts] == ["new_domain"] and alerts[0]["detail"] == "first request to evil.test"
    assert c.get("/v1/audit/verify", headers=ADMIN).json()["ok"] is True
    assert c.get("/v1/alerts").status_code == 403


def test_baseline_survives_restart(env):
    c = TestClient(create_app())
    for u in ("https://a.test", "https://b.test", "https://evil.test"):
        fetch(c, u)
    c2 = TestClient(create_app())                                  # same DB
    n = len(c2.get("/v1/alerts", headers=ADMIN).json())
    fetch(c2, "https://evil.test")                                 # already known: no new alert
    assert len(c2.get("/v1/alerts", headers=ADMIN).json()) == n
    fetch(c2, "https://fresh.test")
    assert len(c2.get("/v1/alerts", headers=ADMIN).json()) == n + 1


def test_webhook_sink_called(env, monkeypatch):
    sent = []
    monkeypatch.setenv("SENTINEL_ALERT_WEBHOOK", "https://hooks.test/x")
    monkeypatch.setattr("sentinel.main.webhook_sink", lambda url: sent.append)
    c = TestClient(create_app())
    for u in ("https://a.test", "https://b.test", "https://evil.test"):
        fetch(c, u)
    assert sent and sent[0]["rule"] == "new_domain"


# ---- per-tool host allowlist (closes SSRF-style URL smuggling)
@pytest.mark.parametrize("url", [
    "https://169.254.169.254/latest/meta-data", "https://docs.python.org@evil.test/", "https://evil.test/",
    "https://127.0.0.1:8080/", "https://docs.python.org.evil.test/",
])
def test_allowed_hosts_blocks_ssrf_tricks(env, url):
    assert fetch(TestClient(create_app()), url, "fetch_docs")["decision"] == "deny"


def test_allowed_hosts_permits_listed(env):
    c = TestClient(create_app())
    assert fetch(c, "https://docs.python.org/3/", "fetch_docs")["decision"] == "allow"
    assert fetch(c, "https://api.github.com/x", "fetch_docs")["decision"] == "allow"


def test_extract_hosts_parses_like_a_browser():
    assert extract_hosts({"a": ["see https://x.test:8443/p?q=1 and http://u:p@y.test/"]}) == ["x.test", "y.test"]


# ---- time-based learning period
def test_time_based_learning_ignores_call_volume():
    d = Detector(learn=2, learn_seconds=100, call_limit=10**6)
    got = []
    for i in range(50):                                   # far past the call count, still inside the window
        got += d.observe(tool(name=f"t{i}", hosts=[f"h{i}.example"]), now=i)
    assert got == []
    late = d.observe(tool(name="late", hosts=["new.example"]), now=101)
    assert "new_domain" in rules(late)                    # window over: novelty alerts


def test_time_based_clock_starts_at_first_allowed_call():
    d = Detector(learn_seconds=100)
    d.observe(tool(decision="deny"), now=0)               # denied calls never start the clock
    assert d.observe(tool(hosts=["a.example"]), now=500) == []
    assert "new_domain" in rules(d.observe(tool(hosts=["b.example"]), now=601))


def test_count_based_default_unchanged():
    d = Detector(learn=1)
    d.observe(tool(hosts=["a.example"]), now=0)
    assert "new_domain" in rules(d.observe(tool(hosts=["b.example"]), now=1))
