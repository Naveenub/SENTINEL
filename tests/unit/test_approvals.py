import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.main import create_app
from sentinel.policy.approvals import ApprovalStore

POLICY = str(Path(__file__).parents[2] / "policies" / "agents.yaml")
ADMIN = {"X-Sentinel-Admin-Token": "adm"}


# ---------------------------------------------------------------- store

def test_lifecycle_single_use_and_args_cleared_on_decision(tmp_path):
    s = ApprovalStore(str(tmp_path / "a.db"))
    assert s.create("a1", "fp", "bot", "shell", {"cmd": "ls"}, now=100)
    assert s.pending(now=101) == [{"approval_id": "a1", "agent": "bot", "tool": "shell", "args": {"cmd": "ls"}}]
    assert s.consume("a1") is None                                   # still pending: cannot be taken
    assert s.resolve("a1", True, now=102) and not s.resolve("a1", False, now=103)   # decided once only
    assert s.pending(now=104) == []
    assert s.db.execute("SELECT args FROM approvals WHERE id='a1'").fetchone() == (None,)  # args not retained
    assert s.consume("a1") == "approved" and s.consume("a1") is None  # single use


def test_denied_state_is_reported_once(tmp_path):
    s = ApprovalStore(str(tmp_path / "a.db"))
    s.create("a1", "fp", "bot", "shell", {}, now=1)
    s.resolve("a1", False, now=2)
    assert s.consume("a1") == "denied" and s.get("a1", now=3) is None


def test_pending_expires_after_ttl_from_creation_decided_after_ttl_from_decision(tmp_path):
    s = ApprovalStore(str(tmp_path / "a.db"), ttl=100)
    s.create("p", "fp", "bot", "shell", {}, now=0)
    s.create("d", "fp", "bot", "shell", {}, now=0)
    s.resolve("d", True, now=90)
    assert s.get("p", now=99) and s.get("p", now=101) is None          # pending: counted from creation
    assert s.get("d", now=180) and s.get("d", now=191) is None         # decided: counted from the decision
    assert not s.resolve("p", True, now=200)                            # expired rows cannot be approved


def test_pending_cap(tmp_path):
    s = ApprovalStore(str(tmp_path / "a.db"), max_pending=2)
    assert s.create("1", "f", "b", "t", {}, now=1) and s.create("2", "f", "b", "t", {}, now=1)
    assert not s.create("3", "f", "b", "t", {}, now=1)
    s.resolve("1", True, now=2)                                         # decided rows do not count against the cap
    assert s.create("3", "f", "b", "t", {}, now=3)


def test_survives_reopen(tmp_path):
    path = str(tmp_path / "a.db")
    ApprovalStore(path).create("a1", "fp", "bot", "shell", {"cmd": "ls"})
    assert ApprovalStore(path).pending()[0]["approval_id"] == "a1"


# ---------------------------------------------------------------- end to end across a restart

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_AUDIT_KEY", "k" * 32)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "adm")
    monkeypatch.setenv("SENTINEL_AUDIT_DB", str(tmp_path / "a.db"))
    monkeypatch.setenv("SENTINEL_POLICY", POLICY)
    return monkeypatch


def call(c, args, aid=None):
    return c.post("/v1/tool/authorize", json={"agent": "research-bot", "tool": "shell", "args": args,
                                              "approval_id": aid}).json()


def test_pending_and_granted_approvals_survive_restart(env):
    c1 = TestClient(create_app())
    pending = call(c1, {"cmd": "ls"})
    granted = call(c1, {"cmd": "pwd"})
    assert pending["decision"] == granted["decision"] == "pending"
    assert c1.post(f"/v1/approvals/{granted['approval_id']}/approve", headers=ADMIN).status_code == 200

    c2 = TestClient(create_app())                                       # "restart": new app, same DB file
    assert [p["approval_id"] for p in c2.get("/v1/approvals", headers=ADMIN).json()] == [pending["approval_id"]]
    assert call(c2, {"cmd": "ls"}, pending["approval_id"])["decision"] == "pending"
    assert call(c2, {"cmd": "pwd"}, granted["approval_id"])["decision"] == "allow"         # grant kept
    assert call(c2, {"cmd": "pwd"}, granted["approval_id"])["decision"] == "deny"          # still single use
    assert c2.post(f"/v1/approvals/{pending['approval_id']}/approve", headers=ADMIN).status_code == 200
    assert call(c2, {"cmd": "rm -rf /"}, pending["approval_id"])["decision"] == "deny"     # still bound to the args
    assert call(c2, {"cmd": "ls"}, pending["approval_id"])["decision"] == "allow"


def test_tool_args_are_not_left_in_db_after_decision(env, tmp_path):
    c = TestClient(create_app())
    aid = call(c, {"cmd": "echo hunter2"})["approval_id"]
    c.post(f"/v1/approvals/{aid}/deny", headers=ADMIN)
    rows = sqlite3.connect(str(tmp_path / "a.db")).execute("SELECT args FROM approvals").fetchall()
    assert rows == [(None,)]


def test_pending_cap_denies_new_requests(env):
    env.setenv("SENTINEL_APPROVAL_MAX_PENDING", "1")
    c = TestClient(create_app())
    assert call(c, {"cmd": "a"})["decision"] == "pending"
    d = call(c, {"cmd": "b"})
    assert d["decision"] == "deny" and "too many pending" in d["reason"]
