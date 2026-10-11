import yaml

from sentinel.auth import FailureLimiter
from sentinel.limits import LimitStore
from sentinel.policy.engine import PolicyEngine


def _policy(tmp_path):
    p = tmp_path / "agents.yaml"
    p.write_text(yaml.safe_dump({"agents": {"a": {"tools": {"t": {
        "schema": {"type": "object"}, "rate_limit": "2/hour"}}}}}))
    return str(p)


def test_rate_limit_survives_restart(tmp_path):
    db = str(tmp_path / "l.db")
    e1 = PolicyEngine(_policy(tmp_path), limits=LimitStore(db))
    assert e1.authorize("a", "t", {}).decision == "allow"
    assert e1.authorize("a", "t", {}).decision == "allow"
    e2 = PolicyEngine(_policy(tmp_path), limits=LimitStore(db))  # "restart"
    assert e2.authorize("a", "t", {}).reason == "rate limit exceeded"


def test_lockout_survives_restart(tmp_path):
    db = str(tmp_path / "l.db")
    now = [1000.0]
    l1 = FailureLimiter(3, 60, 300, clock=lambda: now[0], store=LimitStore(db))
    for _ in range(3):
        l1.failure("1.2.3.4")
    assert l1.retry_after("1.2.3.4") > 0
    l2 = FailureLimiter(3, 60, 300, clock=lambda: now[0], store=LimitStore(db))
    assert l2.retry_after("1.2.3.4") > 0
    now[0] += 301
    assert l2.retry_after("1.2.3.4") == 0
