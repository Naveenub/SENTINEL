"""Measure the configured L1 stack (rules + SENTINEL_CLASSIFIER) on the red-team corpus.

Usage:  SENTINEL_CLASSIFIER=prompt_guard python scripts/eval_classifier.py
Prints how many attacks are blocked, benign allowed, and which known gaps / false positives changed.
(The strict-xfail pytest corpus assumes rules only; use this script when a classifier is enabled.)
"""
import os
import sys
import tempfile
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

root = Path(__file__).parents[1]
os.environ.setdefault("SENTINEL_AUDIT_KEY", "eval-only-key-0123456789abcdef")
os.environ.setdefault("SENTINEL_ADMIN_TOKEN", "eval")
os.environ["SENTINEL_AUDIT_DB"] = str(Path(tempfile.mkdtemp()) / "eval.db")
os.environ.setdefault("SENTINEL_POLICY", str(root / "policies" / "agents.yaml"))
from sentinel.main import create_app  # noqa: E402

c = TestClient(create_app())
print("classifier:", c.get("/healthz").json()["classifier"] or "none (rules only)")
cases = yaml.safe_load((root / "tests/redteam/cases/injection.yaml").read_text())


def verdicts(texts):
    out = []
    for t in texts:
        r = c.post("/v1/scan", json={"agent": "eval", "items": [{"source": "external", "ref": "eval", "text": t}]}).json()
        out.append((t, r["verdict"], [f["rule"] for f in r["findings"]]))
    return out


def show(title, rows, want):
    ok = [r for r in rows if r[1] == want]
    print(f"\n{title}: {len(ok)}/{len(rows)} {want}")
    for t, v, rules in rows:
        if v != want:
            print(f"   MISS  {t[:70]!r}  {rules}")


show("attacks", verdicts(cases["attacks"]), "block")
show("benign", verdicts(cases["benign"]), "allow")
gaps = verdicts(cases["known_gaps"])
print(f"\nknown gaps now caught: {sum(v == 'block' for _, v, _ in gaps)}/{len(gaps)}")
for t, v, _ in gaps:
    print(f"   {'CAUGHT' if v == 'block' else 'missed'}  {t[:70]!r}")
fps = verdicts(cases["known_false_positives"])
print(f"\nknown false positives now allowed: {sum(v == 'allow' for _, v, _ in fps)}/{len(fps)}")
sys.exit(0)
