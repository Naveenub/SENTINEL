from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from sentinel.main import create_app

CASES = yaml.safe_load((Path(__file__).parent / "cases" / "injection.yaml").read_text())
POLICY = str(Path(__file__).parents[2] / "policies" / "agents.yaml")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    for k, v in {"SENTINEL_AUDIT_KEY": "k" * 32, "SENTINEL_ADMIN_TOKEN": "adm", "SENTINEL_POLICY": POLICY,
                 "SENTINEL_AUDIT_DB": str(tmp_path_factory.mktemp("rt") / "a.db")}.items():
        mp.setenv(k, v)
    yield TestClient(create_app())
    mp.undo()


def verdict(client, text):
    r = client.post("/v1/scan", json={"agent": "research-bot", "items": [{"source": "external", "ref": "redteam", "text": text}]})
    return r.json()["verdict"]


def ids(xs):
    return [x[:40].replace("\n", " ") for x in xs]


@pytest.mark.parametrize("text", CASES["attacks"], ids=ids(CASES["attacks"]))
def test_attack_is_blocked(client, text):
    assert verdict(client, text) == "block"


@pytest.mark.parametrize("text", CASES["benign"], ids=ids(CASES["benign"]))
def test_benign_is_allowed(client, text):
    assert verdict(client, text) == "allow"


@pytest.mark.xfail(strict=True, reason="known detection gap: needs the ML classifier layer")
@pytest.mark.parametrize("text", CASES["known_gaps"], ids=ids(CASES["known_gaps"]))
def test_known_gap(client, text):
    assert verdict(client, text) == "block"


@pytest.mark.xfail(strict=True, reason="known false positive of the rule layer")
@pytest.mark.parametrize("text", CASES["known_false_positives"], ids=ids(CASES["known_false_positives"]))
def test_known_false_positive(client, text):
    assert verdict(client, text) == "allow"
