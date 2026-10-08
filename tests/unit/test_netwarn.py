import logging

import pytest

from sentinel.netwarn import bind_host, is_loopback, warn_if_exposed


@pytest.mark.parametrize("h,ok", [("127.0.0.1", True), ("::1", True), ("[::1]", True), ("localhost", True),
                                  ("0.0.0.0", False), ("::", False), ("10.0.0.5", False), ("example.com", False)])
def test_is_loopback(h, ok):
    assert is_loopback(h) is ok


def test_bind_host_sources():
    assert bind_host([], {}) == "127.0.0.1"
    assert bind_host(["uvicorn", "--host", "0.0.0.0"], {}) == "0.0.0.0"
    assert bind_host(["uvicorn", "--host=10.1.1.1"], {}) == "10.1.1.1"
    assert bind_host([], {"UVICORN_HOST": "0.0.0.0"}) == "0.0.0.0"
    assert bind_host(["--host", "127.0.0.1"], {"SENTINEL_BIND_HOST": "0.0.0.0"}) == "0.0.0.0"
    assert bind_host(["--uds", "/tmp/s.sock", "--host", "0.0.0.0"], {}) == "127.0.0.1"


def test_warns_auth_on_nonloopback(caplog):
    with caplog.at_level(logging.WARNING, logger="sentinel.startup"):
        msg = warn_if_exposed(True, ["--host", "0.0.0.0"], {})
    assert msg and "TLS" in msg and "NON-LOOPBACK" in msg
    assert "NON-LOOPBACK" in caplog.text


def test_warns_auth_off_nonloopback():
    msg = warn_if_exposed(False, ["--host", "0.0.0.0"], {})
    assert msg and "auth is OFF" in msg


def test_silent_on_loopback_and_when_acked():
    assert warn_if_exposed(True, ["--host", "127.0.0.1"], {}) is None
    assert warn_if_exposed(False, [], {}) is None
    assert warn_if_exposed(True, ["--host", "0.0.0.0"], {"SENTINEL_ACK_NONLOOPBACK": "1"}) is None
