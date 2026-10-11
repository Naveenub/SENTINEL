"""Startup warning when the gateway is reachable from other machines.

create_app() cannot see the address uvicorn binds to, so this is best effort. In order:
SENTINEL_BIND_HOST (explicit), `--host` in argv, UVICORN_HOST, then uvicorn's default (127.0.0.1).
`--uds` (unix socket) counts as local. Under gunicorn or another launcher, set SENTINEL_BIND_HOST.
SENTINEL_ACK_NONLOOPBACK=1 silences the warning once TLS or a private network is in place.
TLS is recognised from `--ssl-keyfile` + `--ssl-certfile` in argv or SENTINEL_TLS_CERT + SENTINEL_TLS_KEY (set by
`python -m sentinel`). With SENTINEL_REQUIRE_TLS=1 a non-loopback bind without TLS refuses to start (ACK does not
override it).
"""
import ipaddress
import logging
import os
import sys

log = logging.getLogger("sentinel.startup")


def bind_host(argv: list[str] | None = None, env=None) -> str:
    argv = sys.argv if argv is None else argv
    env = os.environ if env is None else env
    if env.get("SENTINEL_BIND_HOST"):
        return env["SENTINEL_BIND_HOST"].strip()
    host = None
    for i, a in enumerate(argv):
        if a == "--uds" or a.startswith("--uds="):
            return "127.0.0.1"
        if a == "--host" and i + 1 < len(argv):
            host = argv[i + 1]
        elif a.startswith("--host="):
            host = a.split("=", 1)[1]
    return (host or env.get("UVICORN_HOST") or "127.0.0.1").strip()


def is_loopback(host: str) -> bool:
    h = host.strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False  # 0.0.0.0, ::, or a hostname: assume reachable from outside


def tls_enabled(argv: list[str] | None = None, env=None) -> bool:
    argv = sys.argv if argv is None else argv
    env = os.environ if env is None else env
    flag = lambda n: any(a == n or a.startswith(n + "=") for a in argv)  # noqa: E731
    return (flag("--ssl-keyfile") and flag("--ssl-certfile")) or bool(env.get("SENTINEL_TLS_CERT") and env.get("SENTINEL_TLS_KEY"))


def exposure_warning(auth_on: bool, host: str, tls: bool = False) -> str | None:
    if is_loopback(host) or (tls and auth_on):
        return None
    bar = "!" * 78
    if auth_on:
        why = ("Agent auth is ON, but tokens are bearer secrets and SENTINEL does not provide TLS.\n"
               "Anyone on the network path can read them. Put a TLS-terminating proxy in front, use\n"
               "uvicorn --ssl-keyfile/--ssl-certfile, or restrict to a private network.")
    else:
        why = ("Agent auth is OFF: /v1/scan, /v1/tool/* and the model proxy trust ANY caller that can\n"
               "reach this port, and the proxy spends your upstream key. Set SENTINEL_AGENT_TOKENS,\n"
               "or bind to 127.0.0.1.")
    return (f"\n{bar}\nSENTINEL IS BOUND TO A NON-LOOPBACK ADDRESS ({host})\n{why}\n"
            f"Set SENTINEL_ACK_NONLOOPBACK=1 to silence this once the above is handled.\n{bar}")


def warn_if_exposed(auth_on: bool, argv: list[str] | None = None, env=None) -> str | None:
    env = os.environ if env is None else env
    host, tls = bind_host(argv, env), tls_enabled(argv, env)
    if env.get("SENTINEL_REQUIRE_TLS") == "1" and not is_loopback(host) and not tls:
        raise RuntimeError(f"SENTINEL_REQUIRE_TLS=1 but bound to {host} without TLS "
                           "(use `python -m sentinel` with SENTINEL_TLS_CERT/SENTINEL_TLS_KEY, or uvicorn --ssl-*)")
    if env.get("SENTINEL_ACK_NONLOOPBACK") == "1":
        return None
    msg = exposure_warning(auth_on, host, tls)
    if msg:
        log.warning(msg)
    return msg
