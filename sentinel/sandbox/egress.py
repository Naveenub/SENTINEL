"""Allowlisting HTTPS (CONNECT) proxy: the only exit for sandboxes with network=proxy.

Run:  python -m sentinel.sandbox.egress --listen 0.0.0.0:3128 --allowlist policies/egress.yaml
Blocks IP literals and hosts that resolve to non-public addresses (SSRF / cloud metadata), and
connects to the address it validated (no re-resolution between check and connect).
# ponytail: CONNECT/443 only – plain HTTP is refused on purpose. Add per-tool allowlists if needed.
"""
import argparse
import asyncio
import ipaddress
import logging
from collections.abc import Awaitable, Callable

import yaml

log = logging.getLogger("sentinel.egress")


class EgressAllowlist:
    def __init__(self, patterns: list[str]):
        self.patterns = [p.lower().rstrip(".") for p in patterns]

    @classmethod
    def from_yaml(cls, path: str) -> "EgressAllowlist":
        with open(path) as f:
            return cls((yaml.safe_load(f) or {}).get("allow", []))

    def allows(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        try:
            ipaddress.ip_address(h.strip("[]"))
            return False  # IP literals are never allowlisted
        except ValueError:
            pass
        return any(h == p or (p.startswith("*.") and h.endswith(p[1:])) for p in self.patterns)


async def _resolve(host: str) -> str:
    infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=0)
    return infos[0][4][0]


async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        w.close()


class EgressProxy:
    def __init__(self, allow: EgressAllowlist, resolver: Callable[[str], Awaitable[str]] = _resolve,
                 block_private: bool = True, ports: frozenset[int] = frozenset({443})):
        self.allow, self.resolver, self.block_private, self.ports = allow, resolver, block_private, ports

    async def _deny(self, w: asyncio.StreamWriter, code: int, why: str):
        log.warning("egress denied: %s", why)
        w.write(f"HTTP/1.1 {code} {why}\r\nConnection: close\r\n\r\n".encode())
        await w.drain()
        w.close()

    async def handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        try:
            line = (await asyncio.wait_for(r.readline(), 10)).decode("latin1").split()
            while (await r.readline()).strip():  # discard headers
                pass
            if len(line) < 2 or line[0] != "CONNECT":
                return await self._deny(w, 405, "only CONNECT is allowed")
            host, _, port = line[1].rpartition(":")
            if not port.isdigit() or int(port) not in self.ports:
                return await self._deny(w, 403, "port not allowed")
            if not self.allow.allows(host):
                return await self._deny(w, 403, f"host not allowlisted: {host}")
            ip = await self.resolver(host)
            if self.block_private and not ipaddress.ip_address(ip).is_global:
                return await self._deny(w, 403, "resolves to non-public address")
            ur, uw = await asyncio.open_connection(ip, int(port))
            w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await w.drain()
            await asyncio.gather(_pipe(r, uw), _pipe(ur, w))
        except Exception as e:  # never let one bad client kill the proxy
            log.warning("egress error: %s", e)
            w.close()

    async def serve(self, host: str, port: int):
        srv = await asyncio.start_server(self.handle, host, port)
        async with srv:
            await srv.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0:3128")
    ap.add_argument("--allowlist", default="policies/egress.yaml")
    a = ap.parse_args()
    h, p = a.listen.rsplit(":", 1)
    logging.basicConfig(level=logging.INFO)
    asyncio.run(EgressProxy(EgressAllowlist.from_yaml(a.allowlist)).serve(h, int(p)))
