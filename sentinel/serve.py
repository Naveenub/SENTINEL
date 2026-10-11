"""Built-in launcher with TLS: `python -m sentinel`.

  SENTINEL_HOST=0.0.0.0 SENTINEL_PORT=8443 SENTINEL_TLS_CERT=cert.pem SENTINEL_TLS_KEY=key.pem python -m sentinel

Defaults to 127.0.0.1:8080. A non-loopback host without a cert and key refuses to start (unless
SENTINEL_ACK_NONLOOPBACK=1 declares that a proxy or private network covers it). Plain HTTP is never served
on a non-loopback address by accident. Certificates are read at startup; renewing one means a restart.
"""
import os
import sys

import uvicorn

from sentinel.netwarn import is_loopback


def main() -> None:
    host = os.getenv("SENTINEL_HOST", "127.0.0.1")
    port = int(os.getenv("SENTINEL_PORT", "8080"))
    cert, key = os.getenv("SENTINEL_TLS_CERT"), os.getenv("SENTINEL_TLS_KEY")
    if bool(cert) != bool(key):
        sys.exit("SENTINEL_TLS_CERT and SENTINEL_TLS_KEY must be set together")
    for f in (cert, key):
        if f and not os.path.isfile(f):
            sys.exit(f"TLS file not found: {f}")
    if not cert and not is_loopback(host) and os.getenv("SENTINEL_ACK_NONLOOPBACK") != "1":
        sys.exit(f"refusing to serve plain HTTP on {host}: set SENTINEL_TLS_CERT/SENTINEL_TLS_KEY, "
                 "or SENTINEL_ACK_NONLOOPBACK=1 if TLS is handled elsewhere")
    os.environ["SENTINEL_BIND_HOST"] = host  # lets create_app's exposure check see the real bind
    uvicorn.run("sentinel.main:create_app", factory=True, host=host, port=port, ssl_certfile=cert, ssl_keyfile=key)


if __name__ == "__main__":
    main()
