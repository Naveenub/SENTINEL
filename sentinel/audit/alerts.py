import json
import logging
import threading
import urllib.request

log = logging.getLogger("sentinel.alerts")


def log_sink(a: dict) -> None:
    log.warning("ALERT %s [%s] agent=%s %s", a["rule"], a["severity"], a["agent"], a["detail"])


def webhook_sink(url: str, timeout: float = 3.0):
    """POST each alert as JSON. Runs in a thread so a slow endpoint never blocks the gateway."""
    if not url.startswith(("http://", "https://")):
        raise ValueError("SENTINEL_ALERT_WEBHOOK must be an http(s) URL")

    def send(a: dict) -> None:
        def go():
            try:
                req = urllib.request.Request(url, data=json.dumps(a).encode(), headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=timeout).close()
            except Exception:
                log.exception("alert webhook failed")
        threading.Thread(target=go, daemon=True).start()

    return send
