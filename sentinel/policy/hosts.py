import re
from urllib.parse import urlsplit

_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)


def extract_hosts(obj) -> list[str]:
    """Hostnames of every http(s) URL found in (nested) tool args. Uses a real URL parser so
    tricks like https://allowed.com@evil.com/ resolve to evil.com. Unparseable URLs -> '<invalid>'."""
    hosts: set[str] = set()

    def walk(o):
        if isinstance(o, str):
            for m in _URL.finditer(o):
                try:
                    hosts.add((urlsplit(m.group()).hostname or "<invalid>").rstrip("."))
                except ValueError:
                    hosts.add("<invalid>")
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)

    walk(obj)
    return sorted(hosts)
