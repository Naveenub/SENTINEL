"""L4: scan tool output before it can reach the model. Secrets -> withhold; PII/exfil -> redact."""
import re
from dataclasses import dataclass, field

_SECRET = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("sentinel_token", re.compile(r"\bsnt1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
]
_REDACT = [
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("card_number", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("exfil_markdown_image", re.compile(r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*\)")),
    ("exfil_base64_blob", re.compile(r"[A-Za-z0-9+/_-]{200,}={0,2}")),
]


def _luhn(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    tot = sum(x if i % 2 == 0 else (x * 2 - 9 if x * 2 > 9 else x * 2) for i, x in enumerate(reversed(d)))
    return tot % 10 == 0


@dataclass
class OutputScan:
    text: str
    findings: list[str] = field(default_factory=list)
    block: bool = False  # True = credentials seen; withhold the whole output


def scan_output(text: str, literals: list[str] = ()) -> OutputScan:
    res = OutputScan(text)
    for lit in literals:  # secrets we handed to the tool must never come back
        if lit and lit in res.text:
            res.findings.append("issued_token_echoed")
            res.block = True
            res.text = res.text.replace(lit, "[REDACTED:issued_token]")
    for name, rx in _SECRET:
        if rx.search(res.text):
            res.findings.append(name)
            res.block = True
            res.text = rx.sub(f"[REDACTED:{name}]", res.text)
    for name, rx in _REDACT:
        def sub(m, name=name):
            if name == "card_number" and not _luhn(m.group()):
                return m.group()
            if name not in res.findings:
                res.findings.append(name)
            return f"[REDACTED:{name}]"
        res.text = rx.sub(sub, res.text)
    return res
