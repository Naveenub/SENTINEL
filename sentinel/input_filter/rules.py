import re
import unicodedata

_F = re.I | re.S
RULES: list[tuple[str, int, re.Pattern]] = [
    ("override_instructions", 3, re.compile(r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any)\b.{0,40}\b(instructions?|prompts?|rules?|guidelines?)\b", _F)),
    ("reveal_system_prompt", 2, re.compile(r"\b(reveal|show|print|repeat|output)\b.{0,30}\b(system|hidden|initial)\s+(prompt|instructions?|message)", _F)),
    ("role_hijack", 2, re.compile(r"\byou are now\b|\bact as (?:dan|an? unrestricted)\b|\bdeveloper mode\b|\bjailbreak\b", re.I)),
    ("exfil_instruction", 3, re.compile(r"\b(send|post|upload|email|forward|curl)\b.{0,60}(?:\b(?:api[_ -]?keys?|secrets?|credentials?|passwords?|tokens?|ssh)\b|\.env\b)", _F)),
    ("html_comment_instruction", 2, re.compile(r"<!--.*?\b(ignore|instruction|assistant|system)\b.*?-->", _F)),
    ("chat_template_spoof", 2, re.compile(r"<\|(?:im_start|im_end|system|assistant)\|>|^\s*(?:system|assistant)\s*:", re.I | re.M)),
]

_HIDDEN = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u202a", "\u202b", "\u202d", "\u202e"}


def scan_text(text: str) -> list[tuple[str, int]]:
    norm = unicodedata.normalize("NFKC", text)
    hits = [(name, sev) for name, sev, rx in RULES if rx.search(norm)]
    # zero-width/bidi chars and Unicode "tag" characters are used to smuggle instructions
    if any(c in _HIDDEN or 0xE0000 <= ord(c) <= 0xE007F for c in text):
        hits.append(("hidden_unicode", 2))
    return hits
