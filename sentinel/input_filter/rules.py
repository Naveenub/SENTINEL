import base64
import codecs
import binascii
import re
import unicodedata

_F = re.I | re.S
RULES: list[tuple[str, int, re.Pattern]] = [
    ("override_instructions", 3, re.compile(r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any)\b.{0,40}\b(instructions?|prompts?|rules?|guidelines?)\b", _F)),
    ("dismiss_prior_context", 3, re.compile(r"\b(?:pay\s+no\s+(?:attention|heed)\s+to|ignore|disregard|forget|set\s+aside|throw\s+away)\b.{0,25}\b(?:everything|anything|whatever|what)\b.{0,40}\b(?:told|said|instructed|given|came\s+before|above|earlier|before|previously)\b", _F)),
    ("dismiss_prior_context", 3, re.compile(r"\bpay\s+no\s+(?:attention|heed)\s+to\b.{0,40}\b(?:previous|prior|above|earlier|instructions?|rules?)\b", _F)),
    ("override_instructions_es", 3, re.compile(r"\b(?:ignora|ignore|olvida|descarta|omite|desatiende)\w*\b.{0,40}\b(?:instrucciones|reglas|indicaciones|directrices)\b", _F)),
    ("override_paraphrase", 3, re.compile(r"\b(?:ignore|disregard|forget|override|discard|dismiss|abandon|drop|bypass|stop\s+following|(?:do\s+not|don'?t)\s+follow|(?:do\s+not|don'?t)\s+obey)\b.{0,70}\b(?:instructions?|guidance|directions?|directives?|rules|prompts?|guidelines?|orders|commands|constraints|briefing)\b.{0,70}\b(?:previous|prior|earlier|before|above|received|given|so\s+far|until\s+now|original|initial|preceding|were\s+told)\b|\b(?:ignore|disregard|forget|override|discard|dismiss|abandon|drop|bypass|stop\s+following|(?:do\s+not|don'?t)\s+follow|(?:do\s+not|don'?t)\s+obey)\b.{0,70}\b(?:previous|prior|earlier|before|above|received|given|so\s+far|until\s+now|original|initial|preceding|were\s+told)\b.{0,50}\b(?:instructions?|guidance|directions?|directives?|rules|prompts?|guidelines?|orders|commands|constraints|briefing)\b", _F)),
    ("override_paraphrase", 3, re.compile(r"\b(?:set|put|push|move|leave|lay)\b.{0,40}\b(?:instructions?|guidance|directions?|directives?|rules|prompts?|guidelines?|orders|commands|constraints|briefing)\b.{0,60}\b(?:previous|prior|earlier|before|above|received|given|so\s+far|until\s+now|original|initial|preceding|were\s+told)\b.{0,40}\b(?:aside|to\s+one\s+side|behind)\b", _F)),
    ("override_instructions_fr", 3, re.compile(r"\b(?:ignor\w+|oubli\w+|néglig\w+|fais?\s+abstraction\s+d\w*)\b.{0,40}\b(?:instructions|consignes|règles|directives)\b", _F)),
    ("reveal_system_prompt_fr", 2, re.compile(r"\b(?:révél\w+|affich\w+|montr\w+|répèt\w+|donn\w+)\b.{0,30}\b(?:prompt|invite|message|instructions)\s+syst[èe]me\b", _F)),
    ("override_instructions_de", 3, re.compile(r"\b(?:vergiss(?!\s+nicht)\w*|ignorier\w*|missachte\w*|übergehe\w*|verwirf\w*)\b.{0,40}\b(?:anweisungen|instruktionen|regeln|vorgaben|richtlinien)\b", _F)),
    ("override_instructions_it", 3, re.compile(r"\b(?:ignor\w+|dimentic\w+|trascur\w+|scart\w+|disattend\w+|non\s+(?:tenere|tenete|tener)\s+conto\s+d\w*)\b.{0,40}\b(?:istruzioni|regole|direttive|indicazioni|linee\s+guida)\b", _F)),
    ("override_instructions_ru", 3, re.compile(r"\b(?:игнорир\w+|забуд\w+|забыть|пренебр\w+|отбрось\w*|отмени\w*|не\s+обращай\w*\s+внимания\s+на)\b.{0,40}\b(?:инструкци\w+|правил\w*|указани\w+|директив\w+)", _F)),
    ("reveal_system_prompt_de", 2, re.compile(r"\b(?:gib|zeig\w*|nenn\w*|verrat\w*|wiederhole\w*|druck\w*)\b.{0,30}\b(?:system[-\s]?prompt|systemanweisung\w*)", _F)),
    ("reveal_system_prompt_es", 2, re.compile(r"\b(?:revela|muestra|imprime|repite|escribe)\w*\b.{0,30}\b(?:prompt|instrucciones|mensaje)\s+del\s+sistema\b", _F)),
    ("reveal_system_prompt", 2, re.compile(r"\b(reveal|show|print|repeat|output)\b.{0,30}\b(system|hidden|initial)\s+(prompt|instructions?|message)", _F)),
    ("role_hijack", 2, re.compile(r"\byou are now\b|\bact as (?:dan|an? unrestricted)\b|\bdeveloper mode\b|\bjailbreak\b", re.I)),
    ("persona_no_restrictions", 2, re.compile(r"\b(?:respond|answer|reply|act|behave|operate|speak|talk)\b.{0,40}\bas\b.{0,80}\b(?:no|without|free\s+(?:of|from)|zero)\s+(?:any\s+)?(?:restrictions?|limitations?|limits|filters?|rules|guidelines|censorship|safeguards?)\b", _F)),
    ("persona_no_restrictions", 2, re.compile(r"\bfrom\s+now\s+on\b.{0,60}\b(?:respond|answer|reply|act|behave)\b.{0,20}\b(?:only\s+)?as\b", _F)),
    ("authority_bypass", 2, re.compile(r"\bas\s+(?:the\s+|an?\s+|your\s+)?(?:system\s+)?(?:administrator|admin|developer|owner|operator|creator|root)\b.{0,40}\b(?:authori[sz]e|permit|allow|grant|instruct|order|command)\w*\b.{0,60}\b(?:bypass|disable|ignore|override|skip|circumvent|turn\s+off|remove)\b", _F)),
    ("safety_bypass", 2, re.compile(r"\b(?:bypass|disable|circumvent|turn\s+off|ignore)\b.{0,20}\b(?:your|the|all)\b.{0,15}\b(?:safety|security|content)\b.{0,10}\b(?:guidelines?|rules?|restrictions?|filters?|polic(?:y|ies)|checks?)\b", _F)),
    ("exfil_instruction", 3, re.compile(r"\b(send|post|upload|email|forward|curl)\b.{0,60}(?:\b(?:api[_ -]?keys?|secrets?|credentials?|passwords?|tokens?|ssh)\b|\.env\b)", _F)),
    ("exfil_url_instruction", 3, re.compile(r"\b(?:visit|open|go\s+to|navigate\s+to|fetch|browse|load)\b.{0,60}https?://\S+.{0,100}\b(?:submit|send|post|upload|forward|append|include|paste)\b.{0,60}\b(?:chat|conversation|history|messages?|context|(?:the\s+)?user'?s?\b)", _F)),
    ("exfil_url_instruction", 3, re.compile(r"\b(?:submit|send|post|upload|forward)\b.{0,60}\b(?:chat\s+history|conversation|previous\s+messages|user'?s?\s+(?:data|history|messages?|chat|info))\b.{0,80}https?://", _F)),
    ("html_comment_instruction", 2, re.compile(r"<!--.*?\b(ignore|instruction|assistant|system)\b.*?-->", _F)),
    ("chat_template_spoof", 2, re.compile(r"<\|(?:im_start|im_end|system|assistant)\|>|^\s*(?:system|assistant)\s*:", re.I | re.M)),
]

_HIDDEN = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u202a", "\u202b", "\u202d", "\u202e"}

# Cyrillic/Greek lookalikes -> Latin. Used only to build an extra variant to scan; never to rewrite output.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j",
    "ѕ": "s", "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "ԁ": "d", "ɡ": "g", "ԛ": "q", "ԝ": "w",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S", "К": "K",
    "М": "M", "Н": "H", "Т": "T", "В": "B",
    "α": "a", "ο": "o", "ν": "v", "ι": "i", "ε": "e", "ρ": "p", "τ": "t", "κ": "k", "υ": "u", "χ": "x",
    "Α": "A", "Ο": "O", "Ι": "I", "Ε": "E", "Ρ": "P", "Τ": "T", "Κ": "K", "Μ": "M", "Ν": "N", "Υ": "Y", "Χ": "X",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_LEET_TOKEN = re.compile(r"[\w@$]+")
_HEX = re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{2}){16,}(?![0-9A-Za-z])")
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")


def _deleet(s: str) -> str:
    # fold only tokens that mix letters with leet characters, so "4%" or "24.04" are untouched
    def fix(m: re.Match) -> str:
        t = m.group(0)
        return t.translate(_LEET) if any(c.isalpha() for c in t) and any(c in "013457@$" for c in t) else t
    return _LEET_TOKEN.sub(fix, s)


def _variants(norm: str) -> list[str]:
    homo = norm.translate(_HOMOGLYPHS)
    out: list[str] = []
    for v in (norm, homo, _deleet(norm), _deleet(homo)):
        if v not in out:
            out.append(v)
    return out


def _decoded_blobs(text: str) -> list[str]:
    blobs = []
    for m in _B64.finditer(text):
        tok = m.group(0).rstrip("=")
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
            s = raw.decode("utf-8")
        except (binascii.Error, ValueError):
            continue
        if len(s) >= 8 and sum(c.isprintable() or c in "\n\t" for c in s) / len(s) >= 0.95:
            blobs.append(s)
    # long even-length hex runs; hashes and ids decode to non-printable bytes and are dropped by the same check
    for m in _HEX.finditer(text):
        try:
            s = bytes.fromhex(m.group(0)).decode("utf-8")
        except ValueError:
            continue
        if len(s) >= 8 and sum(c.isprintable() or c in "\n\t" for c in s) / len(s) >= 0.95:
            blobs.append(s)
    return blobs


# --- Narrow, documented exemptions for two known false positives -------------------------------------
# Each exemption rewrites only the benign span in the text that is scanned (never the caller's text), so
# anything after or around it is still scanned. They are deliberately strict: every condition must hold.

# "System: Ubuntu 24.04 LTS" / "Assistant: Gemini 2" style header lines from logs, inventories, neofetch output.
_ROLE_LINE = re.compile(r"^([ \t]*)(system|assistant)([ \t]*:[ \t]*)([^\n]*)$", re.I | re.M)
_KV_LINE = re.compile(r"[ \t]*[A-Za-z][\w ./-]{0,24}:[ \t]*\S")
# words that make a value look like an instruction rather than a name/version
_DIRECTIVE = re.compile(
    r"\b(?:you|your|yours|must|should|shall|always|never|not|don'?t|do|ignore|disregard|forget|override|bypass|"
    r"disable|obey|follow|comply|reveal|print|output|repeat|send|email|forward|upload|execute|run|delete|now|new|"
    r"act|respond|answer|reply|pretend|assume|grant|allow|authori[sz]e|permit|instructions?|rules?|prompt|"
    r"unrestricted|jailbreak|mode|password|secret|key|token)\b", re.I)


def _benign_role_value(payload: str, following: str) -> bool:
    toks = payload.split()
    if not 1 <= len(toks) <= 6 or not (payload[:1].isupper() or payload[:1].isdigit()):
        return False
    if _DIRECTIVE.search(payload) or re.search(r"[!?]|\.\s|:\s", payload):
        return False
    next_line = following.lstrip("\n").split("\n", 1)[0] if following.startswith("\n") else ""
    # a version/number in the value, or the next line is another "Label: value" pair (a structured header block)
    return any(c.isdigit() for c in payload) or bool(_KV_LINE.fullmatch(next_line))


# "You can ignore the previous instructions in the README if you use Docker." Only the head of the sentence is
# defused, and only when it is advice ("you can/may/should"), scoped to a named document, and followed by an
# "if/when/unless" clause. "all/any previous instructions" and unscoped forms are never exempt.
_DOC_ADVICE = re.compile(
    r"\byou\s+(?:can|may|could|might|should)\s+(?:safely\s+)?(?:ignore|skip|disregard)\s+the\s+"
    r"(?:previous|prior|earlier|above|preceding)\s+(?:instructions?|steps|rules)\s+(?:in|from|of|within)\s+"
    r"(?:the|this|that|our)\s+(?:readme|docs?|documentation|manual|guide|tutorial|wiki|changelog|"
    r"(?:install(?:ation)?|setup)\s+guide)(?:\.md)?\b(?=\s+(?:if|when|unless|once)\b)", re.I)


def _neutralize_benign(norm: str) -> str:
    def role(m: re.Match) -> str:
        if _benign_role_value(m.group(4), norm[m.end():]):
            return f"{m.group(1)}Info{m.group(3)}{m.group(4)}"  # role word swapped for a neutral label
        return m.group(0)
    return _DOC_ADVICE.sub("a note about the docs", _ROLE_LINE.sub(role, norm))


def _match(norm: str) -> dict[str, int]:
    hits: dict[str, int] = {}
    for v in _variants(_neutralize_benign(norm)):
        for name, sev, rx in RULES:
            if rx.search(v):
                hits[name] = max(sev, hits.get(name, 0))
    return hits


def scan_text(text: str) -> list[tuple[str, int]]:
    norm = unicodedata.normalize("NFKC", text)
    hits = _match(norm)
    # base64 blobs that decode to readable text are scanned too; a hit inside one is a high-severity finding
    if any(_match(unicodedata.normalize("NFKC", b)) for b in _decoded_blobs(norm)):
        hits["encoded_payload"] = 3
    # ROT13 is a classic cheap obfuscation; a hit only in the decoded text is a high-severity finding
    # (rot13 leaves non-ASCII untouched, so ignore rules that already matched the plain text, e.g. Cyrillic)
    if set(_match(codecs.decode(norm, "rot13"))) - set(hits):
        hits["encoded_payload"] = 3
    out = list(hits.items())
    # zero-width/bidi chars and Unicode "tag" characters are used to smuggle instructions
    if any(c in _HIDDEN or 0xE0000 <= ord(c) <= 0xE007F for c in text):
        out.append(("hidden_unicode", 2))
    return out
