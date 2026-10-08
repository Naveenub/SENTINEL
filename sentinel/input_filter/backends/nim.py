"""NVIDIA NemoGuard JailbreakDetect NIM (the jailbreak model behind NeMo Guardrails' jailbreak rail).

API (per NVIDIA docs): POST {url}/v1/classify  {"input": "<text>"}  ->  {"jailbreak": bool, "score": float}
We act on the boolean only; the score's sign/scale is not something we interpret.
Run the NIM yourself (needs an NGC key + NVIDIA GPU) and point SENTINEL_NIM_URL at it.
Data note: the default URL is localhost. If you point this at a hosted endpoint, document text leaves your network.
"""
import json
import os
import urllib.request

from sentinel.input_filter.backends.chunking import char_windows


def _post(url: str, payload: dict, headers: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (scheme validated in __init__)
        return json.loads(r.read(1_000_000))


class NvidiaJailbreakNIM:
    name = "nvidia_nim"

    def __init__(self, url=None, api_key=None, model=None, timeout=None, max_chars=None, max_chunks=None, post=_post):
        base = (url or os.getenv("SENTINEL_NIM_URL", "http://127.0.0.1:8000")).rstrip("/")
        if not base.startswith(("http://", "https://")):
            raise ValueError("SENTINEL_NIM_URL must be http(s)")
        self.endpoint = base + "/v1/classify"
        self.api_key = api_key or os.getenv("SENTINEL_NIM_API_KEY")
        self.model = model or os.getenv("SENTINEL_NIM_MODEL")  # only needed behind NeMo's NIM Proxy
        self.timeout = float(timeout or os.getenv("SENTINEL_NIM_TIMEOUT", "5"))
        # ponytail: 4000 chars/32 chunks are tunable guesses, not NVIDIA-documented limits
        self.max_chars = int(max_chars or os.getenv("SENTINEL_NIM_MAX_CHARS", "4000"))
        self.max_chunks = int(max_chunks or os.getenv("SENTINEL_NIM_MAX_CHUNKS", "32"))
        self._post = post

    def score(self, text: str) -> float:
        if not text.strip():
            return 0.0
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        for chunk in char_windows(text, self.max_chars, self.max_chars // 8, self.max_chunks):
            payload = {"input": chunk, **({"model": self.model} if self.model else {})}
            out = self._post(self.endpoint, payload, headers, self.timeout)
            if not isinstance(out, dict) or not isinstance(out.get("jailbreak"), bool):
                raise ValueError("unexpected response from NIM")
            if out["jailbreak"]:
                return 1.0
        return 0.0
