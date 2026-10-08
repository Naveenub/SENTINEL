"""Meta Llama Prompt Guard 2: a small binary classifier (benign vs malicious injection/jailbreak).

Not Llama Guard: that is a generative content-safety model (violence, hate, ...), a different job.
Setup: pip install -e ".[ml]"; accept Meta's license for the model on Hugging Face (it is gated) and set HF_TOKEN.
Models: meta-llama/Llama-Prompt-Guard-2-86M (multilingual, default) or -22M (English, faster).
Runs locally, so no document text leaves your host. The model has a ~512-token window, so long inputs are
scored in overlapping token windows and the maximum malicious probability wins.
"""
import os

from sentinel.input_filter.backends.chunking import token_windows

_MALICIOUS = {"label_1", "malicious", "jailbreak", "injection"}  # gated repos publish LABEL_0/LABEL_1


class PromptGuard:
    name = "prompt_guard"

    def __init__(self, model=None, device=None, pipe=None, window=480, overlap=96, max_chunks=None):
        if pipe is None:
            from transformers import pipeline  # optional dependency, imported lazily
            dev = device if device is not None else os.getenv("SENTINEL_PG_DEVICE")
            kw = {} if dev in (None, "") else {"device": int(dev) if str(dev).lstrip("-").isdigit() else dev}
            pipe = pipeline("text-classification",
                            model=model or os.getenv("SENTINEL_PG_MODEL", "meta-llama/Llama-Prompt-Guard-2-86M"), **kw)
        self.pipe = pipe
        self.window, self.overlap = window, overlap
        self.max_chunks = int(max_chunks or os.getenv("SENTINEL_PG_MAX_CHUNKS", "32"))

    def score(self, text: str) -> float:
        if not text.strip():
            return 0.0
        chunks = token_windows(text, self.pipe.tokenizer, self.window, self.overlap, self.max_chunks)
        results = self.pipe(chunks, top_k=None, truncation=True, max_length=512)
        worst = 0.0
        for r in results:
            labels = r if isinstance(r, list) else [r]
            probs = [x["score"] for x in labels if str(x["label"]).lower() in _MALICIOUS]
            if not probs:  # an unknown label scheme must never read as "benign"
                raise ValueError(f"no malicious label among {[x['label'] for x in labels]}")
            worst = max(worst, max(probs))
        return worst
