"""Pluggable ML backend for L1.

Implement a class with `score(self, text: str) -> float` (injection probability, 0..1) and point
SENTINEL_CLASSIFIER at it as "module:Class". Use this to wrap NVIDIA NeMo Guardrails / the Jailbreak
Detect NIM, Llama Guard / Prompt Guard, or LLM Guard. Rules in rules.py always run regardless.
"""
import importlib
import os
from typing import Protocol


class Classifier(Protocol):
    def score(self, text: str) -> float: ...


def load() -> Classifier | None:
    spec = os.getenv("SENTINEL_CLASSIFIER")
    if not spec:
        return None
    mod, cls = spec.split(":")
    return getattr(importlib.import_module(mod), cls)()
