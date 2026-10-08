"""Pluggable ML backend for L1. Rules in rules.py always run in addition.

SENTINEL_CLASSIFIER = comma-separated list of: "nim", "prompt_guard", or "module:Class"
(a class with a no-arg constructor and `score(text) -> float`, 0..1 injection probability).
Several backends form an Ensemble: the highest score wins. If any backend errors, the whole
ensemble errors (surfaced by the pipeline per SENTINEL_CLASSIFIER_ON_ERROR).
A configured backend that cannot load stops startup: the gateway never silently runs rules-only.
"""
import importlib
import os
from typing import Protocol

ALIASES = {
    "nim": "sentinel.input_filter.backends.nim:NvidiaJailbreakNIM",
    "prompt_guard": "sentinel.input_filter.backends.prompt_guard:PromptGuard",
}


class Classifier(Protocol):
    def score(self, text: str) -> float: ...


class Ensemble:
    def __init__(self, members: list):
        self.members = members
        self.name = "+".join(getattr(m, "name", type(m).__name__) for m in members)

    def score(self, text: str) -> float:
        return max(m.score(text) for m in self.members)


def _one(spec: str):
    mod, cls = ALIASES.get(spec, spec).split(":")
    return getattr(importlib.import_module(mod), cls)()


def load() -> Classifier | None:
    parts = [p.strip() for p in os.getenv("SENTINEL_CLASSIFIER", "").split(",") if p.strip()]
    if not parts:
        return None
    members = [_one(p) for p in parts]
    return members[0] if len(members) == 1 else Ensemble(members)
