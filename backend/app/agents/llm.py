"""LLM provider seam. Only `none` (AI off) and an offline mock exist; real providers plug in behind `LLM`.

A real provider must enforce `timeout` itself (seconds, for the whole call), and must not put credentials or
request headers into the exceptions it raises more than needed: the run records only the exception class.
"""
import json
import re
from collections.abc import Callable
from typing import Protocol

from fastapi import Depends

from app.core.config import Settings, get_settings


class LLM(Protocol):
    name: str  # provider, e.g. "mock"
    model: str  # model identifier recorded with every run

    def complete(self, system: str, user: str, timeout: float) -> str: ...


class MockLLM:
    """Deterministic offline model. Default reply cites the first allowed id it is shown; tests pass `reply` to script it."""

    name = "mock"
    model = "mock-1"

    def __init__(self, reply: Callable[[str, str], str] | None = None) -> None:
        self._reply = reply or self._default

    def complete(self, system: str, user: str, timeout: float) -> str:
        return self._reply(system, user)

    @staticmethod
    def _default(_system: str, user: str) -> str:
        first = re.search(r"ALLOWED_IDS: (\S+)", user)
        claims = [{"text": "Activity matches the grouped alerts.", "cites": [first.group(1)]}] if first else []
        return json.dumps({
            "priority": "high", "claims": claims, "confidence": "low", "likely_techniques": [],
            "uncertainties": ["Mock model: no real analysis was performed."], "next_steps": ["Review the cited events."], "proposals": [],
        })


def get_llm(cfg: Settings = Depends(get_settings)) -> LLM | None:
    return MockLLM() if cfg.llm_provider == "mock" else None
