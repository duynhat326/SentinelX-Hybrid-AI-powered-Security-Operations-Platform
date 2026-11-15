"""LLM provider seam. Only `none` (AI off) and an offline mock exist; real providers plug in behind `LLM`."""
import json
import re
from collections.abc import Callable
from typing import Protocol

from fastapi import Depends

from app.core.config import Settings, get_settings


class LLM(Protocol):
    name: str

    def complete(self, system: str, user: str) -> str: ...


class MockLLM:
    """Deterministic offline model. Default reply cites the first allowed id it is shown; tests pass `reply` to script it."""

    name = "mock"

    def __init__(self, reply: Callable[[str, str], str] | None = None) -> None:
        self._reply = reply or self._default

    def complete(self, system: str, user: str) -> str:
        return self._reply(system, user)

    @staticmethod
    def _default(_system: str, user: str) -> str:
        first = re.search(r"ALLOWED_IDS: (\S+)", user)
        claims = [{"text": "Activity matches the grouped alerts.", "cites": [first.group(1)]}] if first else []
        return json.dumps({"priority": "high", "claims": claims, "next_steps": ["Review the cited events."]})


def get_llm(cfg: Settings = Depends(get_settings)) -> LLM | None:
    return MockLLM() if cfg.llm_provider == "mock" else None
