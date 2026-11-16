"""Enrich an indicator from the local IOC table, then (only if allowed and confirmed) from external providers."""
import time
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.audit import audit
from app.api.auth import Principal
from app.core.config import Settings
from app.core.indicators import normalize_indicator
from app.core.netutil import is_global_ip
from app.core.timeutil import utc
from app.database.models import Ioc
from app.threat_intel.providers import ProviderError, Verdict, abuseipdb, virustotal

# provider -> (indicator kinds, API key, lookup)
PROVIDERS: dict[str, tuple[frozenset[str], Callable[[Settings], object], Callable[[Settings, str, str], Verdict | None]]] = {
    "abuseipdb": (frozenset({"ip"}), lambda c: c.abuseipdb_api_key, abuseipdb),
    "virustotal": (frozenset({"ip", "domain", "sha256"}), lambda c: c.vt_api_key, virustotal),
}

# shortcut: in-memory, per process, resets on restart; the providers enforce their own quota anyway
_calls: dict[tuple[str, int], int] = defaultdict(int)


def reset_limits() -> None:
    _calls.clear()


def _allowed(provider: str, per_minute: int) -> bool:
    key = (provider, int(time.time() // 60))
    if _calls[key] >= per_minute:
        return False
    _calls[key] += 1
    return True


class SourceResult(BaseModel):
    source: str
    status: Literal["found", "not_found", "unavailable", "rate_limited"]
    score: int | None = None
    summary: str | None = None
    checked_at: datetime | None = None
    cached: bool = False  # true when answered from the local table instead of a live call


class EnrichOut(BaseModel):
    indicator: str
    kind: str
    status: Literal["found", "not_found", "unavailable", "skipped"]
    sources: list[SourceResult]
    note: str | None = None


class ConfirmationRequired(Exception):
    def __init__(self, indicator: str, providers: list[str]) -> None:
        self.indicator, self.providers = indicator, providers
        super().__init__("confirmation required")

    def detail(self) -> dict:
        return {"code": "confirmation_required", "indicator": self.indicator, "providers": self.providers,
                "warning": f"This sends {self.indicator!r} to third parties ({', '.join(self.providers)}), which will learn that you are "
                           "investigating it. Repeat the request with confirm_external=true to proceed."}


def upsert_ioc(db: Session, kind: str, value: str, source: str, score: int, summary: str, expires: datetime | None, by: str | None) -> Ioc:
    now = datetime.now(UTC)
    for _ in range(2):  # a concurrent insert of the same row loses the unique constraint; the second pass updates it
        row = db.scalar(select(Ioc).where(Ioc.kind == kind, Ioc.value == value, Ioc.source == source))
        if row:
            row.score, row.summary, row.checked_at, row.expires_at, row.created_by = score, summary, now, expires, by or row.created_by
            return row
        try:
            with db.begin_nested():
                row = Ioc(kind=kind, value=value, source=source, score=score, summary=summary, checked_at=now, expires_at=expires, created_by=by)
                db.add(row)
            return row
        except IntegrityError:
            continue
    raise RuntimeError("could not upsert IOC")


def _as_result(r: Ioc) -> SourceResult:
    return SourceResult(source=r.source, status="found", score=r.score, summary=r.summary, checked_at=r.checked_at, cached=r.source != "manual")


def enrich(db: Session, cfg: Settings, who: Principal, indicator: str, confirm_external: bool, request: Request | None = None) -> tuple[EnrichOut, bool]:
    """Returns the result and whether it stored anything new (the caller then rescores incidents). ValueError for a bad indicator,
    ConfirmationRequired when an external lookup would be needed but the caller did not confirm it."""
    kind, value = normalize_indicator(indicator)
    now = datetime.now(UTC)
    fresh = {r.source: r for r in db.scalars(select(Ioc).where(Ioc.kind == kind, Ioc.value == value)) if r.expires_at is None or utc(r.expires_at) > now}
    sources = [_as_result(r) for r in fresh.values()]
    todo = [name for name, (kinds, key, _) in PROVIDERS.items() if kind in kinds and key(cfg) and name not in fresh]
    note, stored = None, False
    if todo and kind == "ip" and not is_global_ip(value):
        note, todo = "not a public address: never sent to third parties", []
    elif todo and not cfg.ti_external_enabled:
        note, todo = "external lookups are disabled (SENTINELX_TI_EXTERNAL_ENABLED=false)", []
    elif todo and not confirm_external:
        raise ConfirmationRequired(value, todo)
    for name in todo:
        if not _allowed(name, cfg.ti_external_rate_per_minute):
            sources.append(SourceResult(source=name, status="rate_limited"))
            continue
        try:
            verdict = PROVIDERS[name][2](cfg, kind, value)
            status = "found" if verdict else "not_found"
        except ProviderError as e:
            verdict, status = None, e.status
        # the privacy trail: what was sent to whom, whatever the outcome (never the API key)
        audit(db, who, "ti.external_lookup", target_type=kind, target_id=value[:64], outcome="ok" if status in ("found", "not_found") else "error",
              detail={"provider": name, "indicator": value, "result": status}, request=request)
        if verdict:
            row = upsert_ioc(db, kind, value, name, verdict.score, verdict.summary, now + timedelta(hours=cfg.ti_cache_ttl_hours), None)
            sources.append(SourceResult(source=name, status="found", score=row.score, summary=row.summary, checked_at=now))
            stored = True
        else:
            sources.append(SourceResult(source=name, status=status))
    found = any(s.status == "found" for s in sources)
    flaky = any(s.status in ("unavailable", "rate_limited") for s in sources)
    overall = "found" if found else "unavailable" if flaky else "skipped" if note and not sources else "not_found"
    return EnrichOut(indicator=value, kind=kind, status=overall, sources=sources, note=note), stored
