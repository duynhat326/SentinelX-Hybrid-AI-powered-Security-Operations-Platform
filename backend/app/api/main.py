import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.agents import router as agents_router
from app.api.auth import require
from app.api.incidents import router as incidents_router
from app.api.intel import router as intel_router
from app.api.ratelimit import rate_limit
from app.api.response import router as response_router
from app.api.users import router as users_router
from app.core.config import Settings, get_settings
from app.correlation.engine import backfill
from app.database.models import Alert, DetectionRule
from app.database.session import get_db, get_factory
from app.detection.engine import sync_rules
from app.ingestion.service import ingest
from app.normalization.normalize import NormalizationError


class SecureHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        r = await call_next(request)
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["Cache-Control"] = "no-store"
        return r


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_settings()  # fail fast on bad config
    with get_factory()() as db:  # schema comes from `alembic upgrade head`, run before the app starts
        sync_rules(db)
        backfill(db, get_settings())  # alerts that predate incidents
    yield


app = FastAPI(title="SentinelX", version="0.1.0", lifespan=lifespan)
app.add_middleware(SecureHeaders)
app.include_router(incidents_router)
app.include_router(agents_router)
app.include_router(users_router)
app.include_router(intel_router)
app.include_router(response_router)
try:
    _origins = get_settings().cors_origins
except Exception:  # settings are validated again in lifespan; keep import-time safe for tooling
    _origins = []
app.add_middleware(CORSMiddleware, allow_origins=_origins, allow_methods=["GET", "POST"], allow_headers=["X-API-Key", "Content-Type"])


class EventIn(BaseModel):
    source: Literal["linux_auth", "sysmon", "wazuh"]
    payload: str = Field(min_length=1, max_length=16384)


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    rule_id: str
    title: str
    severity: str
    status: str
    host: str
    mitre: list[str]
    event_count: int
    first_event_at: datetime
    last_event_at: datetime
    evidence_event_ids: list[uuid.UUID]
    incident_id: uuid.UUID | None


def _alert_out(a: Alert) -> AlertOut:
    return AlertOut(**{k: getattr(a, k) for k in ("id", "rule_id", "title", "severity", "status", "host", "mitre", "event_count",
                                                  "first_event_at", "last_event_at")},
                    evidence_event_ids=[e.event_id for e in a.evidence],
                    incident_id=a.incident_link.incident_id if a.incident_link else None)


class IngestOut(BaseModel):
    event_id: uuid.UUID | None
    duplicate: bool
    alerts: list[AlertOut]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/events", response_model=IngestOut, dependencies=[Depends(require("ingest")), Depends(rate_limit)])
def post_event(body: EventIn, db: Session = Depends(get_db), cfg: Settings = Depends(get_settings)) -> IngestOut:
    try:
        event, alerts = ingest(db, cfg, body.source, body.payload)
    except NormalizationError as e:
        raise HTTPException(422, str(e)) from e
    return IngestOut(event_id=event.id if event else None, duplicate=event is None, alerts=[_alert_out(a) for a in alerts])


@app.get("/api/v1/alerts", response_model=list[AlertOut], dependencies=[Depends(require("read"))])
def list_alerts(db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=200)) -> list[AlertOut]:
    rows = db.scalars(select(Alert).options(selectinload(Alert.evidence), selectinload(Alert.incident_link))
                      .order_by(Alert.created_at.desc()).limit(limit))
    return [_alert_out(a) for a in rows]


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    title: str
    severity: str
    mitre: list[str]
    enabled: bool


@app.get("/api/v1/rules", response_model=list[RuleOut], dependencies=[Depends(require("read"))])
def list_rules(db: Session = Depends(get_db)) -> list[DetectionRule]:
    return list(db.scalars(select(DetectionRule).order_by(DetectionRule.id)))
