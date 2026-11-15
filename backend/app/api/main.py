import hmac
import uuid
from contextlib import asynccontextmanager
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.ratelimit import rate_limit
from app.core.config import Settings, get_settings
from app.database.models import Alert, Base
from app.database.session import get_db, get_engine
from app.ingestion.service import ingest
from app.normalization.normalize import NormalizationError


def require_key(x_api_key: Annotated[str, Header()] = "", cfg: Settings = Depends(get_settings)) -> None:
    if not hmac.compare_digest(x_api_key.encode(), cfg.api_key.encode()):
        raise HTTPException(401, "invalid API key")


class SecureHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        r = await call_next(request)
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["Cache-Control"] = "no-store"
        return r


@asynccontextmanager
async def lifespan(_: FastAPI):
    get_settings()  # fail fast on bad config
    # shortcut: create_all instead of Alembic migrations, add Alembic in Milestone 2.
    Base.metadata.create_all(get_engine())
    yield


app = FastAPI(title="SentinelX", version="0.1.0", lifespan=lifespan)
app.add_middleware(SecureHeaders)
try:
    _origins = get_settings().cors_origins
except Exception:  # settings are validated again in lifespan; keep import-time safe for tooling
    _origins = []
app.add_middleware(CORSMiddleware, allow_origins=_origins, allow_methods=["GET", "POST"], allow_headers=["X-API-Key", "Content-Type"])


class EventIn(BaseModel):
    source: Literal["linux_auth", "sysmon"]
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
    evidence_event_ids: list[uuid.UUID]


def _alert_out(a: Alert) -> AlertOut:
    return AlertOut(**{k: getattr(a, k) for k in ("id", "rule_id", "title", "severity", "status", "host", "mitre", "event_count")},
                    evidence_event_ids=[e.event_id for e in a.evidence])


class IngestOut(BaseModel):
    event_id: uuid.UUID | None
    duplicate: bool
    alerts: list[AlertOut]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/events", response_model=IngestOut, dependencies=[Depends(require_key), Depends(rate_limit)])
def post_event(body: EventIn, db: Session = Depends(get_db), cfg: Settings = Depends(get_settings)) -> IngestOut:
    try:
        event, alerts = ingest(db, cfg, body.source, body.payload)
    except NormalizationError as e:
        raise HTTPException(422, str(e)) from e
    return IngestOut(event_id=event.id if event else None, duplicate=event is None, alerts=[_alert_out(a) for a in alerts])


@app.get("/api/v1/alerts", response_model=list[AlertOut], dependencies=[Depends(require_key)])
def list_alerts(db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=200)) -> list[AlertOut]:
    rows = db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(limit))
    return [_alert_out(a) for a in rows]
