from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.agents import AgentRunOut
from app.api.auth import require
from app.database.models import AgentRun, Alert, BlocklistEntry, Incident, ResponseAction, SecurityEvent
from app.database.session import get_db

router = APIRouter(dependencies=[Depends(require("read"))])


class Overview(BaseModel):
    events_total: int
    last_event_at: datetime | None
    alerts_by_severity: dict[str, int]
    open_incidents_by_severity: dict[str, int]
    pending_actions: int
    active_blocklist_entries: int


@router.get("/api/v1/overview", response_model=Overview)
def overview(db: Session = Depends(get_db)) -> Overview:
    """Exact counts for the dashboard (the list endpoints are capped, so counting their pages would silently undercount)."""
    def by(col, *where) -> dict[str, int]:
        return dict(db.execute(select(col, func.count()).where(*where).group_by(col)).tuples().all())

    return Overview(
        events_total=db.scalar(select(func.count()).select_from(SecurityEvent)) or 0,
        last_event_at=db.scalar(select(func.max(SecurityEvent.timestamp))),
        alerts_by_severity=by(Alert.severity),
        open_incidents_by_severity=by(Incident.severity, Incident.status == "open"),
        pending_actions=db.scalar(select(func.count()).select_from(ResponseAction).where(ResponseAction.status == "proposed")) or 0,
        active_blocklist_entries=db.scalar(select(func.count()).select_from(BlocklistEntry).where(BlocklistEntry.active)) or 0,
    )


@router.get("/api/v1/agent-runs", response_model=list[AgentRunOut])
def agent_runs(db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=200)) -> list[AgentRun]:
    return list(db.scalars(select(AgentRun).order_by(AgentRun.created_at.desc()).limit(limit)))
