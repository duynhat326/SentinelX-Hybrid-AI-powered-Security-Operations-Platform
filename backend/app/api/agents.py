import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.investigate import investigate
from app.agents.llm import LLM, get_llm
from app.api.auth import require_key
from app.api.ratelimit import llm_rate_limit
from app.core.config import Settings, get_settings
from app.database.models import AgentRun, Incident
from app.database.session import get_db

router = APIRouter(prefix="/api/v1/incidents", dependencies=[Depends(require_key)])


class AgentRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    incident_id: uuid.UUID
    status: str
    provider: str
    model: str
    prompt_version: str
    input_sha256: str | None
    duration_ms: int | None
    output: dict[str, Any] | None
    dropped_claims: int
    rejected_tool_calls: list[dict[str, str]]  # name and truncated args of each refused tool call
    error: str | None
    created_at: datetime


@router.post("/{incident_id}/investigate", response_model=AgentRunOut, dependencies=[Depends(llm_rate_limit)])
def run_investigation(incident_id: uuid.UUID, db: Session = Depends(get_db), cfg: Settings = Depends(get_settings),
                      llm: LLM | None = Depends(get_llm)) -> AgentRun:
    if llm is None:
        raise HTTPException(503, "AI investigation is disabled (SENTINELX_LLM_PROVIDER=none)")
    return investigate(db, cfg, llm, incident_id)


@router.get("/{incident_id}/agent-runs", response_model=list[AgentRunOut])
def list_runs(incident_id: uuid.UUID, db: Session = Depends(get_db)) -> list[AgentRun]:
    if db.get(Incident, incident_id) is None:
        raise HTTPException(404, "incident not found")
    return list(db.scalars(select(AgentRun).where(AgentRun.incident_id == incident_id).order_by(AgentRun.created_at.desc()).limit(50)))
