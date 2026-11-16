import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.llm import LLM, get_llm
from app.agents.respond import PROMPT_VERSION, llm_candidates, policy_candidates
from app.api.audit import audit
from app.api.auth import Principal, require
from app.api.incidents import get_incident
from app.api.ratelimit import llm_rate_limit
from app.core.config import Settings, get_settings
from app.database.models import BlocklistEntry, Incident, ResponseAction
from app.database.session import get_db
from app.response import workflow
from app.response.actions import ActionParams
from app.response.workflow import KeyConflict, PolicyViolation, WorkflowError, create_action

router = APIRouter()
KEY_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"


class ActionOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    type: str
    params: dict[str, Any]
    status: str
    source: str
    requested_by: str
    triggered_by: str
    requested_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    decision_reason: str | None
    executed_at: datetime | None
    dry_run: bool | None  # true when approval only simulated; null until it has run


class ActionDetail(ActionOut):
    result: dict[str, Any] | None
    rollback_guidance: str


class SuggestIn(BaseModel):
    use_ai: bool = False


class SuggestOut(BaseModel):
    source: str
    created: list[ActionOut]
    existing: list[ActionOut]
    denied: list[dict[str, Any]]  # candidates the policy refused, with the reasons
    dropped: int  # model proposals that were not valid allowlisted actions
    error: str | None = None


class ApproveIn(BaseModel):
    real: bool = False  # false = dry run, the default


class RejectIn(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class BlocklistOut(BaseModel):
    id: uuid.UUID
    ip: str
    action_id: uuid.UUID
    active: bool
    created_at: datetime
    created_by: str
    removed_at: datetime | None
    removed_by: str | None


def _out(a: ResponseAction) -> ActionOut:
    return ActionOut(**{k: getattr(a, k) for k in ActionOut.model_fields if k != "dry_run"}, dry_run=(a.result or {}).get("dry_run"))


def _detail(a: ResponseAction) -> ActionDetail:
    return ActionDetail(**_out(a).model_dump(), result=a.result, rollback_guidance=a.rollback_guidance)


def _fail(e: WorkflowError) -> HTTPException:
    return HTTPException(e.status, detail={"message": e.message, "reasons": e.reasons})


def _incident(db: Session, incident_id: uuid.UUID) -> Incident:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    return inc


@router.post("/api/v1/incidents/{incident_id}/response-actions", response_model=ActionOut, status_code=201)
def propose_action(incident_id: uuid.UUID, body: ActionParams, request: Request, response: Response, who: Principal = Depends(require("propose")),
                   db: Session = Depends(get_db), cfg: Settings = Depends(get_settings),
                   idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", pattern=KEY_PATTERN)] = None) -> ActionOut:
    try:
        action, created = workflow.propose(db, cfg, who, _incident(db, incident_id), body, idempotency_key, request)
    except WorkflowError as e:
        raise _fail(e) from e
    response.status_code = 201 if created else 200  # a replay of the same request returns the original
    return _out(action)


@router.post("/api/v1/incidents/{incident_id}/response-actions/suggest", response_model=SuggestOut)
def suggest_actions(incident_id: uuid.UUID, body: SuggestIn, request: Request, who: Principal = Depends(require("propose")),
                    db: Session = Depends(get_db), cfg: Settings = Depends(get_settings), llm: LLM | None = Depends(get_llm)) -> SuggestOut:
    inc = _incident(db, incident_id)
    detail = get_incident(incident_id, db, 100)
    dropped, error = 0, None
    if body.use_ai:
        if llm is None:
            raise HTTPException(503, "AI is disabled (SENTINELX_LLM_PROVIDER=none)")
        llm_rate_limit(request, cfg)
        by, source = f"agent:{llm.name}", "agent"
        try:
            candidates, dropped = llm_candidates(cfg, llm, detail)
        except ValueError as e:
            candidates, error = [], str(e)
        except Exception as e:
            candidates, error = [], f"{type(e).__name__} (details withheld)"
    else:
        by, source, candidates = "policy", "policy", policy_candidates(detail)
    created: list[ActionOut] = []
    existing: list[ActionOut] = []
    denied: list[dict[str, Any]] = []
    for p in candidates:
        key = f"suggest:{incident_id}:{p.type}:{getattr(p, 'ip', None) or getattr(p, 'host', '')}"
        try:
            action, is_new = create_action(db, cfg, inc, p, by=by, triggered_by=who.name, source=source, key=key)
        except PolicyViolation as e:
            denied.append({"type": p.type, "target": getattr(p, "ip", None) or getattr(p, "host", None), "reasons": e.reasons})
            continue
        except KeyConflict:  # same target proposed again with different wording: it is the same suggestion
            same = db.scalar(select(ResponseAction).where(ResponseAction.requested_by == by, ResponseAction.idempotency_key == key))
            if same is None:
                raise
            action, is_new = same, False
        if is_new:
            audit(db, who, "response.propose", target_type="response_action", target_id=str(action.id),
                  detail={"type": action.type, "incident": str(incident_id), "source": source, "proposed_by": by, "prompt_version": PROMPT_VERSION}, request=request)
        (created if is_new else existing).append(_out(action))
    audit(db, who, "response.suggest", target_type="incident", target_id=str(incident_id),
          detail={"source": source, "created": len(created), "existing": len(existing), "denied": len(denied), "dropped": dropped, "error": error}, request=request)
    db.commit()
    return SuggestOut(source=source, created=created, existing=existing, denied=denied, dropped=dropped, error=error)


@router.get("/api/v1/response-actions", response_model=list[ActionOut], dependencies=[Depends(require("read"))])
def list_actions(db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=500), status: str | None = None,
                 incident_id: uuid.UUID | None = None) -> list[ActionOut]:
    q = select(ResponseAction)
    for col, val in ((ResponseAction.status, status), (ResponseAction.incident_id, incident_id)):
        if val:
            q = q.where(col == val)
    return [_out(a) for a in db.scalars(q.order_by(ResponseAction.requested_at.desc()).limit(limit))]


@router.get("/api/v1/response-actions/{action_id}", response_model=ActionDetail, dependencies=[Depends(require("read"))])
def get_action(action_id: uuid.UUID, db: Session = Depends(get_db)) -> ActionDetail:
    a = db.get(ResponseAction, action_id)
    if a is None:
        raise HTTPException(404, "response action not found")
    return _detail(a)


@router.post("/api/v1/response-actions/{action_id}/approve", response_model=ActionDetail)
def approve_action(action_id: uuid.UUID, body: ApproveIn, request: Request, who: Principal = Depends(require("approve")),
                   db: Session = Depends(get_db), cfg: Settings = Depends(get_settings)) -> ActionDetail:
    try:
        return _detail(workflow.approve(db, cfg, who, action_id, body.real, request))
    except WorkflowError as e:
        raise _fail(e) from e


@router.post("/api/v1/response-actions/{action_id}/reject", response_model=ActionDetail)
def reject_action(action_id: uuid.UUID, body: RejectIn, request: Request, who: Principal = Depends(require("approve")),
                  db: Session = Depends(get_db)) -> ActionDetail:
    try:
        return _detail(workflow.reject(db, who, action_id, body.reason, request))
    except WorkflowError as e:
        raise _fail(e) from e


@router.post("/api/v1/response-actions/{action_id}/rollback", response_model=ActionDetail)
def rollback_action(action_id: uuid.UUID, request: Request, who: Principal = Depends(require("approve")), db: Session = Depends(get_db)) -> ActionDetail:
    try:
        return _detail(workflow.rollback(db, who, action_id, request))
    except WorkflowError as e:
        raise _fail(e) from e


@router.get("/api/v1/blocklist", response_model=list[BlocklistOut], dependencies=[Depends(require("read"))])
def blocklist(db: Session = Depends(get_db), active_only: bool = True) -> list[BlocklistEntry]:
    q = select(BlocklistEntry).order_by(BlocklistEntry.created_at.desc()).limit(500)
    return list(db.scalars(q.where(BlocklistEntry.active) if active_only else q))
