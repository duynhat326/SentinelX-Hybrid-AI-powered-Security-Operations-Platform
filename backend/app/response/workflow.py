"""The approval state machine. Every transition is audited, takes a row lock, and is safe to repeat.

    proposed --approve (dry run, the default)--> simulated
    proposed --approve (real, if enabled and the type allows it)--> executed | failed
    proposed --reject--> rejected
    executed --rollback (blocklist entries)--> rolled_back

Approval needs the `approve` permission, a person other than the requester, and passes the policy again at that moment.
"""
from datetime import UTC, datetime

from fastapi import Request
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.audit import audit
from app.api.auth import Principal
from app.api.incidents import get_incident
from app.core.config import Settings
from app.database.models import BlocklistEntry, Incident, ResponseAction
from app.response.actions import ADAPTER, GUIDANCE, REAL_CAPABLE, build_report, describe, fingerprint, violations


class WorkflowError(Exception):
    def __init__(self, status: int, message: str, reasons: list[str] | None = None) -> None:
        super().__init__(message)
        self.status, self.message, self.reasons = status, message, reasons or []


class PolicyViolation(Exception):
    def __init__(self, reasons: list[str]) -> None:
        super().__init__("policy violation")
        self.reasons = reasons


class KeyConflict(Exception):
    pass


def create_action(db: Session, cfg: Settings, inc: Incident, params, *, by: str, triggered_by: str, source: str, key: str | None) -> tuple[ResponseAction, bool]:
    """(action, created). A repeated idempotency key from the same requester returns the original instead of a duplicate."""
    data = params.model_dump()
    digest = fingerprint(inc.id, data)

    def existing() -> ResponseAction | None:
        row = db.scalar(select(ResponseAction).where(ResponseAction.requested_by == by, ResponseAction.idempotency_key == key)) if key else None
        if row and row.request_hash != digest:
            raise KeyConflict
        return row

    if (row := existing()) is not None:
        return row, False
    if reasons := violations(db, cfg, inc, params):
        raise PolicyViolation(reasons)
    action = ResponseAction(incident_id=inc.id, type=params.type, params=data, status="proposed", source=source, requested_by=by, triggered_by=triggered_by,
                            rollback_guidance=GUIDANCE[params.type], idempotency_key=key, request_hash=digest)
    try:
        with db.begin_nested():
            db.add(action)
    except IntegrityError:  # a concurrent request with the same key won
        if (row := existing()) is not None:
            return row, False
        raise
    return action, True


def _deny(db: Session, who: Principal, request: Request | None, action: ResponseAction | None, verb: str, status: int, message: str,
          reasons: list[str] | None = None) -> None:
    audit(db, who, f"response.{verb}", target_type="response_action", target_id=str(action.id) if action else None, outcome="denied",
          detail={"why": message, "reasons": reasons or [], "type": action.type if action else None, "status": action.status if action else None}, request=request)
    db.commit()  # the refusal itself must survive the failed request
    raise WorkflowError(status, message, reasons)


def _locked(db: Session, action_id) -> ResponseAction:
    action = db.scalar(select(ResponseAction).where(ResponseAction.id == action_id).with_for_update())  # serialises concurrent decisions on PostgreSQL
    if action is None:
        raise WorkflowError(404, "response action not found")
    return action


def propose(db: Session, cfg: Settings, who: Principal, inc: Incident, params, key: str | None, request: Request | None) -> tuple[ResponseAction, bool]:
    try:
        action, created = create_action(db, cfg, inc, params, by=who.name, triggered_by=who.name, source="human", key=key)
    except PolicyViolation as e:
        audit(db, who, "response.propose", target_type="incident", target_id=str(inc.id), outcome="denied",
              detail={"type": params.type, "reasons": e.reasons}, request=request)
        db.commit()
        raise WorkflowError(422, "policy violation", e.reasons) from e
    except KeyConflict as e:
        raise WorkflowError(409, "this Idempotency-Key was already used for a different request") from e
    if created:
        audit(db, who, "response.propose", target_type="response_action", target_id=str(action.id),
              detail={"type": action.type, "incident": str(inc.id), "source": "human"}, request=request)
    db.commit()
    return action, created


def approve(db: Session, cfg: Settings, who: Principal, action_id, real: bool, request: Request | None) -> ResponseAction:
    a = _locked(db, action_id)
    if a.status in ("simulated", "executed"):
        if real and a.status == "simulated":
            _deny(db, who, request, a, "approve", 409, "it was approved as a dry run; propose a new action to run it for real")
        return a  # approving twice is the same as approving once
    if a.status != "proposed":
        _deny(db, who, request, a, "approve", 409, f"the action is {a.status}")
    if who.name in (a.requested_by, a.triggered_by):  # also whoever asked the policy or the model for it
        _deny(db, who, request, a, "approve", 403, "a different person must approve: nobody approves a proposal they made or asked for")
    if real and not cfg.response_real_actions_enabled:
        _deny(db, who, request, a, "approve", 409, "real actions are disabled (SENTINELX_RESPONSE_REAL_ACTIONS_ENABLED=false): approve as a dry run")
    if real and a.type not in REAL_CAPABLE:
        _deny(db, who, request, a, "approve", 409, f"{a.type} can only be simulated")
    inc = db.get(Incident, a.incident_id)
    try:
        params = ADAPTER.validate_python(a.params)
    except ValidationError:
        _deny(db, who, request, a, "approve", 409, "the stored action no longer validates")
    if inc is None or (reasons := violations(db, cfg, inc, params)):
        _deny(db, who, request, a, "approve", 409, "the policy no longer allows this action", reasons if inc else ["the incident no longer exists"])
    now = datetime.now(UTC)
    a.decided_by, a.decided_at = who.name, now
    audit(db, who, "response.approve", target_type="response_action", target_id=str(a.id), detail={"type": a.type, "real": real}, request=request)
    try:
        with db.begin_nested():
            if real and a.type == "add_blocklist_entry":
                db.add(BlocklistEntry(ip=params.ip, action_id=a.id, created_by=who.name))
                result = {"dry_run": False, "blocklisted": params.ip}
            elif real:  # generate_report
                result = {"dry_run": False, "report_markdown": build_report(get_incident(a.incident_id, db, 100), _history(db, a.incident_id))}
            else:
                result = {"dry_run": True, "would": describe(params)}
            db.flush()
    except Exception as e:
        a.status, a.result = "failed", {"error": type(e).__name__}
        audit(db, who, "response.execute", target_type="response_action", target_id=str(a.id), outcome="error", detail={"type": a.type, "error": type(e).__name__}, request=request)
    else:
        a.status, a.result, a.executed_at = ("executed" if real else "simulated"), result, now
        audit(db, who, "response.execute", target_type="response_action", target_id=str(a.id), detail={"type": a.type, "dry_run": result["dry_run"]}, request=request)
    db.commit()
    return a


def _history(db: Session, incident_id) -> list[ResponseAction]:
    return list(db.scalars(select(ResponseAction).where(ResponseAction.incident_id == incident_id).order_by(ResponseAction.requested_at)))


def reject(db: Session, who: Principal, action_id, reason: str, request: Request | None) -> ResponseAction:
    a = _locked(db, action_id)
    if a.status == "rejected":
        return a
    if a.status != "proposed":
        _deny(db, who, request, a, "reject", 409, f"the action is {a.status}")
    a.status, a.decided_by, a.decided_at, a.decision_reason = "rejected", who.name, datetime.now(UTC), reason
    audit(db, who, "response.reject", target_type="response_action", target_id=str(a.id), detail={"type": a.type, "reason": reason}, request=request)
    db.commit()
    return a


def rollback(db: Session, who: Principal, action_id, request: Request | None) -> ResponseAction:
    a = _locked(db, action_id)
    if a.status == "rolled_back":
        return a
    if a.status != "executed" or a.type != "add_blocklist_entry":
        dry = "It was approved as a dry run, so nothing was changed and there is nothing to undo."
        _deny(db, who, request, a, "rollback", 409, "there is nothing to roll back automatically" if a.status != "executed" else "no automatic rollback for this type",
              [dry if a.status == "simulated" else a.rollback_guidance])
    entry = db.scalar(select(BlocklistEntry).where(BlocklistEntry.action_id == a.id, BlocklistEntry.active))
    if entry:
        entry.active, entry.removed_at, entry.removed_by = False, datetime.now(UTC), who.name
    a.status = "rolled_back"
    audit(db, who, "response.rollback", target_type="response_action", target_id=str(a.id), detail={"type": a.type, "had_active_entry": entry is not None}, request=request)
    db.commit()
    return a
