import json

from fastapi import Request
from sqlalchemy.orm import Session

from app.api.auth import Principal
from app.database.models import AuditLog
from app.normalization.normalize import redact_obj

MAX_DETAIL_CHARS = 2000


def client_ip(request: Request | None) -> str | None:
    return request.client.host if request and request.client else None


def audit(db: Session, who: Principal | str | None, action: str, *, target_type: str | None = None, target_id: str | None = None,
          outcome: str = "ok", detail: dict | None = None, request: Request | None = None) -> None:
    """Add an audit row to the caller's transaction (it commits or rolls back with the action itself).
    Denied attempts must commit explicitly before raising, otherwise the failed request would roll the record back."""
    clean = redact_obj(detail or {})
    if len(json.dumps(clean, default=str)) > MAX_DETAIL_CHARS:
        clean = {"truncated": True}
    actor, role = (who.name, who.role) if isinstance(who, Principal) else (who or "anonymous", None)
    db.add(AuditLog(actor=actor, role=role, action=action, target_type=target_type, target_id=target_id, outcome=outcome,
                    ip=client_ip(request), detail=clean))
