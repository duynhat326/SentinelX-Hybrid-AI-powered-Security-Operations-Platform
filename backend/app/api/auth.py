"""Who is calling and what they may do. Two kinds of principal:
- a user, via `Authorization: Bearer <token>` (from POST /api/v1/auth/login), with one of four fixed roles;
- the service API key (`X-API-Key`), kept for collectors and legacy clients, with a narrow fixed role.
Every route declares the permission it needs with `require(...)`; tests/test_authz_matrix.py fails if one forgets to.
"""
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.security import hash_token
from app.core.timeutil import utc
from app.database.models import AuditLog, AuthToken, User
from app.database.session import get_db

_ANALYST = {"read", "investigate", "enrich", "propose"}
_APPROVER = _ANALYST | {"approve", "manage_iocs"}
PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"read"}),
    "analyst": frozenset(_ANALYST),
    "approver": frozenset(_APPROVER),
    "admin": frozenset(_APPROVER | {"manage_users", "read_audit"}),
    "service": frozenset({"read", "ingest", "investigate"}),  # the shared API key: never proposes, approves or administers
}


@dataclass(frozen=True)
class Principal:
    name: str  # user:alice | service:api-key
    role: str
    user_id: object = None


def current_principal(
    db: Session = Depends(get_db), cfg: Settings = Depends(get_settings),
    authorization: Annotated[str | None, Header()] = None, x_api_key: Annotated[str, Header()] = "",
) -> Principal:
    if authorization:  # a bearer token that is wrong never falls back to the API key
        scheme, _, token = authorization.partition(" ")
        row = db.execute(select(AuthToken, User).join(User, User.id == AuthToken.user_id)
                         .where(AuthToken.token_sha256 == hash_token(token.strip()))).first() if scheme.lower() == "bearer" and token else None
        if row is None or row[0].revoked or utc(row[0].expires_at) <= datetime.now(UTC) or not row[1].active:
            raise HTTPException(401, "invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
        return Principal(f"user:{row[1].username}", row[1].role, row[1].id)
    if x_api_key and hmac.compare_digest(x_api_key.encode(), cfg.api_key.encode()):
        return Principal("service:api-key", "service")
    raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})


def require(permission: str):
    """Dependency: the caller must hold `permission`. A refusal is audited, then answered with 403."""

    def check(request: Request, who: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> Principal:
        if permission not in PERMISSIONS[who.role]:
            db.add(AuditLog(actor=who.name, role=who.role, action="authz.denied", outcome="denied",
                            ip=request.client.host if request.client else None,
                            detail={"needed": permission, "method": request.method, "path": request.url.path}))
            db.commit()  # must persist even though the request fails
            raise HTTPException(403, "insufficient role")
        return who

    return check
