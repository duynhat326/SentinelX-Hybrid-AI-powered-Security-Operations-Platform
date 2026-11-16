import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.audit import audit
from app.api.auth import PERMISSIONS, Principal, current_principal, require
from app.api.ratelimit import make_limiter
from app.core.config import Settings, get_settings
from app.core.security import (
    DUMMY_HASH,
    MAX_PASSWORD,
    MIN_PASSWORD,
    USERNAME_RE,
    hash_password,
    hash_token,
    new_token,
    verify_password,
)
from app.database.models import AuditLog, AuthToken, User
from app.database.session import get_db

router = APIRouter()
login_limit = make_limiter("login", lambda c: c.login_rate_limit_per_minute)

Role = Literal["viewer", "analyst", "approver", "admin"]


class LoginIn(BaseModel):
    username: str = Field(max_length=200)
    password: str = Field(max_length=MAX_PASSWORD)


class UserIn(BaseModel):
    username: str = Field(pattern=USERNAME_RE.pattern)
    password: str = Field(min_length=MIN_PASSWORD, max_length=MAX_PASSWORD)
    role: Role


class UserPatch(BaseModel):
    role: Role | None = None
    active: bool | None = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    username: str
    role: str
    active: bool
    created_at: datetime


@router.post("/api/v1/auth/login", dependencies=[Depends(login_limit)])
def login(body: LoginIn, request: Request, db: Session = Depends(get_db), cfg: Settings = Depends(get_settings)) -> dict:
    user = db.scalar(select(User).where(User.username == body.username.strip().lower()))
    ok = verify_password(body.password, user.password_hash if user else DUMMY_HASH)  # same work whether or not the user exists
    # log the name only if it is a well-formed username: people sometimes type their password into that field
    name = body.username.strip().lower() if USERNAME_RE.match(body.username.strip().lower()) else "<malformed>"
    if not (user and ok and user.active):
        audit(db, None, "auth.login", target_type="username", target_id=name, outcome="denied", request=request)
        db.commit()
        raise HTTPException(401, "invalid credentials")  # one message for unknown user, wrong password and disabled account
    token, digest = new_token()
    expires = datetime.now(UTC) + timedelta(minutes=cfg.token_ttl_minutes)
    db.add(AuthToken(user_id=user.id, token_sha256=digest, expires_at=expires))
    audit(db, f"user:{user.username}", "auth.login", target_type="user", target_id=str(user.id), request=request)
    db.commit()
    return {"token": token, "token_type": "bearer", "expires_at": expires.isoformat(), "username": user.username, "role": user.role}


@router.post("/api/v1/auth/logout")
def logout(request: Request, who: Principal = Depends(current_principal), db: Session = Depends(get_db),
           authorization: Annotated[str | None, Header()] = None) -> dict:
    if who.user_id is None:
        raise HTTPException(400, "only a user session can log out")
    tok = db.scalar(select(AuthToken).where(AuthToken.token_sha256 == hash_token((authorization or "").partition(" ")[2].strip())))
    if tok:
        tok.revoked = True
    audit(db, who, "auth.logout", target_type="user", target_id=str(who.user_id), request=request)
    db.commit()
    return {"status": "logged out"}


@router.get("/api/v1/auth/me")
def me(who: Principal = Depends(current_principal)) -> dict:
    # the dashboard hides what a caller may not do; the server still enforces every permission
    return {"name": who.name, "role": who.role, "permissions": sorted(PERMISSIONS[who.role])}


@router.post("/api/v1/users", response_model=UserOut, status_code=201)
def create_user(body: UserIn, request: Request, who: Principal = Depends(require("manage_users")), db: Session = Depends(get_db)) -> User:
    if db.scalar(select(User.id).where(User.username == body.username)):
        raise HTTPException(409, "username already exists")
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.flush()
    audit(db, who, "user.create", target_type="user", target_id=str(user.id), detail={"username": user.username, "role": user.role}, request=request)
    db.commit()
    return user


@router.get("/api/v1/users", response_model=list[UserOut], dependencies=[Depends(require("manage_users"))])
def list_users(db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.username)))


@router.patch("/api/v1/users/{user_id}", response_model=UserOut)
def patch_user(user_id: uuid.UUID, body: UserPatch, request: Request, who: Principal = Depends(require("manage_users")),
               db: Session = Depends(get_db)) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    before = {"role": user.role, "active": user.active}
    new_role, new_active = body.role or user.role, user.active if body.active is None else body.active
    losing_admin = user.role == "admin" and user.active and (new_role != "admin" or not new_active)
    if losing_admin and (db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.active)) or 0) <= 1:
        raise HTTPException(409, "cannot demote or disable the last active admin")
    user.role, user.active = new_role, new_active
    audit(db, who, "user.update", target_type="user", target_id=str(user.id), detail={"before": before, "after": {"role": new_role, "active": new_active}}, request=request)
    db.commit()
    return user


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    ts: datetime
    actor: str
    role: str | None
    action: str
    target_type: str | None
    target_id: str | None
    outcome: str
    ip: str | None
    detail: dict


@router.get("/api/v1/audit-logs", response_model=list[AuditOut], dependencies=[Depends(require("read_audit"))])
def list_audit(db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=500), action: str | None = None,
               actor: str | None = None, outcome: str | None = None) -> list[AuditLog]:
    q = select(AuditLog)
    for col, val in ((AuditLog.action, action), (AuditLog.actor, actor), (AuditLog.outcome, outcome)):
        if val:
            q = q.where(col == val)
    return list(db.scalars(q.order_by(AuditLog.ts.desc()).limit(limit)))
