import json
import os

import pytest
from fastapi.testclient import TestClient

KEY = "k" * 32


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Set SENTINELX_TEST_DATABASE_URL to run the suite against PostgreSQL (tables are wiped per test).
    url = os.environ.get("SENTINELX_TEST_DATABASE_URL") or f"sqlite+pysqlite:///{tmp_path}/t.db"
    monkeypatch.setenv("SENTINELX_DATABASE_URL", url)
    monkeypatch.setenv("SENTINELX_API_KEY", KEY)
    from app.api import ratelimit
    from app.core import config
    from app.database import session
    from app.database.models import Base

    config.get_settings.cache_clear()
    ratelimit.reset()
    session._engine = session._factory = None
    Base.metadata.drop_all(session.get_engine())
    Base.metadata.create_all(session.get_engine())
    from app.api.main import app

    with TestClient(app, headers={"X-API-Key": KEY}) as c:
        yield c


def ssh_fail(n: int, ip: str = "203.0.113.50") -> dict:
    line = f"2026-11-15T10:00:{n:02d}+00:00 web01 sshd[1201]: Failed password for invalid user admin from {ip} port {40220 + n} ssh2"
    return {"source": "linux_auth", "payload": line}


def sysmon_ps(cmd: str, t: str = "2026-11-15 10:05:00.000") -> dict:
    rec = {"EventID": 1, "UtcTime": t, "Computer": "win10-lab", "User": "LAB\\alice",
           "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
           "ParentImage": "C:\\Windows\\System32\\cmd.exe", "CommandLine": cmd}
    return {"source": "sysmon", "payload": json.dumps(rec)}


# --- users and sessions for authorization tests -------------------------------------------------
PASSWORD = "correct horse battery"
_PASSWORD_HASH = None


def make_user(username: str, role: str, active: bool = True, password: str = PASSWORD):
    from app.core.security import hash_password
    from app.database.models import User
    from app.database.session import get_factory

    global _PASSWORD_HASH
    if password == PASSWORD:  # scrypt is deliberately slow: hash the shared test password once
        _PASSWORD_HASH = _PASSWORD_HASH or hash_password(PASSWORD)
    with get_factory()() as db:
        user = User(username=username, password_hash=_PASSWORD_HASH if password == PASSWORD else hash_password(password), role=role, active=active)
        db.add(user)
        db.commit()
        return user.id


def session_for(role: str, username: str | None = None, minutes: int = 60) -> dict:
    """Create a user and a live session directly; returns an Authorization header."""
    from datetime import UTC, datetime, timedelta

    from app.core.security import new_token
    from app.database.models import AuthToken
    from app.database.session import get_factory

    user_id = make_user(username or f"{role}-user", role)
    token, digest = new_token()
    with get_factory()() as db:
        db.add(AuthToken(user_id=user_id, token_sha256=digest, expires_at=datetime.now(UTC) + timedelta(minutes=minutes)))
        db.commit()
    return {"Authorization": f"Bearer {token}"}
