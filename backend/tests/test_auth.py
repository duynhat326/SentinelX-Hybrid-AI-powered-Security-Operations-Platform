import io
import json

import pytest
from sqlalchemy import select

from app import manage
from app.core.security import hash_password, hash_token, verify_password
from app.database.models import AuditLog, AuthToken, User
from app.database.session import get_factory
from tests.conftest import KEY, PASSWORD, make_user, session_for

NO_KEY = {"X-API-Key": ""}  # drop the test client's default API key


def login(client, username, password=PASSWORD):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password}, headers=NO_KEY)


def audit_rows(**where):
    with get_factory()() as db:
        q = select(AuditLog).order_by(AuditLog.ts)
        for k, v in where.items():
            q = q.where(getattr(AuditLog, k) == v)
        return list(db.scalars(q))


def test_password_hash_roundtrip_and_rejects_garbage():
    h = hash_password("a long enough password")
    assert h.startswith("scrypt$") and "a long enough password" not in h
    assert verify_password("a long enough password", h) and not verify_password("another one", h)
    assert h != hash_password("a long enough password")  # fresh salt each time
    assert not verify_password("x", "not-a-hash") and not verify_password("x", "md5$1$2$3$4$5")


def test_login_returns_a_working_token_and_audits_it(client):
    make_user("alice-a", "analyst")
    r = login(client, "alice-a")
    assert r.status_code == 200 and r.json()["role"] == "analyst"
    me = client.get("/api/v1/auth/me", headers={**NO_KEY, "Authorization": f"Bearer {r.json()['token']}"})
    assert me.json() == {"name": "user:alice-a", "role": "analyst"}
    (row,) = audit_rows(action="auth.login")
    assert (row.actor, row.outcome) == ("user:alice-a", "ok")


def test_failed_logins_look_identical_and_are_audited_without_leaking_what_was_typed(client):
    make_user("bob-b", "viewer")
    make_user("gone-g", "viewer", active=False)
    answers = [login(client, "bob-b", "wrong password!!"), login(client, "nobody-n"), login(client, "gone-g"),
               login(client, "Hunter2 is my password!")]
    assert {(r.status_code, r.text) for r in answers} == {(401, '{"detail":"invalid credentials"}')}
    rows = audit_rows(action="auth.login", outcome="denied")
    assert len(rows) == 4 and [r.target_id for r in rows] == ["bob-b", "nobody-n", "gone-g", "<malformed>"]
    assert "Hunter2" not in json.dumps([[r.target_id, r.detail] for r in rows])


def test_only_hashes_are_stored(client):
    make_user("carol-c", "viewer")
    token = login(client, "carol-c").json()["token"]
    with get_factory()() as db:
        assert db.scalar(select(AuthToken.token_sha256)) == hash_token(token) != token
        assert db.scalar(select(User.password_hash)).startswith("scrypt$")


def test_logout_revokes_the_session(client):
    make_user("dave-d", "viewer")
    h = {**NO_KEY, "Authorization": f"Bearer {login(client, 'dave-d').json()['token']}"}
    assert client.post("/api/v1/auth/logout", headers=h).status_code == 200
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401
    assert [r.outcome for r in audit_rows(action="auth.logout")] == ["ok"]
    assert client.post("/api/v1/auth/logout").status_code == 400  # the service key has no session to end


def _expire(db, tok):
    from datetime import UTC, datetime, timedelta
    tok.expires_at = datetime.now(UTC) - timedelta(seconds=1)


def _revoke(db, tok):
    tok.revoked = True


def _disable(db, tok):
    db.get(User, tok.user_id).active = False


@pytest.mark.parametrize("break_it", [_expire, _revoke, _disable])
def test_expired_revoked_and_disabled_sessions_are_refused(client, break_it):
    make_user("erin-e", "analyst")
    h = {**NO_KEY, "Authorization": f"Bearer {login(client, 'erin-e').json()['token']}"}
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200
    with get_factory()() as db:
        break_it(db, db.scalar(select(AuthToken)))
        db.commit()
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


@pytest.mark.parametrize("auth", ["Bearer", "Bearer ", "Basic abc", "Bearer not-a-real-token", f"Bearer {KEY}", "bearer"])
def test_bad_bearer_headers_are_refused_and_never_fall_back_to_the_api_key(client, auth):
    # the test client also sends a valid X-API-Key: a wrong bearer must still fail, not quietly use it
    assert client.get("/api/v1/incidents", headers={"Authorization": auth}).status_code == 401


def test_login_is_rate_limited_even_for_the_right_password(client, monkeypatch):
    from app.core import config

    make_user("fred-f", "viewer")
    monkeypatch.setenv("SENTINELX_LOGIN_RATE_LIMIT_PER_MINUTE", "3")
    config.get_settings.cache_clear()
    assert [login(client, "fred-f", "nope nope nope").status_code for _ in range(3)] == [401, 401, 401]
    assert login(client, "fred-f").status_code == 429


def test_user_management_and_the_last_admin_guard(client):
    admin = session_for("admin", "root-r")
    new = {"username": "gina-g", "password": "a perfectly fine pass", "role": "analyst"}
    r = client.post("/api/v1/users", json=new, headers=admin)
    assert r.status_code == 201 and "password" not in r.text and r.json()["role"] == "analyst"
    assert client.post("/api/v1/users", json=new, headers=admin).status_code == 409
    for bad in ({**new, "username": "x"}, {**new, "username": "UPPER-case"}, {**new, "password": "short"}, {**new, "username": "hank-h", "role": "root"}):
        assert client.post("/api/v1/users", json=bad, headers=admin).status_code == 422
    listed = client.get("/api/v1/users", headers=admin).json()
    assert {u["username"] for u in listed} == {"root-r", "gina-g"} and all("password_hash" not in u for u in listed)
    gina = next(u for u in listed if u["username"] == "gina-g")["id"]
    assert client.patch(f"/api/v1/users/{gina}", json={"role": "approver"}, headers=admin).json()["role"] == "approver"
    # disabling a user cuts off a session that was already issued
    gina_h = {**NO_KEY, "Authorization": f"Bearer {login(client, 'gina-g', 'a perfectly fine pass').json()['token']}"}
    assert client.get("/api/v1/auth/me", headers=gina_h).status_code == 200
    client.patch(f"/api/v1/users/{gina}", json={"active": False}, headers=admin)
    assert client.get("/api/v1/auth/me", headers=gina_h).status_code == 401
    root = next(u for u in listed if u["username"] == "root-r")["id"]
    assert client.patch(f"/api/v1/users/{root}", json={"role": "viewer"}, headers=admin).status_code == 409
    assert client.patch(f"/api/v1/users/{root}", json={"active": False}, headers=admin).status_code == 409
    assert [r.action for r in audit_rows(action="user.create")] == ["user.create"]
    assert len(audit_rows(action="user.update")) == 2


def test_passwords_and_tokens_never_reach_audit_logs_or_responses(client):
    admin = session_for("admin", "root-r")
    secret = "S3cretPassw0rd-unique"
    created = client.post("/api/v1/users", json={"username": "ivy-i", "password": secret, "role": "viewer"}, headers=admin)
    token = login(client, "ivy-i", secret).json()["token"]
    login(client, "ivy-i", "wrong wrong wrong")
    everything = created.text + client.get("/api/v1/users", headers=admin).text + client.get("/api/v1/audit-logs", headers=admin).text
    with get_factory()() as db:
        everything += json.dumps([[r.actor, r.target_id, r.detail] for r in db.scalars(select(AuditLog))])
    assert secret not in everything and token not in everything and "wrong wrong wrong" not in everything


def test_cli_creates_users_with_the_same_rules_and_audits_as_cli(client, monkeypatch):
    with get_factory()() as db:
        u = manage.create_user(db, "jack-j", "a perfectly fine pass", "admin")
        assert u.role == "admin"
        for args, msg in ((("jack-j", "a perfectly fine pass", "admin"), "exists"), (("x", "a perfectly fine pass", "admin"), "username"),
                          (("kim-k", "short", "admin"), "password"), (("kim-k", "a perfectly fine pass", "root"), "role")):
            with pytest.raises(ValueError, match=msg):
                manage.create_user(db, *args)
    monkeypatch.setattr("sys.stdin", io.StringIO("another fine password\n"))
    assert manage.main(["create-user", "lea-l", "viewer", "--password-stdin"]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO("tiny\n"))
    assert manage.main(["create-user", "mo-m", "viewer", "--password-stdin"]) == 1
    assert login(client, "lea-l", "another fine password").status_code == 200
    assert {r.actor for r in audit_rows(action="user.create")} == {"cli"}
