"""Every route, every kind of caller. The completeness test fails when a new route is added without a row here,
so an endpoint cannot ship without its authorization being decided and tested."""

from sqlalchemy import select

from app.api.auth import PERMISSIONS
from app.api.main import app
from app.database.models import AuditLog
from app.database.session import get_factory
from tests.conftest import KEY, session_for

ZERO = "00000000-0000-0000-0000-000000000000"
PUBLIC = {("GET", "/health"), ("POST", "/api/v1/auth/login")}  # FastAPI's own /docs and /openapi.json are not in the schema
ANY_USER = "authenticated"  # any valid principal may call it
MATRIX = {
    ("POST", "/api/v1/events"): "ingest",
    ("GET", "/api/v1/alerts"): "read",
    ("GET", "/api/v1/rules"): "read",
    ("GET", "/api/v1/incidents"): "read",
    ("GET", "/api/v1/incidents/{incident_id}"): "read",
    ("POST", "/api/v1/incidents/{incident_id}/investigate"): "investigate",
    ("GET", "/api/v1/incidents/{incident_id}/agent-runs"): "read",
    ("GET", "/api/v1/auth/me"): ANY_USER,
    ("POST", "/api/v1/users"): "manage_users",
    ("GET", "/api/v1/users"): "manage_users",
    ("PATCH", "/api/v1/users/{user_id}"): "manage_users",
    ("GET", "/api/v1/audit-logs"): "read_audit",
    ("POST", "/api/v1/enrich"): "enrich",
    ("POST", "/api/v1/incidents/{incident_id}/enrich"): "enrich",
    ("GET", "/api/v1/iocs"): "read",
    ("POST", "/api/v1/iocs"): "manage_iocs",
    ("DELETE", "/api/v1/iocs/{ioc_id}"): "manage_iocs",
    ("POST", "/api/v1/auth/logout"): ANY_USER,  # last: it revokes the caller's own session
}
NO_KEY = {"X-API-Key": ""}
ROLES = ["viewer", "analyst", "approver", "admin"]


def _routes():
    # app.routes does not list routers added with include_router in this FastAPI version; the OpenAPI schema lists everything
    return {(m.upper(), path) for path, ops in app.openapi()["paths"].items() for m in ops if m in ("get", "post", "put", "patch", "delete")}


def test_every_route_is_either_public_or_in_the_matrix():
    unknown = _routes() - PUBLIC - set(MATRIX)
    assert not unknown, f"routes without a declared permission: {sorted(unknown)}"
    assert not (set(MATRIX) - _routes()), "matrix lists a route that no longer exists"


def _call(client, method, path, headers):
    url = path.replace("{incident_id}", ZERO).replace("{user_id}", ZERO).replace("{ioc_id}", ZERO)
    kwargs = {"json": {}} if method in ("POST", "PATCH") else {}
    return client.request(method, url, headers=headers, **kwargs)


def test_every_route_enforces_its_permission_for_every_caller_and_audits_each_refusal(client):
    callers = {role: session_for(role, f"{role}-m") for role in ROLES}
    callers["service"] = {"X-API-Key": KEY}
    callers["anonymous"] = NO_KEY
    callers["bad-token"] = {**NO_KEY, "Authorization": "Bearer definitely-not-valid"}
    refused = []
    for (method, path), need in MATRIX.items():
        for who, headers in callers.items():
            code = _call(client, method, path, headers).status_code
            role = who if who in PERMISSIONS else None
            if role is None:  # no valid identity at all
                expect_blocked, want = True, 401
            elif need == ANY_USER:
                expect_blocked, want = False, None
            else:
                expect_blocked, want = need not in PERMISSIONS[role], 403
            if expect_blocked:
                assert code == want, f"{method} {path} as {who}: got {code}, want {want}"
                if want == 403:
                    refused.append(("service:api-key" if who == "service" else f"user:{who}-m", need))
            else:
                assert code not in (401, 403), f"{method} {path} as {who} should be allowed, got {code}"
    # 100% of refusals of an identified caller are in the audit log, with who and which permission was missing
    with get_factory()() as db:
        logged = [(r.actor, r.detail["needed"]) for r in db.scalars(select(AuditLog).where(AuditLog.action == "authz.denied"))]
    assert sorted(logged) == sorted(refused) and refused


def test_the_service_key_cannot_act_as_a_person():
    assert PERMISSIONS["service"] == {"read", "ingest", "investigate"}
    assert not (PERMISSIONS["service"] & {"propose", "approve", "manage_users", "read_audit", "manage_iocs", "enrich"})


def test_roles_only_ever_gain_permissions():
    assert PERMISSIONS["viewer"] < PERMISSIONS["analyst"] < PERMISSIONS["approver"] < PERMISSIONS["admin"]
    assert "ingest" not in PERMISSIONS["admin"]  # collectors use the service key, not a person


def test_no_route_can_modify_or_delete_audit_logs():
    assert not [(m, p) for m, p in _routes() if "audit" in p and m != "GET"]
