import uuid

from app.database.models import AgentRun
from app.database.session import get_factory
from tests.conftest import ssh_fail


def test_overview_counts_are_exact_and_not_page_limited(client):
    empty = client.get("/api/v1/overview").json()
    assert empty == {"events_total": 0, "last_event_at": None, "alerts_by_severity": {}, "open_incidents_by_severity": {},
                     "pending_actions": 0, "active_blocklist_entries": 0}
    for i in range(5):
        client.post("/api/v1/events", json=ssh_fail(i))
    o = client.get("/api/v1/overview").json()
    assert o["events_total"] == 5 and o["alerts_by_severity"] == {"high": 1} and o["open_incidents_by_severity"] == {"high": 1}
    assert o["last_event_at"].startswith("2026-11-15T10:00:04")


def test_agent_runs_lists_every_incident_newest_first(client):
    for i in range(5):
        client.post("/api/v1/events", json=ssh_fail(i))
    iid = uuid.UUID(client.get("/api/v1/incidents").json()[0]["id"])
    with get_factory()() as db:
        for n in range(3):
            db.add(AgentRun(incident_id=iid, status="ok", provider="mock", model=f"m{n}", prompt_version="v2", dropped_claims=0, rejected_tool_calls=[]))
        db.commit()
    runs = client.get("/api/v1/agent-runs?limit=2").json()
    assert len(runs) == 2 and runs[0]["created_at"] >= runs[1]["created_at"] and client.get("/api/v1/agent-runs?limit=0").status_code == 422
