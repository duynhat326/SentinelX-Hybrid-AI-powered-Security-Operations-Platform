import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import delete, text

from app.core.config import get_settings
from app.correlation.engine import backfill
from app.database.models import Asset, Incident, IncidentAlert, IncidentEntity
from app.database.session import get_factory
from tests.corpus_runner import payload

IP = "203.0.113.50"


def send(client, ev: dict, host: str, dt: int = 0) -> dict:
    r = client.post("/api/v1/events", json=payload({**ev, "dt": dt}, dt, host))
    assert r.status_code == 200, r.text
    return r.json()


def fails(client, host, ip=IP, user="root", start=0, n=5, users=None):
    for i in range(n):
        send(client, {"k": "f", "ip": ip, "u": (users or [user])[i % len(users or [user])]}, host, start + i)


def netuser(user): return {"k": "p", "img": "net.exe", "par": "cmd.exe", "cmd": "net user bob Pw /add", "user": user}  # noqa: E704
def netadmin(user): return {"k": "p", "img": "net.exe", "par": "cmd.exe", "cmd": "net localgroup administrators bob /add", "user": user}  # noqa: E704
def runkey(img, user): return {"k": "r", "img": img, "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x", "val": "C:\\x.exe", "user": user}  # noqa: E704


def incidents(client, **params):
    return client.get("/api/v1/incidents", params=params).json()


def test_bruteforce_then_success_is_one_incident_with_risk_and_reason(client):
    fails(client, "web01")
    send(client, {"k": "s", "ip": IP, "u": "root"}, "web01", 5)
    (inc,) = incidents(client)
    assert inc["alert_count"] == 2 and inc["severity"] == "critical" and inc["hosts"] == ["web01"]
    assert inc["mitre"] == ["T1078", "T1110"] and inc["title"].endswith("(+1 related)")
    # (0.4*100 + 0.3*33.3 + 0.1*50) / 0.8 = 68.75, threat intel missing and renormalized
    assert inc["risk_score"] == 69
    d = client.get(f"/api/v1/incidents/{inc['id']}").json()
    assert d["risk_breakdown"]["missing"] == ["threat_intel"]
    assert {a["rule_id"] for a in d["alerts"]} == {"SX-001", "SX-008"}
    assert {a["reason"] for a in d["alerts"]} == {"seed", f"ip:{IP}"}
    assert all(a["incident_id"] == inc["id"] for a in client.get("/api/v1/alerts").json())


def test_timeline_is_ordered_cited_and_capped(client):
    fails(client, "web01")
    send(client, {"k": "s", "ip": IP, "u": "root"}, "web01", 5)
    (inc,) = incidents(client)
    d = client.get(f"/api/v1/incidents/{inc['id']}").json()
    assert d["timeline_total"] == 6 and len(d["timeline"]) == 6
    stamps = [e["timestamp"] for e in d["timeline"]]
    assert stamps == sorted(stamps)
    assert [len(e["alert_ids"]) for e in d["timeline"]] == [2, 2, 2, 2, 2, 1]  # failures cited by both rules, success by SX-008 only
    assert d["entities"]["host"] == ["web01"] and d["entities"]["ip"] == [IP]
    short = client.get(f"/api/v1/incidents/{inc['id']}", params={"timeline_limit": 3}).json()
    assert len(short["timeline"]) == 3 and short["timeline_total"] == 6 and short["timeline"][0]["event_id"] == d["timeline"][0]["event_id"]


def test_alerts_far_apart_in_time_are_separate_incidents(client):
    fails(client, "web01", start=0)
    fails(client, "web01", start=10_000)  # 2.7 h later, window is 1 h
    assert len(incidents(client)) == 2


def test_unrelated_hosts_and_users_stay_separate(client):
    send(client, netuser("LAB\\alice"), "h1", 0)
    send(client, netuser("LAB\\bob"), "h2", 1)
    assert len(incidents(client)) == 2


def test_same_attacker_ip_links_hosts(client):
    fails(client, "web01")
    fails(client, "db01", start=10)
    (inc,) = incidents(client)
    assert inc["alert_count"] == 2 and inc["hosts"] == ["db01", "web01"]


def test_user_link_normalizes_domain_and_case_but_ignores_generic_users(client):
    send(client, netuser("LAB\\Alice"), "h1", 0)
    send(client, netadmin("alice"), "h2", 1)
    (inc,) = incidents(client)
    assert inc["alert_count"] == 2
    detail = client.get(f"/api/v1/incidents/{inc['id']}").json()
    assert {a["reason"] for a in detail["alerts"]} == {"seed", "user:alice"}


def test_generic_username_does_not_link(client):
    fails(client, "web01", ip="203.0.113.10", user="root")
    fails(client, "db01", ip="203.0.113.11", user="root", start=10)
    assert len(incidents(client)) == 2


def test_unusual_process_path_links_but_system_binary_does_not(client):
    send(client, runkey("C:\\Users\\lab\\dropper.exe", "LAB\\alice"), "h1", 0)
    send(client, runkey("C:\\Users\\lab\\dropper.exe", "LAB\\bob"), "h2", 1)
    send(client, runkey("reg.exe", "LAB\\carol"), "h3", 2)
    send(client, runkey("reg.exe", "LAB\\dave"), "h4", 3)
    counts = sorted(i["alert_count"] for i in incidents(client))
    assert counts == [1, 1, 2]  # dropper pair linked; the two reg.exe alerts are not


def test_same_alert_activity_is_idempotent(client):
    fails(client, "web01")
    (before,) = incidents(client)
    fails(client, "web01")  # exact duplicates are ignored
    send(client, {"k": "f", "ip": IP, "u": "root"}, "web01", 6)  # one more failure extends the alert
    (after,) = incidents(client)
    assert after["id"] == before["id"] and after["alert_count"] == 1 and after["risk_score"] == before["risk_score"]
    assert after["last_seen"] > before["last_seen"]
    assert len(client.get("/api/v1/alerts").json()) == 1


def test_bridging_alert_merges_two_incidents(client):
    send(client, netuser("LAB\\alice"), "h1", 0)
    send(client, netuser("LAB\\bob"), "h2", 1)
    first, second = incidents(client)
    fails(client, "h3", users=["alice", "bob"], start=10)  # one alert whose evidence names both users
    (merged,) = incidents(client)
    assert merged["alert_count"] == 3 and merged["hosts"] == ["h1", "h2", "h3"]
    old = {first["id"], second["id"]} - {merged["id"]}
    assert len(old) == 1 and client.get(f"/api/v1/incidents/{old.pop()}").status_code == 404
    with get_factory()() as db:  # nothing orphaned
        assert db.query(IncidentEntity).filter(IncidentEntity.incident_id.not_in(db.query(Incident.id))).count() == 0


def test_out_of_order_alert_arrival_still_correlates_and_widens_bounds(client):
    send(client, netuser("LAB\\alice"), "h1", 1000)
    send(client, netadmin("LAB\\alice"), "h1", 100)  # earlier event arrives later
    (inc,) = incidents(client)
    assert inc["alert_count"] == 2 and inc["first_seen"] < inc["last_seen"]
    assert inc["first_seen"].startswith("2026-11-15T10:01:40") and inc["last_seen"].startswith("2026-11-15T10:16:40")


def test_closed_incident_is_not_extended(client):
    send(client, netuser("LAB\\alice"), "h1", 0)
    with get_factory()() as db:
        db.query(Incident).update({"status": "closed"})
        db.commit()
    send(client, netadmin("LAB\\alice"), "h1", 5)
    assert len(incidents(client)) == 2 and len(incidents(client, status="open")) == 1


def test_asset_criticality_changes_risk(client):
    with get_factory()() as db:
        db.add_all([Asset(hostname="crit5", criticality=5), Asset(hostname="crit1", criticality=1)])
        db.commit()
    fails(client, "crit5", ip="203.0.113.21")
    fails(client, "crit1", ip="203.0.113.22", start=10)
    by_host = {i["hosts"][0]: i["risk_score"] for i in incidents(client)}
    assert by_host == {"crit5": 50, "crit1": 38}  # (0.4*75 + 0.1*asset) / 0.8


def test_list_filters_ordering_auth_and_unknown_id(client):
    fails(client, "web01")
    send(client, {"k": "s", "ip": IP, "u": "root"}, "web01", 5)
    send(client, netuser("LAB\\zed"), "lonely", 50)
    scores = [i["risk_score"] for i in incidents(client)]
    assert scores == sorted(scores, reverse=True) and len(scores) == 2
    assert len(incidents(client, min_risk=scores[0])) == 1 and incidents(client, status="closed") == []
    assert client.get(f"/api/v1/incidents/{uuid.uuid4()}").status_code == 404
    assert client.get("/api/v1/incidents/not-a-uuid").status_code == 422
    assert client.get("/api/v1/incidents", headers={"X-API-Key": "bad"}).status_code == 401
    assert client.get(f"/api/v1/incidents/{uuid.uuid4()}", headers={"X-API-Key": "bad"}).status_code == 401


def test_backfill_creates_incidents_for_alerts_that_have_none(client):
    fails(client, "web01")
    with get_factory()() as db:
        for t in (IncidentEntity, IncidentAlert, Incident):
            db.execute(delete(t))
        db.commit()
    assert incidents(client) == []
    with get_factory()() as db:
        assert backfill(db, get_settings()) == 1
        assert backfill(db, get_settings()) == 0
    assert len(incidents(client)) == 1


def test_concurrent_alerts_from_one_attacker_make_one_incident(client):
    if not os.environ.get("SENTINELX_TEST_DATABASE_URL", "").startswith("postgresql"):
        pytest.skip("needs PostgreSQL: SQLite serializes writers")
    hosts = [f"h{i}" for i in range(8)]
    for h in hosts:  # 4 failures each: no alert yet
        fails(client, h, n=4)
    barrier = threading.Barrier(len(hosts))

    def fifth(h: str) -> int:  # all eight 5th failures create their alert and correlate at the same moment
        barrier.wait()
        return client.post("/api/v1/events", json=payload({"k": "f", "ip": IP, "u": "root", "dt": 4}, 4, h)).status_code

    with ThreadPoolExecutor(len(hosts)) as ex:
        assert list(ex.map(fifth, hosts)) == [200] * 8
    (inc,) = incidents(client)
    assert inc["alert_count"] == 8 and inc["hosts"] == sorted(hosts)
    with get_factory()() as db:
        assert db.execute(text("select count(*) from incident_alerts")).scalar() == 8
        assert db.execute(text("select count(*) from incidents")).scalar() == 1
