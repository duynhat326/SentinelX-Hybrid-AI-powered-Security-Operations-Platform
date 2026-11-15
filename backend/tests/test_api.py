from tests.conftest import ssh_fail, sysmon_ps


def test_auth_required(client):
    assert client.get("/api/v1/alerts", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/api/v1/events", json=ssh_fail(1), headers={"X-API-Key": ""}).status_code == 401


def test_bruteforce_single_alert_with_evidence(client):
    for n in range(1, 5):
        assert client.post("/api/v1/events", json=ssh_fail(n)).json()["alerts"] == []
    r = client.post("/api/v1/events", json=ssh_fail(5)).json()
    assert len(r["alerts"]) == 1 and r["alerts"][0]["event_count"] == 5 and r["alerts"][0]["mitre"] == ["T1110"]
    client.post("/api/v1/events", json=ssh_fail(6))
    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) == 1 and alerts[0]["event_count"] == 6 and len(alerts[0]["evidence_event_ids"]) == 6


def test_duplicate_event_is_idempotent(client):
    assert client.post("/api/v1/events", json=ssh_fail(1)).json()["duplicate"] is False
    assert client.post("/api/v1/events", json=ssh_fail(1)).json()["duplicate"] is True


def test_different_sources_do_not_mix(client):
    for n in range(1, 5):
        client.post("/api/v1/events", json=ssh_fail(n, "203.0.113.1"))
        client.post("/api/v1/events", json=ssh_fail(n, "203.0.113.2"))
    assert client.get("/api/v1/alerts").json() == []


def test_powershell_detection_and_benign(client):
    bad = client.post("/api/v1/events", json=sysmon_ps("powershell.exe -nop -enc SQBFAFgA")).json()
    assert [a["rule_id"] for a in bad["alerts"]] == ["SX-002"]
    assert client.post("/api/v1/events", json=sysmon_ps("powershell.exe Get-Date", "2026-11-15 10:06:00.000")).json()["alerts"] == []
    # flag at very end of command line
    assert client.post("/api/v1/events", json=sysmon_ps("powershell.exe -e", "2026-11-15 10:07:00.000")).json()["alerts"] != []


def test_bad_payload_422(client):
    assert client.post("/api/v1/events", json={"source": "linux_auth", "payload": "nope"}).status_code == 422
    assert client.post("/api/v1/events", json={"source": "bogus", "payload": "x"}).status_code == 422


def test_concurrent_ingest_one_alert(client):
    import os
    from concurrent.futures import ThreadPoolExecutor

    import pytest

    if not os.environ.get("SENTINELX_TEST_DATABASE_URL", "").startswith("postgresql"):
        pytest.skip("needs PostgreSQL: SQLite serializes writers")
    with ThreadPoolExecutor(8) as ex:
        codes = list(ex.map(lambda n: client.post("/api/v1/events", json=ssh_fail(n)).status_code, range(1, 9)))
    assert codes == [200] * 8
    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) == 1 and alerts[0]["event_count"] == 8


def test_out_of_order_arrival_still_alerts_with_full_evidence(client):
    for n in (5, 4, 3, 2, 1):
        r = client.post("/api/v1/events", json=ssh_fail(n)).json()
    assert len(r["alerts"]) == 1 and r["alerts"][0]["event_count"] == 5


def test_rate_limit_returns_429(client, monkeypatch):
    from app.core import config

    monkeypatch.setenv("SENTINELX_RATE_LIMIT_PER_MINUTE", "3")
    config.get_settings.cache_clear()
    codes = [client.post("/api/v1/events", json=ssh_fail(n)).status_code for n in range(1, 6)]
    assert codes == [200, 200, 200, 429, 429]
    assert client.get("/api/v1/alerts").status_code == 200  # reads are not limited


def test_secret_in_json_payload_is_redacted_and_event_accepted(client):
    from app.database.models import SecurityEvent
    from app.database.session import get_factory

    r = client.post("/api/v1/events", json=sysmon_ps("tool.exe password=hunter2", "2026-11-15 10:09:00.000"))
    assert r.status_code == 200, r.text
    with get_factory()() as db:
        ev = db.query(SecurityEvent).one()
        assert "hunter2" not in str(ev.raw) and "hunter2" not in (ev.command_line or "")
