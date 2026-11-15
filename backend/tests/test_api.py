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
