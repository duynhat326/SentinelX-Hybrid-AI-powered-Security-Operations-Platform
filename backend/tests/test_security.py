"""Regression tests for the security review findings: attacker-controlled input must not evade detection."""
import json

from sqlalchemy import func, select

from app.database.models import SecurityEvent
from app.database.session import get_factory
from tests.corpus_runner import payload

IP = "203.0.113.50"


def ssh_line(i: int, name: str, ip: str = IP, what: str = "Failed password for invalid user") -> dict:
    return {"source": "linux_auth", "payload": f"2026-11-15T10:00:{i:02d}+00:00 web01 sshd[1]: {what} {name} from {ip} port {4000 + i} ssh2"}


def test_username_injection_does_not_evade_the_bruteforce_rule(client):
    for i in range(5):  # every attempt claims a different fake source IP inside the username
        r = client.post("/api/v1/events", json=ssh_line(i, f"a from 10.1.1.{i} port 1 b")).json()
    assert [a["rule_id"] for a in r["alerts"]] == ["SX-001"]
    (inc,) = client.get("/api/v1/incidents").json()
    assert client.get(f"/api/v1/incidents/{inc['id']}").json()["entities"]["ip"] == [IP]  # no fake address reaches an incident


def test_long_process_path_is_stored_and_detected(client):
    for n, length in enumerate((612, 5000)):  # over the old 512-char column, and far over it
        path = "C:\\" + "a\\" * (length // 2) + "net.exe"
        ev = {"k": "p", "img": path, "par": "cmd.exe", "cmd": "net user bob Pw /add", "dt": n}
        r = client.post("/api/v1/events", json=payload(ev, n, f"h{n}"))
        assert r.status_code == 200, r.text[:200]
        assert [a["rule_id"] for a in r.json()["alerts"]] == ["SX-003"]
    with get_factory()() as db:
        assert db.scalar(select(func.max(func.length(SecurityEvent.process_name)))) > 5000


def test_long_username_is_truncated_not_dropped(client):
    r = client.post("/api/v1/events", json=ssh_line(1, "u" * 400))
    assert r.status_code == 200, r.text[:200]
    with get_factory()() as db:
        assert db.scalar(select(func.length(SecurityEvent.user))) == 255


def test_failures_then_success_with_a_long_username_still_alerts(client):
    for i in range(5):
        client.post("/api/v1/events", json=ssh_line(i, "root"))
    r = client.post("/api/v1/events", json=ssh_line(10, "v" * 400, what="Accepted password for"))
    assert r.status_code == 200, r.text[:200]
    assert "SX-008" in [a["rule_id"] for a in r.json()["alerts"]]


def test_oversized_hostname_is_rejected_loudly(client):
    ev = {"k": "p", "img": "net.exe", "par": "cmd.exe", "cmd": "net user bob Pw /add"}
    r = client.post("/api/v1/events", json=payload(ev, 0, "h" * 300))
    assert r.status_code == 422 and "host" in r.text


def test_database_data_error_becomes_422_not_500(client, monkeypatch):
    from sqlalchemy.exc import DataError

    def boom(*a, **k):
        raise DataError("INSERT", {}, Exception("value too long"))

    monkeypatch.setattr("app.ingestion.service.run_detections", boom)
    r = client.post("/api/v1/events", json=ssh_line(1, "root"))
    assert r.status_code == 422 and json.loads(r.text)["detail"]
