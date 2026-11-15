from datetime import datetime

IP = "203.0.113.50"


def fail(client, ts: str, n: int):
    line = f"{ts}+00:00 web01 sshd[1]: Failed password for root from {IP} port {40000 + n} ssh2"
    return client.post("/api/v1/events", json={"source": "linux_auth", "payload": line}).json()


def test_bursts_far_apart_become_separate_alerts(client):
    for n in range(1, 6):
        fail(client, f"2026-11-15T10:00:0{n}", n)
    for n in range(1, 6):
        fail(client, f"2026-11-15T10:30:0{n}", 10 + n)
    alerts = client.get("/api/v1/alerts").json()
    assert sorted(a["event_count"] for a in alerts) == [5, 5]
    starts = sorted(datetime.fromisoformat(a["first_event_at"]) for a in alerts)
    assert (starts[1] - starts[0]).total_seconds() == 30 * 60
    for a in alerts:
        assert (datetime.fromisoformat(a["last_event_at"]) - datetime.fromisoformat(a["first_event_at"])).total_seconds() == 4


def test_later_event_inside_window_extends_the_same_alert(client):
    for n in range(1, 6):
        fail(client, f"2026-11-15T10:00:0{n}", n)
    fail(client, "2026-11-15T10:03:00", 9)  # 175 s after the burst, inside the 300 s window
    (a,) = client.get("/api/v1/alerts").json()
    assert a["event_count"] == 6 and a["last_event_at"].startswith("2026-11-15T10:03:00")
