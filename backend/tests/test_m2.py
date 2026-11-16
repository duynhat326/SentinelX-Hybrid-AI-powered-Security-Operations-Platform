import json
from pathlib import Path

import pytest

from app.database.models import Asset, DetectionRule, SecurityEvent
from app.database.session import get_factory
from tests.conftest import ssh_fail

FIX = Path(__file__).parent / "fixtures"


def post(client, source: str, name: str):
    return client.post("/api/v1/events", json={"source": source, "payload": (FIX / name).read_text()})


def only_event():
    with get_factory()() as db:
        return db.query(SecurityEvent).one()


def test_sysmon_network_event(client):
    assert post(client, "sysmon", "sysmon_3_network.json").status_code == 200
    e = only_event()
    assert (e.category, e.action, e.src_ip, e.src_port, e.dst_ip, e.dst_port) == ("network", "connect", "10.0.0.5", 49822, "198.51.100.7", 443)


def test_sysmon_registry_events(client):
    assert post(client, "sysmon", "sysmon_12_createkey.json").status_code == 200
    assert post(client, "sysmon", "sysmon_13_setvalue_run.json").status_code == 200
    with get_factory()() as db:
        rows = {e.action: e for e in db.query(SecurityEvent)}
    assert rows["create_key"].registry_value is None
    assert rows["set_value"].registry_key.endswith("CurrentVersion\\Run\\SentinelXTest")
    assert rows["set_value"].registry_value == "C:\\Windows\\System32\\notepad.exe"


@pytest.mark.parametrize("patch", [{"EventID": 99}, {"DestinationPort": "70000"}, {"DestinationIp": "not-an-ip"}, {"UtcTime": "garbage"}])
def test_sysmon_bad_records_rejected(client, patch):
    rec = json.loads((FIX / "sysmon_3_network.json").read_text()) | patch
    assert client.post("/api/v1/events", json={"source": "sysmon", "payload": json.dumps(rec)}).status_code == 422


def test_wazuh_sshd_alert_is_normalized_like_native_and_feeds_rules(client):
    for n in range(5):  # five distinct events through the Wazuh transport -> SX-001 fires
        rec = json.loads((FIX / "wazuh_sshd_failed.json").read_text())
        rec["full_log"] = rec["full_log"].replace("40221", str(40221 + n)).replace("10:00:01", f"10:00:0{n + 1}")
        r = client.post("/api/v1/events", json={"source": "wazuh", "payload": json.dumps(rec)}).json()
    assert [a["rule_id"] for a in r["alerts"]] == ["SX-001"]
    with get_factory()() as db:
        e = db.query(SecurityEvent).first()
        assert e.source == "linux_auth" and e.raw["via"] == "wazuh" and e.raw["wazuh_rule_id"] == "5710"


def test_wazuh_sysmon_powershell_triggers_sx002(client):
    r = post(client, "wazuh", "wazuh_sysmon_1_powershell.json").json()
    assert [a["rule_id"] for a in r["alerts"]] == ["SX-002"]
    assert only_event().source == "sysmon"


@pytest.mark.parametrize("mutate", [
    lambda a: a["data"]["win"]["system"].update(providerName="Microsoft-Windows-Security-Auditing"),
    lambda a: a.pop("data"),
])
def test_wazuh_unsupported_shapes_rejected(client, mutate):
    rec = json.loads((FIX / "wazuh_sysmon_1_powershell.json").read_text())
    mutate(rec)
    assert client.post("/api/v1/events", json={"source": "wazuh", "payload": json.dumps(rec)}).status_code == 422


def test_wazuh_duplicate_and_key_order_independent(client):
    rec = json.loads((FIX / "wazuh_sshd_failed.json").read_text())
    a = {"source": "wazuh", "payload": json.dumps(rec)}
    b = {"source": "wazuh", "payload": json.dumps(dict(reversed(list(rec.items()))))}
    assert client.post("/api/v1/events", json=a).json()["duplicate"] is False
    assert client.post("/api/v1/events", json=b).json()["duplicate"] is True


def test_asset_created_once_per_host(client):
    client.post("/api/v1/events", json=ssh_fail(1))
    client.post("/api/v1/events", json=ssh_fail(2))
    with get_factory()() as db:
        assets = db.query(Asset).all()
        assert [a.hostname for a in assets] == ["web01"] and assets[0].criticality == 3
        assert {e.asset_id for e in db.query(SecurityEvent)} == {assets[0].id}


def test_rules_listed_and_disabling_stops_alerts(client):
    rules = {r["id"]: r for r in client.get("/api/v1/rules").json()}
    assert set(rules) == {f"SX-00{i}" for i in range(1, 10)} and rules["SX-001"]["enabled"] and rules["SX-001"]["mitre"] == ["T1110"]
    with get_factory()() as db:
        db.get(DetectionRule, "SX-001").enabled = False
        db.commit()
    for n in range(1, 7):
        assert client.post("/api/v1/events", json=ssh_fail(n)).json()["alerts"] == []
    assert client.get("/api/v1/rules").json()[0]["enabled"] is False
    assert client.get("/api/v1/rules", headers={"X-API-Key": "bad"}).status_code == 401
