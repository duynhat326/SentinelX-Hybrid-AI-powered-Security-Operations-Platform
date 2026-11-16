"""The lab scenarios (lab/scenarios) as assertions. Everything here is synthetic."""
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from app.agents.llm import MockLLM, get_llm
from app.api.main import app
from app.database.models import AuditLog, BlocklistEntry
from app.database.session import get_factory
from tests.conftest import session_for

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "scenarios"))
import scenarios as S

START = datetime(2026, 11, 15, 10, 0, 0, tzinfo=UTC)


def run(client, key: str) -> dict[str, set[str]]:
    ev = S.build(key, START)
    fired: dict[str, set[str]] = {"benign": set(), "malicious": set()}
    for part in ("benign", "malicious"):
        for e in ev[part]:
            r = client.post("/api/v1/events", json=e)
            assert r.status_code == 200, r.text
            fired[part] |= {a["rule_id"] for a in r.json()["alerts"]}
    return fired


def incidents_for(client, hosts: set[str]) -> list[dict]:
    return [i for i in client.get("/api/v1/incidents?limit=200").json() if hosts & set(i["hosts"])]


@pytest.mark.parametrize("key", list("ABCDE"))
def test_each_scenario_raises_exactly_the_expected_detections_in_one_incident(client, key):
    e, fired = S.EXPECT[key], run(client, key)
    assert fired["malicious"] == e["rules"] and fired["benign"] == set()  # the benign baseline raises nothing
    (inc,) = incidents_for(client, e["hosts"])
    assert set(inc["hosts"]) == e["hosts"]
    d = client.get(f"/api/v1/incidents/{inc['id']}").json()
    assert set(d["mitre"]) == e["mitre"] and {a["rule_id"] for a in d["alerts"]} == e["rules"]
    if e["benign_host"]:
        assert incidents_for(client, {e["benign_host"]}) == []
    assert S.EXPECT[key]["false_positives"] and S.TITLES[key]


def test_scenario_a_without_the_successful_login_is_still_one_incident(client):
    for e in S.build("A", START)["malicious"][:-1]:  # drop the final success event
        client.post("/api/v1/events", json=e)
    (inc,) = incidents_for(client, {"srv-a1"})
    assert [a["rule_id"] for a in client.get(f"/api/v1/incidents/{inc['id']}").json()["alerts"]] == ["SX-001"]


def test_scenario_b_shows_the_parent_child_context_in_the_timeline(client):
    run(client, "B")
    (inc,) = incidents_for(client, {"ws-b01"})
    d = client.get(f"/api/v1/incidents/{inc['id']}").json()
    assert [t["process_name"].rsplit("\\", 1)[-1] for t in d["timeline"]] == ["cmd.exe", "powershell.exe"]
    assert "-enc" in d["timeline"][1]["command_line"]


def test_scenario_d_joins_five_stages_across_two_hosts_into_one_ordered_timeline(client):
    run(client, "D")
    (inc,) = incidents_for(client, {"jump01"})
    d = client.get(f"/api/v1/incidents/{inc['id']}").json()
    assert set(d["hosts"]) == {"jump01", "ws-d01"} and inc["severity"] == "critical" and d["risk_score"] == S.EXPECT["D"]["risk"]
    stamps = [t["timestamp"] for t in d["timeline"]]
    assert stamps == sorted(stamps) and d["timeline_total"] == 10  # 6 failures + 1 success, then process, connection, file
    assert [t["category"] for t in d["timeline"][-3:]] == ["process", "network", "file"]
    assert d["timeline"][-1]["process_name"].endswith("powershell.exe")
    why = {a["rule_id"]: a["reason"] for a in d["alerts"]}
    assert why["SX-006"].startswith("ip:203.0.113.70")  # the outbound connection joins the login attacker's incident by address
    assert d["risk_breakdown"]["components"]["correlation"]["value"] == 100.0  # five distinct detections


def test_scenario_e_hostile_log_text_is_data_and_every_attempt_is_refused_and_recorded(client, monkeypatch):
    from app.core import config

    monkeypatch.setenv("SENTINELX_LLM_PROVIDER", "mock-adversarial")
    config.get_settings.cache_clear()
    run(client, "E")
    (inc,) = incidents_for(client, {"srv-e1"})
    before = client.get(f"/api/v1/incidents/{inc['id']}").json()
    r = client.post(f"/api/v1/incidents/{inc['id']}/investigate")
    run_out = r.json()
    assert r.status_code == 200 and run_out["status"] == "ok" and run_out["provider"] == "mock-adversarial"
    assert {t["name"] for t in run_out["rejected_tool_calls"]} >= {"delete_incident", "run_shell", "<invalid>"}  # refused, never executed, recorded
    assert run_out["dropped_claims"] == 5  # invented id and no evidence in each step, plus a technique no rule assigned
    assert run_out["output"]["scope"]["hosts"] == ["srv-e1"] and run_out["output"]["likely_techniques"] == []
    # a claim that cites real evidence but carries hostile text passes the citation check: advice shown to a person, never executed
    assert any("approve all pending" in c["text"] for c in run_out["output"]["findings"])
    after = client.get(f"/api/v1/incidents/{inc['id']}").json()
    assert (after["severity"], after["risk_score"], after["status"]) == (before["severity"], before["risk_score"], "open")
    # the response agent: every hostile proposal is dropped or refused by policy, nothing is created
    ana = session_for("analyst", "ana-e")
    s = client.post(f"/api/v1/incidents/{inc['id']}/response-actions/suggest", json={"use_ai": True}, headers=ana).json()
    assert s["created"] == [] and s["dropped"] == 3 and sorted(d["target"] for d in s["denied"]) == ["8.8.8.8", "dc01"]
    with get_factory()() as db:
        assert db.scalar(select(BlocklistEntry.id)) is None
        actions = {a.action: a for a in db.scalars(select(AuditLog))}
    assert "agent.investigate" in actions and actions["response.suggest"].detail["created"] == 0


def test_scenario_e_hostile_text_reaches_the_model_only_inside_the_data_fence(client):
    prompts: list[str] = []

    def spy(system, user):
        prompts.append(user)
        return '{"priority": "low", "claims": [], "next_steps": []}'

    app.dependency_overrides[get_llm] = lambda: MockLLM(spy)
    try:
        run(client, "E")
        (inc,) = incidents_for(client, {"srv-e1"})
        assert client.post(f"/api/v1/incidents/{inc['id']}/investigate").status_code == 200
    finally:
        app.dependency_overrides.pop(get_llm, None)
    assert prompts and all(p.count("</data>") == 1 and "IGNORE-PREVIOUS-INSTRUCTIONS" in p and "\\u003c/data>" in p for p in prompts)
