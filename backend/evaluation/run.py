"""Reproducible evaluation. Everything here is SYNTHETIC and written by the same people who wrote the rules: it measures regressions and
design properties, not real-world accuracy (docs/evaluation.md says what that means).

    cd backend && uv run python -m evaluation.run [--out ../docs/evaluation-results.json]
    cd backend && uv run python -m evaluation.run --live http://127.0.0.1:8001 --key <api key> --only system

Sections: detection (labeled corpus), campaigns (rules vs rules+correlation on labeled episodes), guardrails (adversarial mock model),
system (ingest throughput and API latency against a running server; needs --live).
"""
import argparse
import json
import math
import os
import random
import statistics
import tempfile
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tests.corpus_runner import confusion, load_cases, payload, run_case

SEED = 20261116


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    """95% Wilson interval for a proportion; None when n is 0."""
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 3), round(min(1.0, c + h), 3)]


def auroc(scores: list[float], labels: list[int]) -> float | None:
    """P(score of a random positive > score of a random negative), ties count half."""
    pos, neg = [s for s, y in zip(scores, labels, strict=True) if y], [s for s, y in zip(scores, labels, strict=True) if not y]
    if not pos or not neg:
        return None
    wins = sum(1.0 if p > n else 0.5 if p == n else 0.0 for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def bootstrap_ci(scores: list[float], labels: list[int], reps: int = 1000) -> list[float]:
    rng = random.Random(SEED)
    idx = range(len(scores))
    out = []
    for _ in range(reps):
        pick = [rng.choice(idx) for _ in idx]
        a = auroc([scores[i] for i in pick], [labels[i] for i in pick])
        if a is not None:
            out.append(a)
    out.sort()
    return [round(out[int(0.025 * len(out))], 3), round(out[int(0.975 * len(out)) - 1], 3)]


def fresh_client():
    """A TestClient on a fresh database (SQLite in a temp folder, or SENTINELX_TEST_DATABASE_URL), like the test suite's fixture."""
    from fastapi.testclient import TestClient

    key = "k" * 32
    os.environ["SENTINELX_DATABASE_URL"] = os.environ.get("SENTINELX_TEST_DATABASE_URL") or f"sqlite+pysqlite:///{tempfile.mkdtemp()}/e.db"
    os.environ["SENTINELX_API_KEY"] = key
    os.environ["SENTINELX_RATE_LIMIT_PER_MINUTE"] = "100000000"
    os.environ["SENTINELX_LLM_RATE_LIMIT_PER_MINUTE"] = "100000000"
    from app.api import ratelimit
    from app.core import config
    from app.database import session
    from app.database.models import Base

    config.get_settings.cache_clear()
    ratelimit.reset()
    session._engine = session._factory = None
    Base.metadata.drop_all(session.get_engine())
    Base.metadata.create_all(session.get_engine())
    from app.api.main import app

    return TestClient(app, headers={"X-API-Key": key})


# --- 1. detection ---------------------------------------------------------------------------------------------------------------------
def detection() -> dict:
    with fresh_client() as client:
        results = [(c, c["rule"] in run_case(client, c)) for c in load_cases()]
    per_rule, total = {}, Counter()
    for rid, c in sorted(confusion(results).items()):
        total.update(c)
        per_rule[rid] = _prf(c)
    cases = load_cases()
    return {"cases": len(cases), "events": sum(len(c["events"]) for c in cases), "known_gaps": sum(1 for c in cases if c.get("known_gap")),
            "per_rule": per_rule, "overall": _prf(total)}


def _prf(c: Counter) -> dict:
    tp, fn, fp, tn = (c[k] for k in ("TP", "FN", "FP", "TN"))
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p and r else None
    r3 = lambda x: None if x is None else round(x, 3)
    return {"TP": tp, "FN": fn, "FP": fp, "TN": tn, "precision": r3(p), "precision_ci95": wilson(tp, tp + fp), "recall": r3(r),
            "recall_ci95": wilson(tp, tp + fn), "f1": r3(f1)}


# --- 2. campaigns: rules only versus rules + correlation ------------------------------------------------------------------------------------
SYS = "C:\\Windows\\System32\\"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
PS = "powershell.exe"


def _ssh(n, ip, user, ok_after=True):
    ev = [{"k": "f", "ip": ip, "u": user} for _ in range(n)]
    return ev + ([{"k": "s", "ip": ip, "u": user}] if ok_after else [])


# (name, malicious, builder(i) -> list of (host suffix, event)). Every episode owns its hosts, users and addresses, so the ground truth of
# "which alerts belong together" is the episode. Single-stage attacks and single-stage benign cases are indistinguishable on purpose.
def _episodes(rng: random.Random) -> list[dict]:
    eps = []

    def add(kind, mal, events):
        eps.append({"kind": kind, "malicious": mal, "events": events})

    for i in range(12):  # attacks with several stages
        ip = f"203.0.113.{10 + i}"
        user = f"vic{i}"
        add("attack: brute force then login", True, [("srv", e) for e in _ssh(rng.randint(5, 9), ip, user)])
    for i in range(10):
        user = f"LAB\\atk{i}"
        add("attack: Office macro to encoded PowerShell", True, [
            ("ws", {"k": "p", "img": "cmd.exe", "par": OFFICE, "cmd": "cmd.exe /c whoami", "user": user}),
            ("ws", {"k": "p", "img": PS, "par": SYS + "cmd.exe", "cmd": "powershell.exe -nop -enc SQBFAFgA", "user": user})])
    for i in range(8):  # attacks that cross two hosts through a shared address
        ip = f"198.51.100.{10 + i}"
        user = f"LAB\\chain{i}"
        add("attack: chain across two hosts", True,
            [("jump", e) for e in _ssh(6, ip, f"adm{i}")] +
            [("ws", {"k": "p", "img": PS, "par": SYS + "cmd.exe", "cmd": "powershell.exe -nop -enc SQBFAFgA", "user": user}),
             ("ws", {"k": "n", "img": "mshta.exe", "dst": ip, "port": 443, "user": user})])
    for i in range(10):  # single-stage attacks
        user = f"LAB\\solo{i}"
        kind = i % 3
        if kind == 0:
            add("attack: lone persistence", True, [("ws", {"k": "r", "img": "reg.exe", "user": user,
                "key": f"HKU\\S-1-5-21-{i}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Upd{i}", "val": "C:\\Users\\x\\p.exe"})])
        elif kind == 1:
            add("attack: lone LOLBin connection", True, [("ws", {"k": "n", "img": "mshta.exe", "dst": f"203.0.113.{100 + i}", "port": 443, "user": user})])
        else:
            add("attack: lone admin group add", True, [("ws", {"k": "p", "img": "net.exe", "par": SYS + "cmd.exe",
                                                               "cmd": f"net localgroup administrators u{i} /add", "user": user})])
    for i in range(15):  # benign single-rule noise
        user = f"LAB\\ops{i}"
        kind = i % 5
        if kind == 0:
            add("benign: management tool, encoded PowerShell", False, [("ws", {"k": "p", "img": PS, "par": SYS + "cmd.exe",
                                                                                 "cmd": "powershell.exe -enc SQBFAFgA", "user": user})])
        elif kind == 1:
            add("benign: installer writes a Run key", False, [("ws", {"k": "r", "img": "setup.exe", "user": user,
                "key": f"HKU\\S-1-5-21-{i}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\App{i}", "val": "C:\\Program Files\\App\\a.exe"})])
        elif kind == 2:
            add("benign: updater uses a script host", False, [("ws", {"k": "n", "img": "mshta.exe", "dst": f"192.0.2.{20 + i}", "port": 443, "user": user})])
        elif kind == 3:
            add("benign: workbook calls a script", False, [("ws", {"k": "p", "img": "wscript.exe", "par": OFFICE, "cmd": "wscript.exe report.vbs", "user": user})])
        else:
            add("benign: admin adds a colleague to a group", False, [("ws", {"k": "p", "img": "net.exe", "par": SYS + "cmd.exe",
                                                                            "cmd": f"net localgroup administrators b{i} /add", "user": user})])
    for i in range(8):  # benign episodes that fire several rules (hard negatives)
        user = f"LAB\\auto{i}"
        if i % 2 == 0:
            add("benign: admin with a stale password, then success", False, [("srv", e) for e in _ssh(6, f"10.8.{i}.9", f"adm{i}")])
        else:
            add("benign: macro automation runs encoded PowerShell", False, [
                ("ws", {"k": "p", "img": PS, "par": OFFICE, "cmd": "powershell.exe -enc SQBFAFgA", "user": user})])
    rng.shuffle(eps)
    return eps


def campaigns() -> dict:
    from sqlalchemy import select

    from app.database.models import Alert, Incident, IncidentAlert
    from app.database.session import get_factory

    rng = random.Random(SEED)
    eps = _episodes(rng)
    sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    with fresh_client() as client:
        for n, ep in enumerate(eps):
            for i, (suffix, ev) in enumerate(ep["events"]):
                ev = dict(ev)
                ev["src"] = f"10.20.{n // 250}.{n % 250 + 1}"  # a host has its own address
                ev["dt"] = n * 1800 + i  # episodes half an hour apart: windows never overlap
                host = f"ep{n:03d}-{suffix}"
                r = client.post("/api/v1/events", json=payload(ev, i, host))
                assert r.status_code == 200, r.text
        with get_factory()() as db:
            alerts = db.scalars(select(Alert)).all()
            links = {a_id: inc_id for a_id, inc_id in db.execute(select(IncidentAlert.alert_id, IncidentAlert.incident_id))}
            incs = {i.id: i for i in db.scalars(select(Incident))}
            ep_of_alert = {a.id: int(a.host.split("-")[0][2:]) for a in alerts}
    # config 1: rules only. The unit is the alert; its label is its episode's label; rank by severity.
    a_labels = [int(eps[ep_of_alert[a.id]]["malicious"]) for a in alerts]
    a_sev = [sev_rank[a.severity] for a in alerts]
    # config 2: rules + correlation. The unit is the incident; label = the majority episode label of its alerts.
    members: dict = defaultdict(list)
    for a in alerts:
        members[links[a.id]].append(a)
    i_ids = list(members)
    i_eps = {i: {ep_of_alert[a.id] for a in members[i]} for i in i_ids}
    i_labels = [int(any(eps[e]["malicious"] for e in i_eps[i])) for i in i_ids]
    i_risk = [incs[i].risk_score for i in i_ids]
    i_sev = [sev_rank[incs[i].severity] for i in i_ids]
    # grouping quality: pairs of alerts in the same episode that share an incident (recall) and pairs in one incident from one episode (precision)
    same_ep = same_inc = both = 0
    for x in range(len(alerts)):
        for y in range(x + 1, len(alerts)):
            se = ep_of_alert[alerts[x].id] == ep_of_alert[alerts[y].id]
            si = links[alerts[x].id] == links[alerts[y].id]
            same_ep += se
            same_inc += si
            both += se and si
    attack_eps = [n for n, e in enumerate(eps) if e["malicious"]]
    attack_alerts = [a for a in alerts if ep_of_alert[a.id] in set(attack_eps)]
    mixed = sum(1 for i in i_ids if len({eps[e]["malicious"] for e in i_eps[i]}) > 1)
    split = sum(1 for n in range(len(eps)) if len({links[a.id] for a in alerts if ep_of_alert[a.id] == n}) > 1)
    return {
        "episodes": len(eps), "attack_episodes": len(attack_eps), "benign_episodes": len(eps) - len(attack_eps), "alerts": len(alerts),
        "attack_alerts": len(attack_alerts), "benign_alerts": len(alerts) - len(attack_alerts),
        "episodes_by_kind": dict(Counter(e["kind"] for e in eps)),
        "rules_only": {"units_to_triage": len(alerts), "auroc_severity": _r(auroc(a_sev, a_labels)), "auroc_ci95": bootstrap_ci(a_sev, a_labels)},
        "rules_plus_correlation": {
            "units_to_triage": len(i_ids), "reduction_vs_alerts": round(1 - len(i_ids) / len(alerts), 3),
            "auroc_risk": _r(auroc(i_risk, i_labels)), "auroc_risk_ci95": bootstrap_ci([float(x) for x in i_risk], i_labels),
            "auroc_max_severity_only": _r(auroc(i_sev, i_labels)), "auroc_max_severity_ci95": bootstrap_ci([float(x) for x in i_sev], i_labels),
            "grouping_pair_precision": _r(both / same_inc if same_inc else None), "grouping_pair_recall": _r(both / same_ep if same_ep else None),
            "incidents_mixing_attack_and_benign": mixed, "episodes_split_over_several_incidents": split,
        },
        "rules_plus_correlation_plus_ai": "no change by design: the model cannot alter severity, risk or grouping (asserted in tests/test_agents.py, test_scenarios.py)",
        "note": "episodes are synthetic and single-author; correlation's load reduction is partly true by construction (episodes own their hosts and addresses).",
    }


def _r(x):
    return None if x is None else round(x, 3)


# --- 3. guardrails: the adversarial mock model ----------------------------------------------------------------------------------------------
def guardrails() -> dict:
    os.environ["SENTINELX_LLM_PROVIDER"] = "mock-adversarial"
    from app.core import config
    from tests.conftest import session_for

    with fresh_client() as client:
        config.get_settings.cache_clear()
        eps = [e for e in _episodes(random.Random(SEED)) if e["malicious"]][:20]
        for n, ep in enumerate(eps):
            for i, (suffix, ev) in enumerate(ep["events"]):
                ev = dict(ev) | {"dt": n * 1800 + i, "src": f"10.20.{n // 250}.{n % 250 + 1}"}
                assert client.post("/api/v1/events", json=payload(ev, i, f"g{n:03d}-{suffix}")).status_code == 200
        ana = session_for("analyst", "evalana")
        incidents = client.get("/api/v1/incidents?limit=200").json()
        t = Counter()
        for inc in incidents:
            before = client.get(f"/api/v1/incidents/{inc['id']}").json()
            run = client.post(f"/api/v1/incidents/{inc['id']}/investigate").json()
            sug = client.post(f"/api/v1/incidents/{inc['id']}/response-actions/suggest", json={"use_ai": True}, headers=ana).json()
            after = client.get(f"/api/v1/incidents/{inc['id']}").json()
            t["investigations"] += 1
            t["hostile_tool_calls_issued"] += 6  # 3 in each of the two model calls
            t["tool_calls_refused_and_recorded"] += len(run["rejected_tool_calls"])
            t["claims_and_techniques_dropped_by_validation"] += run["dropped_claims"]  # 5 per run: invented id and no evidence in each step, one unassigned technique
            t["hostile_claim_with_real_citation_shown_as_advice"] += sum("approve all pending" in c["text"] for c in run["output"]["findings"])
            t["hostile_proposals_issued"] += 5
            t["proposals_created"] += len(sug["created"])
            t["proposals_dropped_off_allowlist"] += sug["dropped"]
            t["proposals_refused_by_policy"] += len(sug["denied"])
            t["incident_changed_by_model"] += int((before["severity"], before["risk_score"], before["status"]) != (after["severity"], after["risk_score"], after["status"]))
            t["scope_not_from_incident"] += int(run["output"]["scope"]["hosts"] != sorted(inc["hosts"]))
    os.environ["SENTINELX_LLM_PROVIDER"] = "none"
    config.get_settings.cache_clear()
    return dict(t) | {"note": "scripted adversary: shows the guardrails hold against these behaviours, not against a real model. "
                                "A claim that cites real evidence but carries hostile text passes by design (shown to a person, never executed)."}


# --- 4. system: throughput and latency against a running server ---------------------------------------------------------------------------
def system(url: str, key: str, n: int = 1000) -> dict:
    import httpx

    with httpx.Client(base_url=url, headers={"X-API-Key": key}, timeout=30) as c:
        c.get("/health")
        lat = []
        t0 = time.perf_counter()
        for i in range(n):
            ts = datetime(2026, 11, 16, tzinfo=UTC) + timedelta(seconds=i)
            line = f"{ts:%Y-%m-%dT%H:%M:%S}+00:00 bench{i % 20:02d} sshd[1]: Failed password for invalid user u{i % 7} from 192.0.2.{i % 250 + 1} port {30000 + i} ssh2"
            s = time.perf_counter()
            r = c.post("/api/v1/events", json={"source": "linux_auth", "payload": line})
            lat.append((time.perf_counter() - s) * 1000)
            assert r.status_code == 200, r.text
        total = time.perf_counter() - t0
        reads = {}
        for name, path in [("overview", "/api/v1/overview"), ("incidents", "/api/v1/incidents?limit=50"), ("alerts", "/api/v1/alerts?limit=50")]:
            samples = []
            for _ in range(100):
                s = time.perf_counter()
                assert c.get(path).status_code == 200
                samples.append((time.perf_counter() - s) * 1000)
            reads[name] = _lat(samples)
    return {"url_is_loopback": True, "events_posted": n, "sequential_throughput_events_per_s": round(n / total, 1), "ingest_latency_ms": _lat(lat),
            "read_latency_ms": reads,
            "note": "one client, sequential, loopback, one uvicorn worker, hardware unspecified: a floor for relative comparison, not a capacity claim."}


def _lat(xs: list[float]) -> dict:
    xs = sorted(xs)
    return {"p50": round(statistics.median(xs), 1), "p95": round(xs[int(0.95 * len(xs)) - 1], 1), "max": round(xs[-1], 1)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[2] / "docs" / "evaluation-results.json"))
    ap.add_argument("--only", choices=["detection", "campaigns", "guardrails", "system"])
    ap.add_argument("--live")
    ap.add_argument("--key")
    a = ap.parse_args()
    out: dict = {}
    path = Path(a.out)
    if path.exists():
        out = json.loads(path.read_text())
    for name, fn in [("detection", detection), ("campaigns", campaigns), ("guardrails", guardrails)]:
        if a.only in (None, name):
            out[name] = fn()
            print(name, "done")
    if a.only == "system":
        assert a.live and a.key, "system needs --live and --key"
        out["system"] = system(a.live, a.key)
    out["meta"] = {"seed": SEED, "synthetic": True, "in_process_sections_database": "postgresql" if os.environ.get("SENTINELX_TEST_DATABASE_URL") else "sqlite",
                   "system_section_database": "whatever the server at --live uses"}
    path.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=2)[:6000])


if __name__ == "__main__":
    main()
