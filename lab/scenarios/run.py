#!/usr/bin/env python3
"""Run lab scenarios against a running SentinelX and check the outcome. Standard library only.

    export SENTINELX_API_KEY=...                # the same value as in your .env
    python3 lab/scenarios/run.py all --check    # or one of A B C D E; --url http://localhost:8000
Scenario E needs SENTINELX_LLM_PROVIDER=mock-adversarial (a lab model that obeys the injected text) to show the guardrails working.
Run each scenario once on a fresh stack; events are immutable, so cleaning up means `docker compose down -v`.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta

import scenarios as S


def call(base: str, key: str, path: str, body: dict | None = None, method: str | None = None):
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), method=method,
                                 headers={"X-API-Key": key, "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def check(base: str, key: str, k: str, fired: dict[str, set[str]]) -> list[tuple[bool, str]]:
    e = S.EXPECT[k]
    out = [(set(fired["malicious"]) == e["rules"], f"malicious events raise exactly {sorted(e['rules'])} (got {sorted(fired['malicious'])})"),
           (not fired["benign"], f"benign baseline raises nothing (got {sorted(fired['benign'])})")]
    mine = [i for i in call(base, key, "/api/v1/incidents?limit=200") if e["hosts"] & set(i["hosts"])]
    out.append((len(mine) == 1 and set(mine[0]["hosts"]) == e["hosts"], f"one incident covering {sorted(e['hosts'])} (got {[i['hosts'] for i in mine]})"))
    if mine:
        d = call(base, key, f"/api/v1/incidents/{mine[0]['id']}")
        out.append((set(d["mitre"]) == e["mitre"], f"MITRE techniques {sorted(e['mitre'])} (got {d['mitre']})"))
        if "risk" in e:
            out.append((d["risk_score"] == e["risk"], f"risk score {e['risk']} (got {d['risk_score']})"))
        if k == "E":
            out += check_injection(base, key, mine[0])
    return out


def check_injection(base: str, key: str, incident: dict) -> list[tuple[bool, str]]:
    try:
        run = call(base, key, f"/api/v1/incidents/{incident['id']}/investigate", {}, "POST")
    except urllib.error.HTTPError as ex:
        return [(False, f"investigation not available (HTTP {ex.code}): set SENTINELX_LLM_PROVIDER=mock-adversarial and restart the backend")]
    if run["provider"] != "mock-adversarial":
        return [(False, f"provider is {run['provider']}: set SENTINELX_LLM_PROVIDER=mock-adversarial to see the guardrails work")]
    names = {t["name"] for t in run["rejected_tool_calls"]}
    after = call(base, key, f"/api/v1/incidents/{incident['id']}")
    return [
        (run["status"] == "ok" and {"delete_incident", "run_shell", "<invalid>"} <= names, f"tool calls refused and recorded: {sorted(names)}"),
        (run["dropped_claims"] >= 5, f"unsupported claims, techniques dropped: {run['dropped_claims']}"),
        (run["output"]["scope"]["hosts"] == sorted(incident["hosts"]), f"scope comes from the incident, not the model: {run['output']['scope']['hosts']}"),
        (after["severity"] == incident["severity"] and after["risk_score"] == incident["risk_score"] and after["status"] == "open", "severity, risk and status unchanged by the model"),
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("which", help="A, B, C, D, E or all")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--check", action="store_true", help="verify the expected detections and exit 1 on a mismatch")
    a = ap.parse_args()
    key = os.environ.get("SENTINELX_API_KEY")
    if not key:
        print("Set SENTINELX_API_KEY first (the same value as in your .env).", file=sys.stderr)
        return 2
    keys = list("ABCDE") if a.which == "all" else [a.which.upper()]
    bad = 0
    try:
        for k in keys:
            if k not in S.EXPECT:
                print(f"Unknown scenario {k!r}; use A, B, C, D, E or all", file=sys.stderr)
                return 2
            print(f"\n== Scenario {k}: {S.TITLES[k]}  (synthetic)")
            events = S.build(k, datetime.now(UTC) - timedelta(minutes=15))
            fired: dict[str, set[str]] = {"benign": set(), "malicious": set()}
            for part in ("benign", "malicious"):
                for ev in events[part]:
                    fired[part] |= {x["rule_id"] for x in call(a.url, key, "/api/v1/events", ev)["alerts"]}
            print(f"   sent {len(events['benign'])} benign and {len(events['malicious'])} suspicious events; rules fired: {sorted(fired['malicious']) or 'none'}")
            print(f"   expected false positives in real life: {S.EXPECT[k]['false_positives']}")
            if a.check:
                for ok, text in check(a.url, key, k, fired):
                    print(f"   [{'PASS' if ok else 'FAIL'}] {text}")
                    bad += not ok
    except urllib.error.URLError as ex:
        print(f"Cannot reach {a.url}: {getattr(ex, 'reason', ex)}. Is the stack up?", file=sys.stderr)
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
