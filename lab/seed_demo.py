#!/usr/bin/env python3
"""Seed SentinelX with a small set of SYNTHETIC events so every page of the dashboard has something to show.

Nothing here is real telemetry and nothing executes anything: the events are text records. Hosts, users and addresses are
fictional or in the RFC 5737 documentation ranges. It uses only the Python standard library.

    export SENTINELX_API_KEY=...        # the same value as in your .env
    python3 lab/seed_demo.py            # optional: --url http://localhost:8000

Run it once on a fresh stack. Timestamps are relative to "now", so a second run adds a second set of events.
Scenarios (each fires the rules named in brackets):
  A  SSH brute force from one address against two Linux hosts, then a login that works   [SX-001 x2, SX-008] -> one incident
  B  a Word document starting cmd and an encoded PowerShell command on one workstation   [SX-007, SX-002]
  C  a new local administrator, a Run-key and a script host calling out on another host   [SX-003, SX-004, SX-005, SX-006]
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta

ATTACKER = "203.0.113.50"  # documentation address
C2 = "198.51.100.7"  # documentation address
SYS32 = "C:\\Windows\\System32\\"
WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"


def build(start: datetime) -> list[dict]:
    t = iter(start + timedelta(seconds=i) for i in range(10_000))  # every event gets its own second
    out: list[dict] = []

    def ssh(host: str, ok: bool, user: str, port: int) -> None:
        what = "Accepted password for" if ok else "Failed password for invalid user"
        out.append({"source": "linux_auth", "payload": f"{next(t):%Y-%m-%dT%H:%M:%S}+00:00 {host} sshd[1201]: {what} {user} from {ATTACKER} port {port} ssh2"})

    def sysmon(host: str, user: str, image: str, **fields) -> None:
        out.append({"source": "sysmon", "payload": json.dumps({"UtcTime": f"{next(t):%Y-%m-%d %H:%M:%S}.000", "Computer": host, "User": user, "Image": image, **fields})})

    # A
    for i in range(7):
        ssh("web01", False, "admin", 40000 + i)
    for i in range(6):
        ssh("db01", False, "root", 41000 + i)
    ssh("web01", True, "deploy", 40100)
    # B
    sysmon("ws-fin-02", "LAB\\dave", SYS32 + "cmd.exe", EventID=1, ParentImage=WORD, CommandLine="cmd.exe /c whoami")
    sysmon("ws-fin-02", "LAB\\dave", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", EventID=1, ParentImage=SYS32 + "cmd.exe",
           CommandLine="powershell.exe -nop -enc SQBFAFgAIAAnAHQAZQBzAHQAJwA=")  # base64 of a harmless string
    # C
    cmd = SYS32 + "cmd.exe"
    sysmon("win10-lab", "LAB\\carol", SYS32 + "net.exe", EventID=1, ParentImage=cmd, CommandLine="net user svc-test Pw-lab-12345 /add")
    sysmon("win10-lab", "LAB\\carol", SYS32 + "net.exe", EventID=1, ParentImage=cmd, CommandLine="net localgroup administrators svc-test /add")
    sysmon("win10-lab", "LAB\\carol", SYS32 + "reg.exe", EventID=13, EventType="SetValue", Details="C:\\Windows\\System32\\notepad.exe",
           TargetObject="HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SentinelXTest")
    sysmon("win10-lab", "LAB\\carol", SYS32 + "mshta.exe", EventID=3, Protocol="tcp", SourceIp="10.0.0.5", SourcePort="49822", DestinationIp=C2, DestinationPort="80")
    return out


def post(base: str, key: str, body: dict) -> dict:
    req = urllib.request.Request(f"{base}/api/v1/events", data=json.dumps(body).encode(), headers={"X-API-Key": key, "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--url", default="http://localhost:8000")
    key = os.environ.get("SENTINELX_API_KEY")
    if not key:
        print("Set SENTINELX_API_KEY first (the same value as in your .env).", file=sys.stderr)
        return 2
    base = ap.parse_args().url.rstrip("/")
    events = build(datetime.now(UTC) - timedelta(minutes=20))
    alerts: dict[str, set[str]] = {}
    try:
        for ev in events:
            for a in post(base, key, ev)["alerts"]:
                alerts.setdefault(a["rule_id"], set()).add(a["id"])
    except urllib.error.HTTPError as e:
        print(f"The server refused an event: HTTP {e.code} {e.read()[:200].decode(errors='replace')}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"Cannot reach {base}: {e.reason}. Is the stack up?", file=sys.stderr)
        return 1
    print(f"Sent {len(events)} synthetic events. Alerts raised: " + (", ".join(f"{r} x{len(ids)}" for r, ids in sorted(alerts.items())) or "none"))
    print("Open http://localhost:8080 and sign in.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
