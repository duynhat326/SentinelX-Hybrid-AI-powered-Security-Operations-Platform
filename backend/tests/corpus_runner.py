"""Turns the labeled corpus in tests/corpus/*.json into API payloads and runs it through the app."""
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

CORPUS = Path(__file__).parent / "corpus"
BASE = datetime(2026, 11, 15, 10, 0, 0, tzinfo=UTC)
SYS32 = "C:\\Windows\\System32\\"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"
OFFICE_EXES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe"}


def load_cases() -> list[dict]:
    return [c for f in sorted(CORPUS.glob("*.json")) for c in json.loads(f.read_text())["cases"]]


def _path(img: str) -> str:
    if "\\" in img:
        return img
    return (OFFICE if img.lower() in OFFICE_EXES else SYS32) + img


def payload(ev: dict, i: int, host: str) -> dict:
    ts = BASE + timedelta(seconds=ev.get("dt", i))
    k = ev["k"]
    if k in ("f", "s"):
        what = "Failed password for invalid user" if k == "f" else "Accepted password for"
        line = f"{ts:%Y-%m-%dT%H:%M:%S}+00:00 {host} sshd[1]: {what} {ev['u']} from {ev['ip']} port {40000 + i} ssh2"
        return {"source": "linux_auth", "payload": line}
    rec = {"UtcTime": f"{ts:%Y-%m-%d %H:%M:%S}.000", "Computer": host, "User": ev.get("user", "LAB\\alice"), "Image": _path(ev["img"])}
    if k == "p":
        rec |= {"EventID": 1, "ParentImage": _path(ev["par"]), "CommandLine": ev["cmd"]}
    elif k == "n":
        rec |= {"EventID": 3, "Protocol": "tcp", "SourceIp": "10.0.0.5", "SourcePort": str(49000 + i),
                "DestinationIp": ev["dst"], "DestinationPort": str(ev["port"])}
    elif k == "r":
        rec |= {"EventID": 13, "EventType": "SetValue", "TargetObject": ev["key"], "Details": ev["val"]}
    elif k == "fc":
        rec |= {"EventID": 11, "TargetFilename": ev["path"]}
    elif k == "r12":
        rec |= {"EventID": 12, "EventType": ev["type"], "TargetObject": ev["key"]}
    else:
        raise ValueError(f"unknown event kind {k!r}")
    return {"source": "sysmon", "payload": json.dumps(rec)}


def run_case(client, case: dict, host: str | None = None) -> set[str]:
    """Send every event of a case on a host of its own and return the rule ids that fired."""
    host = host or case["id"].lower()
    fired: set[str] = set()
    for i, ev in enumerate(case["events"]):
        r = client.post("/api/v1/events", json=payload(ev, i, host))
        assert r.status_code == 200, (case["id"], r.text)
        fired |= {a["rule_id"] for a in r.json()["alerts"]}
    return fired


def confusion(results: list[tuple[dict, bool]]) -> dict[str, Counter]:
    """results: (case, fired). Truth is the label; known-gap cases still count as FN."""
    out: dict[str, Counter] = {}
    for case, fired in results:
        mal = case["label"] == "malicious"
        out.setdefault(case["rule"], Counter())["TP" if mal and fired else "FN" if mal else "FP" if fired else "TN"] += 1
    return out
