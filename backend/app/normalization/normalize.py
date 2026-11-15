"""Raw record -> NormalizedEvent. Inputs are untrusted: every field is validated or dropped."""
import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

_SECRET = re.compile(r"(?i)(password|passwd|token|api[_-]?key|secret)(\s*[=:]\s*)\S+")
_SYSLOG = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:\d\d)|[A-Z][a-z]{2}\s+\d+\s[\d:]{8})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_OK = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")


class NormalizedEvent(BaseModel):
    timestamp: datetime
    source: str
    host: str
    category: str  # authentication | process | network | registry
    action: str
    user: str | None = None
    src_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    process_name: str | None = None
    parent_process_name: str | None = None
    command_line: str | None = None
    registry_key: str | None = None
    registry_value: str | None = None

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        return str(ipaddress.ip_address(v)) if v else v


class NormalizationError(ValueError):
    pass


def redact(text: str) -> str:
    return _SECRET.sub(r"\1\2[REDACTED]", text)


def dedup_hash(source: str, raw: str) -> str:
    return hashlib.sha256(f"{source}\0{raw}".encode()).hexdigest()


def _parse_syslog_ts(ts: str, now: datetime) -> datetime:
    if ts[0].isdigit():
        return datetime.fromisoformat(ts).astimezone(UTC)
    # shortcut: classic syslog has no year; assume current UTC year, roll back if that lands in the future.
    dt = datetime.strptime(f"{now.year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
    return dt.replace(year=now.year - 1) if dt > now else dt


def normalize_linux_auth(line: str, now: datetime | None = None) -> NormalizedEvent:
    now = now or datetime.now(UTC)
    m = _SYSLOG.match(line.strip())
    if not m:
        raise NormalizationError("unrecognized sshd syslog line")
    for pat, action in ((_FAIL, "failure"), (_OK, "success")):
        d = pat.search(m["msg"])
        if d:
            try:
                return NormalizedEvent(
                    timestamp=_parse_syslog_ts(m["ts"], now), source="linux_auth", host=m["host"],
                    category="authentication", action=action, user=d["user"], src_ip=d["ip"],
                )
            except ValueError as e:
                raise NormalizationError(str(e)) from e
    raise NormalizationError("sshd message is not a login success/failure")


def _opt(v: object) -> str | None:
    return None if v in (None, "", "-") else str(v)


def _int(v: object) -> int | None:
    o = _opt(v)
    return int(o) if o else None


def _sysmon_ts(v: object) -> datetime:
    s = str(v)
    if "T" in s:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=UTC)  # naive means UTC, never local time
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=UTC)


_REG_ACTIONS = {"CreateKey": "create_key", "DeleteKey": "delete_key", "SetValue": "set_value"}


def normalize_sysmon(rec: dict) -> NormalizedEvent:
    """Sysmon events 1 (process create), 3 (network connect), 12/13 (registry), as JSON."""
    try:
        eid = int(rec["EventID"])
        base: dict = {
            "timestamp": _sysmon_ts(rec["UtcTime"]), "source": "sysmon", "host": str(rec["Computer"]),
            "user": _opt(rec.get("User")), "process_name": _opt(rec.get("Image")),
        }
        if eid == 1:
            return NormalizedEvent(
                **base, category="process", action="create", parent_process_name=_opt(rec.get("ParentImage")),
                command_line=redact(_opt(rec.get("CommandLine")) or "") or None,
            )
        if eid == 3:
            return NormalizedEvent(
                **base, category="network", action="connect", src_ip=_opt(rec.get("SourceIp")),
                src_port=_int(rec.get("SourcePort")), dst_ip=_opt(rec.get("DestinationIp")),
                dst_port=_int(rec.get("DestinationPort")),
            )
        if eid in (12, 13):
            return NormalizedEvent(
                **base, category="registry", action=_REG_ACTIONS[str(rec["EventType"])],
                registry_key=redact(str(rec["TargetObject"])),
                registry_value=redact(_opt(rec.get("Details")) or "") or None if eid == 13 else None,
            )
    except (KeyError, ValueError, TypeError) as e:
        raise NormalizationError(f"invalid sysmon record: {e!r}") from e
    raise NormalizationError(f"unsupported Sysmon EventID {rec.get('EventID')!r} (supported: 1, 3, 12, 13)")


def normalize_wazuh(alert: dict, max_raw: int) -> tuple[NormalizedEvent, dict]:
    """A Wazuh alert is only a transport: the event is the wrapped Sysmon record or sshd log line,
    so the normalized `source` stays linux_auth / sysmon and the existing rules apply unchanged."""
    meta = {"via": "wazuh", "wazuh_rule_id": str((alert.get("rule") or {}).get("id"))}
    win = (alert.get("data") or {}).get("win")
    if isinstance(win, dict):
        system, ed = win.get("system") or {}, win.get("eventdata") or {}
        if system.get("providerName") != "Microsoft-Windows-Sysmon":
            raise NormalizationError("only Sysmon-provided Windows events are supported from Wazuh")
        rec = {k[:1].upper() + k[1:]: v for k, v in ed.items()}  # Wazuh lowercases the first letter
        rec["EventID"], rec["Computer"] = system.get("eventID"), system.get("computer")
        return normalize_sysmon(rec), {**meta, "record": {k: str(v)[:max_raw] for k, v in rec.items()}}
    line = alert.get("full_log")
    if isinstance(line, str):
        return normalize_linux_auth(line), {**meta, "line": line[:max_raw]}
    raise NormalizationError("wazuh alert has neither data.win nor full_log")


def _redact_obj(o: Any) -> Any:
    if isinstance(o, str):
        return redact(o)
    if isinstance(o, dict):
        return {k: _redact_obj(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_redact_obj(v) for v in o]
    return o


def prepare(source: str, payload: str, max_raw: int, now: datetime | None = None) -> tuple[NormalizedEvent, dict, str]:
    """Return (event, redacted raw dict, dedup hash)."""
    if source == "linux_auth":
        payload = redact(payload)
        return normalize_linux_auth(payload, now), {"line": payload[:max_raw]}, dedup_hash(source, payload)
    if source not in ("sysmon", "wazuh"):
        raise NormalizationError(f"unsupported source {source!r}")
    try:
        rec = json.loads(payload)
    except json.JSONDecodeError as e:
        raise NormalizationError(f"{source} payload is not JSON") from e
    if not isinstance(rec, dict):
        raise NormalizationError(f"{source} payload must be an object")
    rec = _redact_obj(rec)  # redact values after parsing: redacting the raw JSON text can break the JSON
    if source == "sysmon":
        ev, raw = normalize_sysmon(rec), {"record": {k: str(v)[:max_raw] for k, v in rec.items()}}
    else:
        ev, raw = normalize_wazuh(rec, max_raw)
    return ev, raw, dedup_hash(source, json.dumps(rec, sort_keys=True))
