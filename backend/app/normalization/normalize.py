"""Raw record -> NormalizedEvent. Inputs are untrusted: every field is validated or dropped."""
import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime

from pydantic import BaseModel, field_validator

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
    category: str
    action: str
    user: str | None = None
    src_ip: str | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    command_line: str | None = None

    @field_validator("src_ip")
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


def normalize_sysmon(rec: dict) -> NormalizedEvent:
    """Sysmon EventID 1 (process create), as exported to JSON (Wazuh / winlogbeat style)."""
    try:
        if int(rec["EventID"]) != 1:
            raise NormalizationError("only Sysmon EventID 1 supported in M1")
        return NormalizedEvent(
            timestamp=datetime.fromisoformat(str(rec["UtcTime"])).astimezone(UTC)
            if "T" in str(rec["UtcTime"])
            else datetime.strptime(rec["UtcTime"], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=UTC),
            source="sysmon", host=str(rec["Computer"]), category="process", action="create",
            user=rec.get("User"), process_name=rec.get("Image"), parent_process_name=rec.get("ParentImage"),
            command_line=redact(str(rec.get("CommandLine", ""))) or None,
        )
    except (KeyError, ValueError, TypeError) as e:
        raise NormalizationError(f"invalid sysmon record: {e}") from e


def prepare(source: str, payload: str, max_raw: int, now: datetime | None = None) -> tuple[NormalizedEvent, dict, str]:
    """Return (event, redacted raw dict, dedup hash)."""
    payload = redact(payload)
    if source == "linux_auth":
        ev = normalize_linux_auth(payload, now)
        raw: dict = {"line": payload[:max_raw]}
    elif source == "sysmon":
        try:
            rec = json.loads(payload)
        except json.JSONDecodeError as e:
            raise NormalizationError("sysmon payload is not JSON") from e
        if not isinstance(rec, dict):
            raise NormalizationError("sysmon payload must be an object")
        ev = normalize_sysmon(rec)
        raw = {"record": {k: str(v)[:max_raw] for k, v in rec.items()}}
    else:
        raise NormalizationError(f"unsupported source {source!r}")
    return ev, raw, dedup_hash(source, payload)
