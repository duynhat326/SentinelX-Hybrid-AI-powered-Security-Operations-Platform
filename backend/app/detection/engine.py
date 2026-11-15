"""Deterministic detection. No LLM involved; works fully offline."""
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import Alert, AlertEvent, DetectionRule, SecurityEvent


def _utc(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=UTC)  # SQLite drops tzinfo on read


Match = tuple[str, list[SecurityEvent]]  # (group_key, evidence events)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str  # low | medium | high | critical
    mitre: list[str]
    references: list[str]
    check: Callable[[Session, SecurityEvent, Settings], Match | None]
    enabled: bool = True
    tags: list[str] = field(default_factory=list)


def _bruteforce(db: Session, ev: SecurityEvent, cfg: Settings) -> Match | None:
    if ev.source != "linux_auth" or ev.action != "failure" or not ev.src_ip:
        return None
    w, n = timedelta(seconds=cfg.bruteforce_window_seconds), cfg.bruteforce_threshold
    # look both ways: logs arrive out of order, so later-stamped events may already be stored
    rows = list(db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.host == ev.host, SecurityEvent.src_ip == ev.src_ip,
            SecurityEvent.category == "authentication", SecurityEvent.action == "failure",
            SecurityEvent.timestamp >= ev.timestamp - w, SecurityEvent.timestamp <= ev.timestamp + w,
        ).order_by(SecurityEvent.timestamp)
    ))
    # shortcut: any burst within +-window of this event triggers, evidence is the whole +-window set (can span 2x window).
    for i in range(len(rows) - n + 1):
        if _utc(rows[i + n - 1].timestamp) - _utc(rows[i].timestamp) <= w:
            return ev.src_ip, rows
    return None


_PS = re.compile(r"powershell(?:_ise)?\.exe$|pwsh\.exe$", re.IGNORECASE)
_PS_SUSPICIOUS = re.compile(r"(?i)(?:\s-(?:e|ec|enc|encodedcommand)\s|downloadstring|invoke-expression|\biex\b|-nop\b.*-w(?:indowstyle)?\s+hidden)")


def _ps_suspicious(db: Session, ev: SecurityEvent, cfg: Settings) -> Match | None:
    if ev.source != "sysmon" or not ev.process_name or not _PS.search(ev.process_name):
        return None
    # pad so a flag at the very end of the command line still matches the \s-delimited pattern
    if ev.command_line and _PS_SUSPICIOUS.search(f" {ev.command_line} "):
        return str(ev.id), [ev]
    return None


RULES: list[Rule] = [
    Rule("SX-001", "Repeated failed SSH logins from one source", "high", ["T1110"],
         ["https://attack.mitre.org/techniques/T1110/"], _bruteforce, tags=["linux", "auth"]),
    Rule("SX-002", "Suspicious PowerShell command line", "high", ["T1059.001"],
         ["https://attack.mitre.org/techniques/T1059/001/"], _ps_suspicious, tags=["windows", "execution"]),
]


def sync_rules(db: Session) -> None:
    """Mirror code-defined rule metadata into detection_rules. `enabled` is operator state: set from
    the code default only when the row is first created, never overwritten afterwards."""
    for r in RULES:
        row = db.get(DetectionRule, r.id)
        if row is None:
            db.add(DetectionRule(id=r.id, title=r.title, severity=r.severity, mitre=r.mitre, enabled=r.enabled))
        else:
            row.title, row.severity, row.mitre = r.title, r.severity, r.mitre
    db.commit()


def run_detections(db: Session, ev: SecurityEvent, cfg: Settings, rules: list[Rule] | None = None) -> list[Alert]:
    out: list[Alert] = []
    disabled = set(db.scalars(select(DetectionRule.id).where(DetectionRule.enabled.is_(False))))
    for rule in rules if rules is not None else RULES:
        if not rule.enabled or rule.id in disabled or not (m := rule.check(db, ev, cfg)):
            continue
        key, evidence = m
        alert = db.scalar(select(Alert).where(Alert.rule_id == rule.id, Alert.host == ev.host, Alert.group_key == key))
        if alert is None:
            alert = Alert(rule_id=rule.id, title=rule.title, severity=rule.severity, host=ev.host,
                          group_key=key, mitre=rule.mitre, event_count=0)
            db.add(alert)
            db.flush()
        have = {e.event_id for e in alert.evidence}
        for e in evidence:
            if e.id not in have:
                alert.evidence.append(AlertEvent(alert_id=alert.id, event_id=e.id))
        alert.event_count = len(alert.evidence)
        out.append(alert)
    return out
