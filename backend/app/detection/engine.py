"""Deterministic detection. No LLM involved; works fully offline."""
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.netutil import is_external
from app.core.timeutil import utc as _utc
from app.database.models import Alert, AlertEvent, DetectionRule, SecurityEvent

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


def _base(path: str | None) -> str:
    return re.split(r"[\\/]", path)[-1].lower() if path else ""


def _single(ev: SecurityEvent) -> Match:
    return str(ev.id), [ev]


_NET_EXE = {"net.exe", "net1.exe"}
_PS_EXE = {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}
_NET_USER_ADD = re.compile(r"(?i)\buser\s+\S+.*\s/add\b")
_PS_NEW_USER = re.compile(r"(?i)\bNew-LocalUser\b")
_NET_ADMIN_ADD = re.compile(r"(?i)\blocalgroup\s+[\"']?administrators[\"']?\s+\S+.*\s/add\b")
_PS_ADMIN_ADD = re.compile(r"(?i)\bAdd-LocalGroupMember\b(?=.*\badministrators\b)")


def _process_cmd(ev: SecurityEvent) -> tuple[str, str] | None:
    if ev.source != "sysmon" or ev.category != "process" or not ev.command_line:
        return None
    return _base(ev.process_name), f" {ev.command_line} "  # padded so a trailing flag still matches


def _account_created(db: Session, ev: SecurityEvent, cfg: Settings) -> Match | None:
    pc = _process_cmd(ev)
    if pc and ((pc[0] in _NET_EXE and _NET_USER_ADD.search(pc[1])) or (pc[0] in _PS_EXE and _PS_NEW_USER.search(pc[1]))):
        return _single(ev)
    return None


def _admin_group_add(db: Session, ev: SecurityEvent, cfg: Settings) -> Match | None:
    pc = _process_cmd(ev)
    if pc and ((pc[0] in _NET_EXE and _NET_ADMIN_ADD.search(pc[1])) or (pc[0] in _PS_EXE and _PS_ADMIN_ADD.search(pc[1]))):
        return _single(ev)
    return None


_RUN_KEY = re.compile(r"(?i)\\(?:CurrentVersion\\Run(?:Once)?(?:Ex)?|Policies\\Explorer\\Run)\\[^\\]+$")


def _run_key_persistence(db: Session, ev: SecurityEvent, cfg: Settings) -> Match | None:
    if ev.source == "sysmon" and ev.category == "registry" and ev.action == "set_value" and _RUN_KEY.search(ev.registry_key or ""):
        return _single(ev)
    return None


_NET_LOLBINS = {"powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
                "bitsadmin.exe", "wscript.exe", "cscript.exe"}


def _lolbin_outbound(db: Session, ev: SecurityEvent, cfg: Settings) -> Match | None:
    if (ev.source == "sysmon" and ev.category == "network" and ev.dst_ip and _base(ev.process_name) in _NET_LOLBINS
            and is_external(ev.dst_ip)):
        return _single(ev)
    return None


_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe"}
_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}


def _office_spawns_shell(db: Session, ev: SecurityEvent, cfg: Settings) -> Match | None:
    if ev.source == "sysmon" and ev.category == "process" and _base(ev.parent_process_name) in _OFFICE and _base(ev.process_name) in _SHELLS:
        return _single(ev)
    return None


_DROPPERS = _PS_EXE | _OFFICE | {"wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
_EXEC_FILE = re.compile(r"(?i)\.(?:exe|dll|scr|js|jse|vbs|vbe|hta|ps1|bat|cmd)$")
_USER_WRITABLE = re.compile(r"(?i)\\(?:Users\\[^\\]+\\(?:AppData|Downloads|Desktop|Documents)|Users\\Public|ProgramData|Temp)\\")


def _dropped_executable(db: Session, ev: SecurityEvent, cfg: Settings) -> Match | None:
    if (ev.source == "sysmon" and ev.category == "file" and ev.file_path and _base(ev.process_name) in _DROPPERS
            and _EXEC_FILE.search(ev.file_path) and _USER_WRITABLE.search(ev.file_path)):
        return _single(ev)
    return None


def _fail_then_success(db: Session, ev: SecurityEvent, cfg: Settings) -> Match | None:
    if ev.source != "linux_auth" or ev.category != "authentication" or not ev.src_ip:
        return None
    w, n = timedelta(seconds=cfg.bruteforce_window_seconds), cfg.bruteforce_threshold
    # successes within +-w of ev, each preceded by >= n failures within w: so fetch [ts - 2w, ts + w]
    rows = list(db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.host == ev.host, SecurityEvent.src_ip == ev.src_ip, SecurityEvent.category == "authentication",
            SecurityEvent.timestamp >= ev.timestamp - 2 * w, SecurityEvent.timestamp <= ev.timestamp + w,
        ).order_by(SecurityEvent.timestamp)
    ))
    for s in (r for r in rows if r.action == "success"):
        st = _utc(s.timestamp)
        fails = [r for r in rows if r.action == "failure" and st - w <= _utc(r.timestamp) <= st]
        if len(fails) >= n:
            return f"{ev.src_ip}:{s.user}", [*fails, s]
    return None


RULES: list[Rule] = [
    Rule("SX-001", "Repeated failed SSH logins from one source", "high", ["T1110"],
         ["https://attack.mitre.org/techniques/T1110/"], _bruteforce, tags=["linux", "auth"]),
    Rule("SX-002", "Suspicious PowerShell command line", "high", ["T1059.001"],
         ["https://attack.mitre.org/techniques/T1059/001/"], _ps_suspicious, tags=["windows", "execution"]),
    Rule("SX-003", "Local account created from the command line", "high", ["T1136.001"],
         ["https://attack.mitre.org/techniques/T1136/001/"], _account_created, tags=["windows", "persistence"]),
    Rule("SX-004", "Account added to the local Administrators group", "high", ["T1098"],
         ["https://attack.mitre.org/techniques/T1098/"], _admin_group_add, tags=["windows", "privilege-escalation"]),
    Rule("SX-005", "Registry Run key persistence", "medium", ["T1547.001"],
         ["https://attack.mitre.org/techniques/T1547/001/"], _run_key_persistence, tags=["windows", "persistence"]),
    Rule("SX-006", "Script host or LOLBin connecting to an external address", "medium", ["T1071"],
         ["https://attack.mitre.org/techniques/T1071/"], _lolbin_outbound, tags=["windows", "command-and-control"]),
    Rule("SX-007", "Office application spawning a shell or script host", "high", ["T1204.002"],
         ["https://attack.mitre.org/techniques/T1204/002/"], _office_spawns_shell, tags=["windows", "execution"]),
    Rule("SX-009", "Script host or Office application writing an executable to a user-writable folder", "medium", ["T1105"],
         ["https://attack.mitre.org/techniques/T1105/"], _dropped_executable, tags=["windows", "command-and-control"]),
    Rule("SX-008", "Repeated SSH failures followed by a successful login", "critical", ["T1110", "T1078"],
         ["https://attack.mitre.org/techniques/T1110/", "https://attack.mitre.org/techniques/T1078/"],
         _fail_then_success, tags=["linux", "auth"]),
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
        key, evidence = m[0][:255], m[1]  # group_key column is 255 chars; keys embed attacker-influenced names
        stamps = [_utc(e.timestamp) for e in evidence]
        lo, hi = min(stamps), max(stamps)
        # shortcut: one merge window (the brute-force window) for every rule; an alert for the same
        # (rule, host, group_key) absorbs events inside it, later ones open a new alert.
        w = timedelta(seconds=cfg.bruteforce_window_seconds)
        alert = db.scalar(
            select(Alert).where(
                Alert.rule_id == rule.id, Alert.host == ev.host, Alert.group_key == key,
                Alert.last_event_at >= ev.timestamp - w, Alert.first_event_at <= ev.timestamp + w,
            ).order_by(Alert.last_event_at.desc())
        )
        if alert is None:
            alert = Alert(rule_id=rule.id, title=rule.title, severity=rule.severity, host=ev.host, group_key=key,
                          mitre=rule.mitre, event_count=0, first_event_at=lo, last_event_at=hi)
            db.add(alert)
            db.flush()
        else:
            alert.first_event_at, alert.last_event_at = min(_utc(alert.first_event_at), lo), max(_utc(alert.last_event_at), hi)
        have = {e.event_id for e in alert.evidence}
        for e in evidence:
            if e.id not in have:
                alert.evidence.append(AlertEvent(alert_id=alert.id, event_id=e.id))
        alert.event_count = len(alert.evidence)
        out.append(alert)
    return out
