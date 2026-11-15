"""Deterministic correlation: group alerts into incidents. No LLM involved.

Two alerts belong to one incident when their time ranges are within `correlation_window_seconds` of the
incident's and they share an entity. Entities are host, ip (source or destination), user and process, with
the exclusions below because over-linking merges unrelated incidents. An alert that bridges two incidents
merges them into the oldest.
"""
from datetime import timedelta
from ipaddress import ip_address

from sqlalchemy import and_, delete, func, or_, select, text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.timeutil import utc
from app.database.models import Alert, AlertEvent, Asset, Incident, IncidentAlert, IncidentEntity, SecurityEvent
from app.risk_engine.score import SEVERITY_ORDER, Weights, risk_score

Entity = tuple[str, str]

# shortcut: fixed lists, extend when real data shows over-linking. Names attackers guess or every host has.
GENERIC_USERS = {"root", "admin", "administrator", "guest", "system", "test", "user", "ubuntu", "pi", "oracle", "postgres", "-"}
_SYSTEM_PATHS = ("c:\\windows\\", "c:\\program files", "/usr/", "/bin/", "/sbin/", "/lib")
_PRIORITY = {"ip": 0, "user": 1, "process": 2, "host": 3}  # most specific link wins as the recorded reason


def _norm_user(u: str | None) -> str | None:
    n = (u or "").replace("/", "\\").split("\\")[-1].strip().lower()  # LAB\Alice and alice are one user
    return None if not n or n in GENERIC_USERS else n


def _ip_ok(ip: str | None) -> bool:
    if not ip:
        return False
    a = ip_address(ip)
    return not (a.is_loopback or a.is_unspecified or a.is_link_local or a.is_multicast)


def _process_ok(p: str | None) -> bool:
    # the same system binary exists on every host and links nothing; an unusual path repeated across hosts does
    return bool(p) and not p.lower().startswith(_SYSTEM_PATHS)  # type: ignore[union-attr]


def alert_entities(db: Session, alert: Alert) -> set[Entity]:
    ents: set[Entity] = {("host", alert.host)}
    rows = db.execute(
        select(SecurityEvent.user, SecurityEvent.src_ip, SecurityEvent.dst_ip, SecurityEvent.process_name)
        .join(AlertEvent, AlertEvent.event_id == SecurityEvent.id).where(AlertEvent.alert_id == alert.id)
    ).all()
    for user, src, dst, proc in rows:
        if (u := _norm_user(user)):
            ents.add(("user", u))
        for ip in (src, dst):
            if ip and _ip_ok(ip):
                ents.add(("ip", ip))
        if _process_ok(proc):
            ents.add(("process", str(proc)[:512]))
    return ents


def _refresh(db: Session, inc: Incident, cfg: Settings) -> None:
    """Recompute everything derived from the incident's alerts."""
    rows = db.execute(
        select(Alert.rule_id, Alert.title, Alert.severity, Alert.first_event_at, Alert.last_event_at, Alert.host)
        .join(IncidentAlert, IncidentAlert.alert_id == Alert.id).where(IncidentAlert.incident_id == inc.id)
    ).all()
    top = max(rows, key=lambda r: (SEVERITY_ORDER.index(r.severity), -utc(r.first_event_at).timestamp()))
    inc.severity = top.severity
    inc.title = (top.title if len(rows) == 1 else f"{top.title} (+{len(rows) - 1} related)")[:300]
    inc.first_seen = min(utc(r.first_event_at) for r in rows)
    inc.last_seen = max(utc(r.last_event_at) for r in rows)
    criticality = db.scalar(select(func.max(Asset.criticality)).where(Asset.hostname.in_({r.host for r in rows})))
    weights = Weights(cfg.risk_weight_severity, cfg.risk_weight_correlation, cfg.risk_weight_threat_intel, cfg.risk_weight_asset)
    # threat intelligence arrives in M6; until then it is "missing", not zero
    inc.risk_score, inc.risk_breakdown = risk_score(inc.severity, len({r.rule_id for r in rows}), criticality, None, weights)


def _merge(db: Session, keep: Incident, drop: Incident) -> None:
    for link in db.scalars(select(IncidentAlert).where(IncidentAlert.incident_id == drop.id)):
        link.incident_id = keep.id
    have = {(e.kind, e.value) for e in db.scalars(select(IncidentEntity).where(IncidentEntity.incident_id == keep.id))}
    for e in list(db.scalars(select(IncidentEntity).where(IncidentEntity.incident_id == drop.id))):
        if (e.kind, e.value) not in have:
            db.add(IncidentEntity(incident_id=keep.id, kind=e.kind, value=e.value))
    db.flush()
    db.execute(delete(IncidentEntity).where(IncidentEntity.incident_id == drop.id))  # SQLite does not enforce ON DELETE CASCADE
    db.delete(drop)
    db.flush()


def correlate(db: Session, alert: Alert, cfg: Settings) -> Incident:
    """Attach `alert` to the right incident (creating or merging as needed). Idempotent for an alert already linked."""
    ents = alert_entities(db, alert)
    w = timedelta(seconds=cfg.correlation_window_seconds)
    found = db.execute(
        select(IncidentEntity.incident_id, IncidentEntity.kind, IncidentEntity.value)
        .join(Incident, Incident.id == IncidentEntity.incident_id)
        .where(or_(*[and_(IncidentEntity.kind == k, IncidentEntity.value == v) for k, v in sorted(ents)]),
               Incident.status == "open",
               Incident.last_seen >= alert.first_event_at - w, Incident.first_seen <= alert.last_event_at + w)
    ).all()
    reasons: dict = {}
    for iid, kind, value in sorted(found, key=lambda r: (_PRIORITY[r.kind], r.value)):
        reasons.setdefault(iid, f"{kind}:{value}"[:600])
    link = db.get(IncidentAlert, alert.id)
    ids = set(reasons) | ({link.incident_id} if link else set())
    if not ids:
        inc = Incident(title=alert.title, severity=alert.severity, status="open", risk_score=0, risk_breakdown={},
                       first_seen=alert.first_event_at, last_seen=alert.last_event_at)
        db.add(inc)
        db.flush()
        reason = "seed"
    else:
        incs = sorted(db.scalars(select(Incident).where(Incident.id.in_(ids))), key=lambda i: (utc(i.first_seen), str(i.id)))
        inc = incs[0]
        for other in incs[1:]:
            _merge(db, inc, other)
        reason = reasons.get(inc.id) or (link.reason if link else "seed")
    if db.get(IncidentAlert, alert.id) is None:
        db.add(IncidentAlert(alert_id=alert.id, incident_id=inc.id, reason=reason))
    have = {(e.kind, e.value) for e in db.scalars(select(IncidentEntity).where(IncidentEntity.incident_id == inc.id))}
    for kind, value in ents - have:
        db.add(IncidentEntity(incident_id=inc.id, kind=kind, value=value))
    db.flush()
    _refresh(db, inc, cfg)
    return inc


def correlate_many(db: Session, alerts: list[Alert], cfg: Settings) -> None:
    if db.get_bind().dialect.name == "postgresql":
        # incidents span hosts, so the per-host ingestion lock is not enough; lock order is host then this one
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext('sentinelx-correlation'))"))
    for a in sorted({a.id: a for a in alerts}.values(), key=lambda a: utc(a.first_event_at)):
        correlate(db, a, cfg)


def backfill(db: Session, cfg: Settings) -> int:
    """Correlate alerts that have no incident yet (created before incidents existed). Idempotent."""
    orphans = list(db.scalars(
        select(Alert).outerjoin(IncidentAlert, IncidentAlert.alert_id == Alert.id)
        .where(IncidentAlert.alert_id.is_(None)).order_by(Alert.first_event_at)
    ))
    for a in orphans:
        correlate(db, a, cfg)
    db.commit()
    return len(orphans)
