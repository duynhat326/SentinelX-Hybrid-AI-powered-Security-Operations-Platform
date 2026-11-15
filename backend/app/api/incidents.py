import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.auth import require_key
from app.database.models import Alert, AlertEvent, Incident, IncidentAlert, IncidentEntity, SecurityEvent
from app.database.session import get_db

router = APIRouter(prefix="/api/v1/incidents", dependencies=[Depends(require_key)])


class IncidentSummary(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    status: str
    risk_score: int
    first_seen: datetime
    last_seen: datetime
    alert_count: int
    hosts: list[str]
    mitre: list[str]


class IncidentAlertOut(BaseModel):
    id: uuid.UUID
    rule_id: str
    title: str
    severity: str
    mitre: list[str]
    reason: str  # why this alert was grouped into the incident
    first_event_at: datetime
    last_event_at: datetime
    event_count: int


class TimelineEntry(BaseModel):
    event_id: uuid.UUID
    timestamp: datetime
    source: str
    host: str
    category: str
    action: str
    user: str | None
    src_ip: str | None
    dst_ip: str | None
    process_name: str | None
    command_line: str | None
    registry_key: str | None
    alert_ids: list[uuid.UUID]  # detections that cite this event as evidence


class IncidentDetail(IncidentSummary):
    risk_breakdown: dict[str, Any]
    entities: dict[str, list[str]]
    alerts: list[IncidentAlertOut]
    timeline: list[TimelineEntry]
    timeline_total: int


def _summaries(db: Session, incidents: list[Incident]) -> list[IncidentSummary]:
    ids = [i.id for i in incidents]
    counts = dict(db.execute(select(IncidentAlert.incident_id, func.count()).where(IncidentAlert.incident_id.in_(ids))
                             .group_by(IncidentAlert.incident_id)).tuples().all())
    hosts: dict[uuid.UUID, list[str]] = defaultdict(list)
    for iid, host in db.execute(select(IncidentEntity.incident_id, IncidentEntity.value)
                                .where(IncidentEntity.incident_id.in_(ids), IncidentEntity.kind == "host")
                                .order_by(IncidentEntity.value)).tuples():
        hosts[iid].append(host)
    mitre: dict[uuid.UUID, set[str]] = defaultdict(set)
    for iid, techniques in db.execute(select(IncidentAlert.incident_id, Alert.mitre).join(Alert, Alert.id == IncidentAlert.alert_id)
                                      .where(IncidentAlert.incident_id.in_(ids))).tuples():
        mitre[iid].update(techniques)
    return [IncidentSummary(id=i.id, title=i.title, severity=i.severity, status=i.status, risk_score=i.risk_score,
                            first_seen=i.first_seen, last_seen=i.last_seen, alert_count=counts.get(i.id, 0),
                            hosts=hosts[i.id], mitre=sorted(mitre[i.id])) for i in incidents]


@router.get("", response_model=list[IncidentSummary])
def list_incidents(db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=200), status: str | None = None,
                   min_risk: int = Query(0, ge=0, le=100)) -> list[IncidentSummary]:
    q = select(Incident).where(Incident.risk_score >= min_risk)
    if status:
        q = q.where(Incident.status == status)
    return _summaries(db, list(db.scalars(q.order_by(Incident.risk_score.desc(), Incident.last_seen.desc()).limit(limit))))


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: uuid.UUID, db: Session = Depends(get_db),
                 timeline_limit: int = Query(500, ge=1, le=2000)) -> IncidentDetail:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    (summary,) = _summaries(db, [inc])
    alert_rows = db.execute(select(Alert, IncidentAlert.reason).join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
                            .where(IncidentAlert.incident_id == inc.id).order_by(Alert.first_event_at)).tuples().all()
    alert_ids = [a.id for a, _ in alert_rows]
    in_incident = AlertEvent.alert_id.in_(alert_ids)
    total = db.scalar(select(func.count(func.distinct(AlertEvent.event_id))).where(in_incident)) or 0
    event_ids = list(db.scalars(
        select(SecurityEvent.id).join(AlertEvent, AlertEvent.event_id == SecurityEvent.id).where(in_incident)
        .group_by(SecurityEvent.id, SecurityEvent.timestamp).order_by(SecurityEvent.timestamp, SecurityEvent.id).limit(timeline_limit)
    ))
    cited: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    for eid, aid in db.execute(select(AlertEvent.event_id, AlertEvent.alert_id).where(in_incident, AlertEvent.event_id.in_(event_ids))).tuples():
        cited[eid].append(aid)
    events = {e.id: e for e in db.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(event_ids)))}
    timeline = [TimelineEntry(event_id=e.id, timestamp=e.timestamp, source=e.source, host=e.host, category=e.category,
                              action=e.action, user=e.user, src_ip=e.src_ip, dst_ip=e.dst_ip, process_name=e.process_name,
                              command_line=e.command_line, registry_key=e.registry_key, alert_ids=sorted(cited[e.id]))
                for e in (events[i] for i in event_ids)]
    entities: dict[str, list[str]] = defaultdict(list)
    for kind, value in db.execute(select(IncidentEntity.kind, IncidentEntity.value).where(IncidentEntity.incident_id == inc.id)
                                  .order_by(IncidentEntity.kind, IncidentEntity.value)).tuples():
        entities[kind].append(value)
    return IncidentDetail(
        **summary.model_dump(), risk_breakdown=inc.risk_breakdown, entities=dict(entities), timeline=timeline, timeline_total=total,
        alerts=[IncidentAlertOut(id=a.id, rule_id=a.rule_id, title=a.title, severity=a.severity, mitre=a.mitre, reason=reason,
                                 first_event_at=a.first_event_at, last_event_at=a.last_event_at, event_count=a.event_count)
                for a, reason in alert_rows],
    )
