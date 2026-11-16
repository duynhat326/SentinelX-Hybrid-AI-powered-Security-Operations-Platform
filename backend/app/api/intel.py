import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.audit import audit
from app.api.auth import Principal, require
from app.api.incidents import IocOut
from app.core.config import Settings, get_settings
from app.core.indicators import normalize_indicator
from app.correlation.engine import rescore_for_ip
from app.database.models import Incident, IncidentEntity, Ioc
from app.database.session import get_db
from app.threat_intel.service import ConfirmationRequired, EnrichOut, enrich, upsert_ioc

router = APIRouter()
MAX_INCIDENT_INDICATORS = 10  # an incident can hold many addresses; each external lookup is a disclosure and a quota use


class EnrichIn(BaseModel):
    indicator: str = Field(min_length=1, max_length=300)
    confirm_external: bool = False  # explicit per-request consent to send the indicator to third parties


class IncidentEnrichIn(BaseModel):
    confirm_external: bool = False


class IocIn(BaseModel):
    indicator: str = Field(min_length=1, max_length=300)
    score: int = Field(ge=0, le=100)
    summary: str = Field(min_length=1, max_length=500)


class IncidentEnrichOut(BaseModel):
    incident_id: uuid.UUID
    indicators: list[EnrichOut]
    risk_score: int


@router.post("/api/v1/enrich", response_model=EnrichOut)
def post_enrich(body: EnrichIn, request: Request, who: Principal = Depends(require("enrich")), db: Session = Depends(get_db),
                cfg: Settings = Depends(get_settings)) -> EnrichOut:
    try:
        out, stored = enrich(db, cfg, who, body.indicator, body.confirm_external, request)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    except ConfirmationRequired as c:
        raise HTTPException(409, detail=c.detail()) from c
    if stored and out.kind == "ip":
        rescore_for_ip(db, cfg, out.indicator)
    db.commit()  # keeps the audit rows of the external lookups that were made
    return out


@router.post("/api/v1/incidents/{incident_id}/enrich", response_model=IncidentEnrichOut)
def enrich_incident(incident_id: uuid.UUID, body: IncidentEnrichIn, request: Request, who: Principal = Depends(require("enrich")),
                    db: Session = Depends(get_db), cfg: Settings = Depends(get_settings)) -> IncidentEnrichOut:
    """The threat-intelligence step for one incident: look up its addresses (local table first, then providers if allowed and confirmed)."""
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    ips = sorted(db.scalars(select(IncidentEntity.value).where(IncidentEntity.incident_id == incident_id, IncidentEntity.kind == "ip")))
    results, stored_ips = [], []
    try:
        for ip in ips[:MAX_INCIDENT_INDICATORS]:
            out, stored = enrich(db, cfg, who, ip, body.confirm_external, request)
            results.append(out)
            if stored:
                stored_ips.append(ip)
    except ConfirmationRequired as c:
        db.commit()  # lookups already made before this one are still audited
        raise HTTPException(409, detail=c.detail()) from c
    for ip in stored_ips:
        rescore_for_ip(db, cfg, ip)
    db.commit()
    db.refresh(inc)
    return IncidentEnrichOut(incident_id=incident_id, indicators=results, risk_score=inc.risk_score)


@router.get("/api/v1/iocs", response_model=list[IocOut], dependencies=[Depends(require("read"))])
def list_iocs(db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=500), kind: str | None = None, source: str | None = None) -> list[Ioc]:
    q = select(Ioc)
    for col, val in ((Ioc.kind, kind), (Ioc.source, source)):
        if val:
            q = q.where(col == val)
    return list(db.scalars(q.order_by(Ioc.score.desc(), Ioc.value).limit(limit)))


@router.post("/api/v1/iocs", response_model=IocOut, status_code=201)
def add_ioc(body: IocIn, request: Request, who: Principal = Depends(require("manage_iocs")), db: Session = Depends(get_db),
            cfg: Settings = Depends(get_settings)) -> Ioc:
    try:
        kind, value = normalize_indicator(body.indicator)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    row = upsert_ioc(db, kind, value, "manual", body.score, body.summary, None, who.name)
    db.flush()
    audit(db, who, "ioc.create", target_type=kind, target_id=value[:64], detail={"indicator": value, "score": body.score}, request=request)
    if kind == "ip":
        rescore_for_ip(db, cfg, value)
    db.commit()
    return row


@router.delete("/api/v1/iocs/{ioc_id}", status_code=204)
def delete_ioc(ioc_id: uuid.UUID, request: Request, who: Principal = Depends(require("manage_iocs")), db: Session = Depends(get_db),
               cfg: Settings = Depends(get_settings)) -> None:
    row = db.get(Ioc, ioc_id)
    if row is None:
        raise HTTPException(404, "IOC not found")
    audit(db, who, "ioc.delete", target_type=row.kind, target_id=row.value[:64], detail={"indicator": row.value, "source": row.source, "score": row.score}, request=request)
    kind, value = row.kind, row.value
    db.delete(row)
    db.flush()
    if kind == "ip":
        rescore_for_ip(db, cfg, value)
    db.commit()
