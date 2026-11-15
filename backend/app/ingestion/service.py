from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.models import Alert, SecurityEvent
from app.detection.engine import run_detections
from app.normalization.normalize import prepare


def ingest(db: Session, cfg: Settings, source: str, payload: str) -> tuple[SecurityEvent | None, list[Alert]]:
    """Normalize, store (idempotent), detect. Returns (None, []) for a duplicate.
    Raises NormalizationError on bad input."""
    ev, raw, h = prepare(source, payload, cfg.max_raw_bytes)
    if db.get_bind().dialect.name == "postgresql":
        # shortcut: serialize ingestion per host so concurrent events see each other (no duplicate alerts,
        # no missed thresholds). Per-host lock limits throughput; upgrade to per-(host, ip) if it matters.
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": ev.host})
    event = SecurityEvent(dedup_hash=h, raw=raw, **ev.model_dump())
    db.add(event)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return None, []
    alerts = run_detections(db, event, cfg)
    db.commit()
    return event, alerts
