from sqlalchemy import select, text
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.correlation.engine import correlate_many
from app.database.models import Alert, Asset, SecurityEvent
from app.detection.engine import run_detections
from app.normalization.normalize import NormalizationError, prepare


def ingest(db: Session, cfg: Settings, source: str, payload: str) -> tuple[SecurityEvent | None, list[Alert]]:
    """Normalize, store (idempotent), detect. Returns (None, []) for a duplicate.
    Raises NormalizationError on bad input."""
    ev, raw, h = prepare(source, payload, cfg.max_raw_bytes)
    try:
        return _store(db, cfg, ev, raw, h)
    except DataError as e:  # a value the database cannot hold: reject visibly, never a silent 500
        db.rollback()
        raise NormalizationError("a field value is too long or invalid for storage") from e


def _store(db: Session, cfg: Settings, ev, raw: dict, h: str) -> tuple[SecurityEvent | None, list[Alert]]:
    if db.get_bind().dialect.name == "postgresql":
        # shortcut: serialize ingestion per host so concurrent events see each other (no duplicate alerts,
        # no missed thresholds). Per-host lock limits throughput; upgrade to per-(host, ip) if it matters.
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": ev.host})
    asset = db.scalar(select(Asset).where(Asset.hostname == ev.host))
    if asset is None:  # safe: on PostgreSQL we hold the per-host lock, so no concurrent creator
        asset = Asset(hostname=ev.host)
        db.add(asset)
        db.flush()
    event = SecurityEvent(dedup_hash=h, raw=raw, asset_id=asset.id, **ev.model_dump())
    db.add(event)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return None, []
    alerts = run_detections(db, event, cfg)
    if alerts:
        correlate_many(db, alerts, cfg)
    db.commit()
    return event, alerts
