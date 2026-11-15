import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

JsonType = JSON().with_variant(JSONB(), "postgresql")


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # sha256 of the redacted raw record: idempotent ingestion.
    dedup_hash: Mapped[str] = mapped_column(String(64), unique=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    source: Mapped[str] = mapped_column(String(32), index=True)  # linux_auth | sysmon
    host: Mapped[str] = mapped_column(String(255), index=True)
    category: Mapped[str] = mapped_column(String(32))  # authentication | process
    action: Mapped[str] = mapped_column(String(32))  # failure | success | create
    user: Mapped[str | None] = mapped_column(String(255), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    process_name: Mapped[str | None] = mapped_column(String(512))
    parent_process_name: Mapped[str | None] = mapped_column(String(512))
    command_line: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict] = mapped_column(JsonType)  # redacted + truncated original record


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alert_dedup", "rule_id", "host", "group_key", unique=True),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    group_key: Mapped[str] = mapped_column(String(255))  # e.g. src_ip; prevents duplicate alerts
    mitre: Mapped[list] = mapped_column(JsonType)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    evidence: Mapped[list["AlertEvent"]] = relationship(cascade="all, delete-orphan")


class AlertEvent(Base):
    __tablename__ = "alert_events"
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("security_events.id", ondelete="RESTRICT"), primary_key=True)
