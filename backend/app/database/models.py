import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

JsonType = JSON().with_variant(JSONB(), "postgresql")


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Asset(Base):
    """A monitored host. Created automatically on first event; criticality (1-5) feeds the risk engine (M4)."""

    __tablename__ = "assets"
    __table_args__ = (CheckConstraint("criticality BETWEEN 1 AND 5", name="ck_asset_criticality"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(255), unique=True)
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DetectionRule(Base):
    """Operator-controlled state of a code-defined rule. Metadata is synced from code at startup;
    `enabled` is never overwritten by the sync."""

    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. SX-001
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    mitre: Mapped[list] = mapped_column(JsonType)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # sha256 of the redacted raw record: idempotent ingestion.
    dedup_hash: Mapped[str] = mapped_column(String(64), unique=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), index=True)
    source: Mapped[str] = mapped_column(String(32), index=True)  # linux_auth | sysmon
    host: Mapped[str] = mapped_column(String(255), index=True)
    category: Mapped[str] = mapped_column(String(32))  # authentication | process | network | registry
    action: Mapped[str] = mapped_column(String(32))  # failure | success | create | connect | create_key | set_value ...
    user: Mapped[str | None] = mapped_column(String(255), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(512))
    parent_process_name: Mapped[str | None] = mapped_column(String(512))
    command_line: Mapped[str | None] = mapped_column(Text)
    registry_key: Mapped[str | None] = mapped_column(Text)
    registry_value: Mapped[str | None] = mapped_column(Text)  # Sysmon "Details" of a SetValue, redacted
    raw: Mapped[dict] = mapped_column(JsonType)  # redacted + truncated original record


class Alert(Base):
    __tablename__ = "alerts"
    # Not unique: a new alert for the same group starts once the merge window has passed (see detection engine).
    __table_args__ = (Index("ix_alert_group", "rule_id", "host", "group_key"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    group_key: Mapped[str] = mapped_column(String(255))  # e.g. src_ip; alerts with the same key merge inside the window
    mitre: Mapped[list] = mapped_column(JsonType)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))  # earliest evidence event
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))  # latest evidence event
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    evidence: Mapped[list["AlertEvent"]] = relationship(cascade="all, delete-orphan")


class AlertEvent(Base):
    __tablename__ = "alert_events"
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("security_events.id", ondelete="RESTRICT"), primary_key=True)
