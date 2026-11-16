import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
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
    process_name: Mapped[str | None] = mapped_column(Text)  # unbounded: an over-long path must not drop the event
    parent_process_name: Mapped[str | None] = mapped_column(Text)
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
    incident_link: Mapped["IncidentAlert | None"] = relationship(uselist=False, viewonly=True)


class AlertEvent(Base):
    __tablename__ = "alert_events"
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("security_events.id", ondelete="RESTRICT"), primary_key=True)


class Incident(Base):
    """A group of related alerts. Severity, risk and title are derived from its alerts and recomputed on change."""

    __tablename__ = "incidents"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(16), index=True)  # highest alert severity
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)  # 0-100, deterministic (app/risk_engine)
    risk_breakdown: Mapped[dict] = mapped_column(JsonType)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class IncidentAlert(Base):
    """alert_id is the primary key: an alert belongs to at most one incident."""

    __tablename__ = "incident_alerts"
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    reason: Mapped[str] = mapped_column(String(600))  # why it was grouped, e.g. "ip:203.0.113.50" or "seed"
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class IncidentEntity(Base):
    """Entities (host, ip, user, process) seen in an incident's alerts; the lookup used to link new alerts."""

    __tablename__ = "incident_entities"
    __table_args__ = (Index("ix_incident_entity_lookup", "kind", "value"),)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)  # host | ip | user | process
    value: Mapped[str] = mapped_column(String(512), primary_key=True)


class AgentRun(Base):
    """One AI investigation of an incident. Advisory only: nothing here feeds severity, risk or any action."""

    __tablename__ = "agent_runs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16))  # ok | failed
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(64), default="")  # model identifier, provenance
    prompt_version: Mapped[str] = mapped_column(String(16), default="v1")  # prompt template version, provenance
    input_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)  # hash of the exact context sent to the model
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output: Mapped[dict | None] = mapped_column(JsonType, nullable=True)  # validated, cited claims only
    dropped_claims: Mapped[int] = mapped_column(Integer, default=0)  # claims without valid evidence citations
    rejected_tool_calls: Mapped[list] = mapped_column(JsonType, default=list)  # audit of refused tool calls
    error: Mapped[str | None] = mapped_column(String(600), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


ROLES = ("viewer", "analyst", "approver", "admin")


class User(Base):
    """Roles are fixed in code (app/api/auth.py PERMISSIONS); the column only names one of them."""

    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('viewer','analyst','approver','admin')", name="ck_user_role"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuthToken(Base):
    """Opaque bearer session. Only the sha256 of the token is stored."""

    __tablename__ = "auth_tokens"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuditLog(Base):
    """Append-only by convention: the application has no code path that updates or deletes a row."""

    __tablename__ = "audit_logs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    actor: Mapped[str] = mapped_column(String(100), index=True)  # user:alice | service:api-key | cli | anonymous
    role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)  # auth.login, authz.denied, user.create, ...
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), index=True)  # ok | denied | error
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    detail: Mapped[dict] = mapped_column(JsonType, default=dict)  # small, redacted; never passwords or tokens


class Ioc(Base):
    """One verdict about one indicator from one source. `manual` rows are the local IOC database (no expiry);
    provider rows are a cache and expire. Unknown is never stored: no row means no information."""

    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("kind", "value", "source", name="uq_ioc"),
        CheckConstraint("score BETWEEN 0 AND 100", name="ck_ioc_score"),
        CheckConstraint("kind IN ('ip','domain','sha256')", name="ck_ioc_kind"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(8))
    value: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(16))  # manual | virustotal | abuseipdb
    score: Mapped[int] = mapped_column(Integer)  # 0 clean .. 100 malicious
    summary: Mapped[str] = mapped_column(String(500))  # built from numbers by us, or written by an analyst; never provider text
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_by: Mapped[str | None] = mapped_column(String(100), nullable=True)


ACTION_TYPES = ("add_blocklist_entry", "request_ip_block", "request_host_isolation", "generate_report")
ACTION_STATUSES = ("proposed", "rejected", "simulated", "executed", "failed", "rolled_back")


class ResponseAction(Base):
    """A response proposed for an incident. Nothing takes effect until a different person approves it, and by default
    approval only simulates (status `simulated`). The state machine lives in app/response/workflow.py."""

    __tablename__ = "response_actions"
    __table_args__ = (
        CheckConstraint("type IN ('add_blocklist_entry','request_ip_block','request_host_isolation','generate_report')", name="ck_action_type"),
        CheckConstraint("status IN ('proposed','rejected','simulated','executed','failed','rolled_back')", name="ck_action_status"),
        UniqueConstraint("requested_by", "idempotency_key", name="uq_action_idempotency"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # RESTRICT: an incident with actions must not disappear (merging incidents re-points them first)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"), index=True)
    type: Mapped[str] = mapped_column(String(32))
    params: Mapped[dict] = mapped_column(JsonType)  # validated against the typed schema for `type`
    status: Mapped[str] = mapped_column(String(16), index=True)
    source: Mapped[str] = mapped_column(String(16))  # human | policy | agent
    requested_by: Mapped[str] = mapped_column(String(100))  # a person, or policy / agent:<provider> for suggestions
    triggered_by: Mapped[str] = mapped_column(String(100))  # the person who proposed or asked for the suggestion: also barred from approving it
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    decided_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict | None] = mapped_column(JsonType, nullable=True)
    rollback_guidance: Mapped[str] = mapped_column(Text)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_hash: Mapped[str] = mapped_column(String(64))  # same key with a different request is a conflict, not a replay


class BlocklistEntry(Base):
    """SentinelX only records the decision. Enforcing it (firewall, proxy) is done by whatever consumes this list."""

    __tablename__ = "blocklist_entries"
    __table_args__ = (Index("uq_blocklist_active", "ip", unique=True, postgresql_where=text("active"), sqlite_where=text("active")),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ip: Mapped[str] = mapped_column(String(45))
    action_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("response_actions.id", ondelete="RESTRICT"))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    created_by: Mapped[str] = mapped_column(String(100))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    removed_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
