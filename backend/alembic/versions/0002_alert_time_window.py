"""alert time window

Alerts stop being unique per (rule, host, group_key): a new alert starts once the merge window has
passed. Adds first/last evidence timestamps, backfilled from existing evidence.

Downgrade restores the unique index and fails loudly (IntegrityError) if time-windowed alerts already
produced several alerts for one (rule, host, group_key); resolve or delete those first.

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_BOUND = (
    "(SELECT {fn}(e.timestamp) FROM alert_events ae JOIN security_events e ON e.id = ae.event_id "
    "WHERE ae.alert_id = alerts.id)"
)


def upgrade() -> None:
    with op.batch_alter_table("alerts") as b:
        b.add_column(sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(
        f"UPDATE alerts SET first_event_at = COALESCE({_BOUND.format(fn='MIN')}, created_at), "
        f"last_event_at = COALESCE({_BOUND.format(fn='MAX')}, created_at)"
    )
    with op.batch_alter_table("alerts") as b:
        b.alter_column("first_event_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        b.alter_column("last_event_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        b.drop_index("ix_alert_dedup")
        b.create_index("ix_alert_group", ["rule_id", "host", "group_key"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("alerts") as b:
        b.drop_index("ix_alert_group")
        b.create_index("ix_alert_dedup", ["rule_id", "host", "group_key"], unique=True)
        b.drop_column("last_event_at")
        b.drop_column("first_event_at")
