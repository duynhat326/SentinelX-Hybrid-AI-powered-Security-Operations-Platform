"""response_actions and blocklist_entries

Actions reference incidents with ON DELETE RESTRICT; merging incidents re-points them first. Only one active blocklist entry per address.

Revision ID: 0009
Revises: 0008
"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('response_actions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('incident_id', sa.Uuid(), nullable=False),
    sa.Column('type', sa.String(length=32), nullable=False),
    sa.Column('params', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('requested_by', sa.String(length=100), nullable=False),
    sa.Column('triggered_by', sa.String(length=100), nullable=False),
    sa.Column('requested_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('decided_by', sa.String(length=100), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('decision_reason', sa.String(length=500), nullable=True),
    sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('result', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('rollback_guidance', sa.Text(), nullable=False),
    sa.Column('idempotency_key', sa.String(length=128), nullable=True),
    sa.Column('request_hash', sa.String(length=64), nullable=False),
    sa.CheckConstraint("status IN ('proposed','rejected','simulated','executed','failed','rolled_back')", name='ck_action_status'),
    sa.CheckConstraint("type IN ('add_blocklist_entry','request_ip_block','request_host_isolation','generate_report')", name='ck_action_type'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('requested_by', 'idempotency_key', name='uq_action_idempotency')
    )
    with op.batch_alter_table('response_actions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_response_actions_incident_id'), ['incident_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_response_actions_requested_at'), ['requested_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_response_actions_status'), ['status'], unique=False)

    op.create_table('blocklist_entries',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=False),
    sa.Column('action_id', sa.Uuid(), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.String(length=100), nullable=False),
    sa.Column('removed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('removed_by', sa.String(length=100), nullable=True),
    sa.ForeignKeyConstraint(['action_id'], ['response_actions.id'], ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('blocklist_entries', schema=None) as batch_op:
        batch_op.create_index('uq_blocklist_active', ['ip'], unique=True, postgresql_where=sa.text('active'), sqlite_where=sa.text('active'))



def downgrade() -> None:
    with op.batch_alter_table('blocklist_entries', schema=None) as batch_op:
        batch_op.drop_index('uq_blocklist_active', postgresql_where=sa.text('active'), sqlite_where=sa.text('active'))

    op.drop_table('blocklist_entries')
    with op.batch_alter_table('response_actions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_response_actions_status'))
        batch_op.drop_index(batch_op.f('ix_response_actions_requested_at'))
        batch_op.drop_index(batch_op.f('ix_response_actions_incident_id'))

    op.drop_table('response_actions')
