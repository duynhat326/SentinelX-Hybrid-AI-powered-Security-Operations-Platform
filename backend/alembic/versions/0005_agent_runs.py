"""agent_runs

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None

_json = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    op.create_table('agent_runs',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('incident_id', sa.Uuid(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('output', _json, nullable=True),
    sa.Column('dropped_claims', sa.Integer(), nullable=False),
    sa.Column('rejected_tool_calls', _json, nullable=False),
    sa.Column('error', sa.String(length=600), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('agent_runs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_agent_runs_incident_id'), ['incident_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('agent_runs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_agent_runs_incident_id'))
    op.drop_table('agent_runs')
