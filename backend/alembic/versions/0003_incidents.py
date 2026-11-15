"""incidents, incident_alerts, incident_entities

Existing alerts get no incident here; the application backfills them at startup (correlation.engine.backfill).

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('incidents',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('risk_score', sa.Integer(), nullable=False),
    sa.Column('risk_breakdown', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_incidents_first_seen'), ['first_seen'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_last_seen'), ['last_seen'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_risk_score'), ['risk_score'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_status'), ['status'], unique=False)

    op.create_table('incident_alerts',
    sa.Column('alert_id', sa.Uuid(), nullable=False),
    sa.Column('incident_id', sa.Uuid(), nullable=False),
    sa.Column('reason', sa.String(length=600), nullable=False),
    sa.Column('linked_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('alert_id')
    )
    with op.batch_alter_table('incident_alerts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_incident_alerts_incident_id'), ['incident_id'], unique=False)

    op.create_table('incident_entities',
    sa.Column('incident_id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('value', sa.String(length=512), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('incident_id', 'kind', 'value')
    )
    with op.batch_alter_table('incident_entities', schema=None) as batch_op:
        batch_op.create_index('ix_incident_entity_lookup', ['kind', 'value'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('incident_entities', schema=None) as batch_op:
        batch_op.drop_index('ix_incident_entity_lookup')

    op.drop_table('incident_entities')
    with op.batch_alter_table('incident_alerts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_incident_alerts_incident_id'))

    op.drop_table('incident_alerts')
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_incidents_status'))
        batch_op.drop_index(batch_op.f('ix_incidents_severity'))
        batch_op.drop_index(batch_op.f('ix_incidents_risk_score'))
        batch_op.drop_index(batch_op.f('ix_incidents_last_seen'))
        batch_op.drop_index(batch_op.f('ix_incidents_first_seen'))

    op.drop_table('incidents')
