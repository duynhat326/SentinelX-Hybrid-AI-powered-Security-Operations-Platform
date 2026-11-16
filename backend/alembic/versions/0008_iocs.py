"""iocs: the local IOC table and the threat-intelligence cache

manual rows never expire; provider rows carry expires_at. Unknown is never stored.

Revision ID: 0008
Revises: 0007
"""
import sqlalchemy as sa

from alembic import op

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('iocs',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.String(length=8), nullable=False),
    sa.Column('value', sa.String(length=255), nullable=False),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('score', sa.Integer(), nullable=False),
    sa.Column('summary', sa.String(length=500), nullable=False),
    sa.Column('checked_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.String(length=100), nullable=True),
    sa.CheckConstraint("kind IN ('ip','domain','sha256')", name='ck_ioc_kind'),
    sa.CheckConstraint('score BETWEEN 0 AND 100', name='ck_ioc_score'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('kind', 'value', 'source', name='uq_ioc')
    )
    with op.batch_alter_table('iocs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_iocs_expires_at'), ['expires_at'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('iocs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_iocs_expires_at'))

    op.drop_table('iocs')
