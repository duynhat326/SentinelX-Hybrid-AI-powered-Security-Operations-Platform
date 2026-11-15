"""agent run provenance

Existing runs (written before provenance existed) get model "" and prompt_version "v1".

Revision ID: 0006
Revises: 0005
"""
import sqlalchemy as sa

from alembic import op

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('agent_runs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('model', sa.String(length=64), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('prompt_version', sa.String(length=16), nullable=False, server_default='v1'))
        batch_op.add_column(sa.Column('input_sha256', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('duration_ms', sa.Integer(), nullable=True))



def downgrade() -> None:
    with op.batch_alter_table('agent_runs', schema=None) as batch_op:
        batch_op.drop_column('duration_ms')
        batch_op.drop_column('input_sha256')
        batch_op.drop_column('prompt_version')
        batch_op.drop_column('model')

