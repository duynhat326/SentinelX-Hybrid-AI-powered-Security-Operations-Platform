"""security_events.file_path for Sysmon event 11 (file create)

Revision ID: 0010
Revises: 0009
"""
import sqlalchemy as sa

from alembic import op

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('security_events', schema=None) as batch_op:
        batch_op.add_column(sa.Column('file_path', sa.Text(), nullable=True))



def downgrade() -> None:
    with op.batch_alter_table('security_events', schema=None) as batch_op:
        batch_op.drop_column('file_path')

