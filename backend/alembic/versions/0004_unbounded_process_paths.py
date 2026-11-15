"""unbounded process paths

process_name and parent_process_name become TEXT so an over-long (attacker-chosen) path cannot make the
database reject the event. Widening is lossless; the downgrade narrows back to VARCHAR(512) and fails if a
longer value is stored (truncate or delete those rows first).

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa

from alembic import op

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('security_events', schema=None) as batch_op:
        batch_op.alter_column('process_name',
               existing_type=sa.VARCHAR(length=512),
               type_=sa.Text(),
               existing_nullable=True)
        batch_op.alter_column('parent_process_name',
               existing_type=sa.VARCHAR(length=512),
               type_=sa.Text(),
               existing_nullable=True)



def downgrade() -> None:
    with op.batch_alter_table('security_events', schema=None) as batch_op:
        batch_op.alter_column('parent_process_name',
               existing_type=sa.Text(),
               type_=sa.VARCHAR(length=512),
               existing_nullable=True)
        batch_op.alter_column('process_name',
               existing_type=sa.Text(),
               type_=sa.VARCHAR(length=512),
               existing_nullable=True)

