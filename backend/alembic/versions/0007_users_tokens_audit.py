"""users, auth_tokens, audit_logs

Roles are fixed in code; the users.role CHECK names them. audit_logs is append-only by convention.

Revision ID: 0007
Revises: 0006
"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('audit_logs',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
    sa.Column('actor', sa.String(length=100), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=True),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('target_type', sa.String(length=32), nullable=True),
    sa.Column('target_id', sa.String(length=64), nullable=True),
    sa.Column('outcome', sa.String(length=16), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=True),
    sa.Column('detail', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_logs_action'), ['action'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_actor'), ['actor'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_outcome'), ['outcome'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_logs_ts'), ['ts'], unique=False)

    op.create_table('users',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("role IN ('viewer','analyst','approver','admin')", name='ck_user_role'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('auth_tokens',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('token_sha256', sa.String(length=64), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token_sha256')
    )
    with op.batch_alter_table('auth_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_auth_tokens_expires_at'), ['expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_auth_tokens_user_id'), ['user_id'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('auth_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_auth_tokens_user_id'))
        batch_op.drop_index(batch_op.f('ix_auth_tokens_expires_at'))

    op.drop_table('auth_tokens')
    op.drop_table('users')
    with op.batch_alter_table('audit_logs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_logs_ts'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_outcome'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_actor'))
        batch_op.drop_index(batch_op.f('ix_audit_logs_action'))

    op.drop_table('audit_logs')
