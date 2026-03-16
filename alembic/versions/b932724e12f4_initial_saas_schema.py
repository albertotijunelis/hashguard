"""initial_saas_schema

Revision ID: b932724e12f4
Revises: 
Create Date: 2026-03-13 19:22:17.664652

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b932724e12f4'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add SaaS tables: users, api_keys, webhooks."""
    # Users table
    op.create_table('users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('display_name', sa.String(length=255), nullable=True),
        sa.Column('role', sa.String(length=50), nullable=False, server_default='analyst'),
        sa.Column('tenant_id', sa.String(length=100), nullable=False, server_default='default'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('email_verified', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.create_index('ix_users_tenant_id', 'users', ['tenant_id'], unique=False)

    # API Keys table (replaces JSON file storage)
    op.create_table('api_keys',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('key_id', sa.String(length=64), nullable=False),
        sa.Column('key_hash', sa.String(length=128), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False, server_default='analyst'),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('tenant_id', sa.String(length=100), nullable=False, server_default='default'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('created_at', sa.Float(), nullable=False, server_default=sa.text('0')),
        sa.Column('last_used', sa.Float(), nullable=False, server_default=sa.text('0')),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_api_keys_key_id', 'api_keys', ['key_id'], unique=True)
    op.create_index('ix_api_keys_tenant_id', 'api_keys', ['tenant_id'], unique=False)

    # Webhooks table (replaces JSON file storage)
    op.create_table('webhooks',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('webhook_id', sa.String(length=64), nullable=False),
        sa.Column('url', sa.String(length=2048), nullable=False),
        sa.Column('events', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('secret', sa.String(length=128), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('tenant_id', sa.String(length=100), nullable=False, server_default='default'),
        sa.Column('created_at', sa.String(length=50), nullable=True),
        sa.Column('last_triggered', sa.String(length=50), nullable=True),
        sa.Column('failure_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_webhooks_webhook_id', 'webhooks', ['webhook_id'], unique=True)
    op.create_index('ix_webhooks_tenant_id', 'webhooks', ['tenant_id'], unique=False)


def downgrade() -> None:
    """Remove SaaS tables."""
    op.drop_index('ix_webhooks_tenant_id', table_name='webhooks')
    op.drop_index('ix_webhooks_webhook_id', table_name='webhooks')
    op.drop_table('webhooks')
    op.drop_index('ix_api_keys_tenant_id', table_name='api_keys')
    op.drop_index('ix_api_keys_key_id', table_name='api_keys')
    op.drop_table('api_keys')
    op.drop_index('ix_users_tenant_id', table_name='users')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_table('users')
