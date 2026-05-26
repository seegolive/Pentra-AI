"""add opsec_mode to engagements

Revision ID: a3c91b7d0e22
Revises: fe72005d78b2
Create Date: 2026-05-25 00:00:00.000000

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "a3c91b7d0e22"
down_revision = "fe72005d78b2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "engagements",
        sa.Column("opsec_mode", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "engagements",
        sa.Column("request_jitter_ms", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("engagements", "request_jitter_ms")
    op.drop_column("engagements", "opsec_mode")
