"""add tool_config to engagements

Revision ID: a3f2c8d91e45
Revises: bcd8b0015e73
Create Date: 2026-07-02 00:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "a3f2c8d91e45"
down_revision = "bcd8b0015e73"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "engagements",
        sa.Column("tool_config", JSONB, nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("engagements", "tool_config")
