"""add_agent_events_table

Revision ID: a9c3f1e82b47
Revises: fe25c4ad4fac
Create Date: 2026-06-09 10:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a9c3f1e82b47"
down_revision: Union[str, Sequence[str], None] = "fe25c4ad4fac"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create agent_events table for WebSocket event persistence (Task 19.4)."""
    op.create_table(
        "agent_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("engagement_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("node", sa.String(length=100), nullable=True),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"], ["engagements.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_agent_events_engagement_id",
        "agent_events",
        ["engagement_id"],
    )
    op.create_index(
        "ix_agent_events_created_at",
        "agent_events",
        ["created_at"],
    )
    # Composite index for cleanup query: engagement_id + created_at
    op.create_index(
        "ix_agent_events_cleanup",
        "agent_events",
        ["engagement_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_agent_events_cleanup", table_name="agent_events")
    op.drop_index("ix_agent_events_created_at", table_name="agent_events")
    op.drop_index("ix_agent_events_engagement_id", table_name="agent_events")
    op.drop_table("agent_events")
