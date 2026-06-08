"""add_engagement_learnings

Revision ID: fe25c4ad4fac
Revises: cc62ee2cd0df
Create Date: 2026-06-03 14:53:31.919794

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'fe25c4ad4fac'
down_revision: Union[str, Sequence[str], None] = 'cc62ee2cd0df'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add engagement_learnings table."""
    op.create_table(
        "engagement_learnings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("engagement_id", sa.UUID(), nullable=False),
        sa.Column("tech_stack", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("target_pattern", sa.String(length=200), nullable=False),
        sa.Column("effective_tools", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("effective_techniques", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("failed_tools", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("failed_techniques", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("high_value_endpoints", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("high_critical_count", sa.Integer(), nullable=False),
        sa.Column("engagement_duration_minutes", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_engagement_learnings_engagement_id"),
        "engagement_learnings",
        ["engagement_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop engagement_learnings table."""
    op.drop_index(
        op.f("ix_engagement_learnings_engagement_id"),
        table_name="engagement_learnings",
    )
    op.drop_table("engagement_learnings")
