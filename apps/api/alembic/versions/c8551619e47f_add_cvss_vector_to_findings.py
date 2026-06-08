"""add_cvss_vector_to_findings

Revision ID: c8551619e47f
Revises: fe25c4ad4fac
Create Date: 2026-06-03

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c8551619e47f"
down_revision: Union[str, Sequence[str], None] = "fe25c4ad4fac"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add cvss_vector column to findings table."""
    op.add_column(
        "findings",
        sa.Column(
            "cvss_vector",
            sa.String(length=200),
            nullable=True,
            comment="CVSS v3.1 vector string, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
    )


def downgrade() -> None:
    """Drop cvss_vector column from findings table."""
    op.drop_column("findings", "cvss_vector")
