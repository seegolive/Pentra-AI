"""add scan_sequential to engagements

Revision ID: b3d7a91f2e05
Revises: 6b96c038171c
Create Date: 2026-06-23 12:00:00.000000

Per-engagement flag that enables the sequential per-subdomain scanner
introduced in Sprint 45. When true, vuln_hunt_node iterates each discovered
subdomain one at a time (passive → sleep → active → sleep → next), preventing
traffic bursts and allowing per-host rate-limit + WAF profiling.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b3d7a91f2e05"
down_revision: Union[str, Sequence[str], None] = "6b96c038171c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "engagements",
        sa.Column(
            "scan_sequential",
            sa.Boolean(),
            nullable=False,
            server_default="false",
            comment="Scan subdomains one-by-one (passive→sleep→active) instead of concurrently",
        ),
    )


def downgrade() -> None:
    op.drop_column("engagements", "scan_sequential")
