"""add_chains_to_findings

Revision ID: a28fd25517b3
Revises: c8551619e47f
Create Date: 2026-06-03 15:45:17.044322

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a28fd25517b3'
down_revision: Union[str, Sequence[str], None] = 'c8551619e47f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add chains JSONB column to findings table."""
    op.add_column(
        'findings',
        sa.Column(
            'chains',
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment='Attack chains this finding participates in, set by VulnerabilityCorrelator',
        ),
    )


def downgrade() -> None:
    """Remove chains column from findings table."""
    op.drop_column('findings', 'chains')
