"""add_monitoring_schedule_to_engagements

Revision ID: 6b96c038171c
Revises: 56f48c3ab424
Create Date: 2026-06-19 13:50:50.125644

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '6b96c038171c'
down_revision: Union[str, Sequence[str], None] = '56f48c3ab424'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add monitoring schedule columns to engagements table."""
    op.add_column('engagements', sa.Column(
        'monitoring_enabled', sa.Boolean(), nullable=False,
        server_default=sa.text('false'),
        comment='Whether continuous monitoring is enabled for this engagement',
    ))
    op.add_column('engagements', sa.Column(
        'monitoring_interval_hours', sa.Integer(), nullable=False,
        server_default=sa.text('24'),
        comment='How often to run recon snapshot (hours)',
    ))


def downgrade() -> None:
    """Remove monitoring schedule columns from engagements table."""
    op.drop_column('engagements', 'monitoring_interval_hours')
    op.drop_column('engagements', 'monitoring_enabled')
