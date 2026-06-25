"""add_scan_preset_to_engagements

Revision ID: bcd8b0015e73
Revises: c4e8a21b7f06
Create Date: 2026-06-25 12:36:36.369783

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'bcd8b0015e73'
down_revision: Union[str, Sequence[str], None] = 'c4e8a21b7f06'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'engagements',
        sa.Column(
            'scan_preset',
            sa.String(length=50),
            nullable=False,
            server_default='fast',
            comment='Scan preset name (full/fast/stealth/quick/authenticated/pentra-ft)',
        ),
    )


def downgrade() -> None:
    op.drop_column('engagements', 'scan_preset')
