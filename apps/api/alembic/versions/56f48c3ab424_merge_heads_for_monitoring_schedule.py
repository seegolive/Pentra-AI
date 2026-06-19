"""merge_heads_for_monitoring_schedule

Revision ID: 56f48c3ab424
Revises: a28fd25517b3, a9c3f1e82b47
Create Date: 2026-06-19 13:50:43.264771

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '56f48c3ab424'
down_revision: Union[str, Sequence[str], None] = ('a28fd25517b3', 'a9c3f1e82b47')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
