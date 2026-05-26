"""add_quality_score_to_knowledge_records

Revision ID: 5270364c5870
Revises: 1861c1b0307a
Create Date: 2026-05-25 15:00:54.549032

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '5270364c5870'
down_revision: Union[str, Sequence[str], None] = '1861c1b0307a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create knowledge_records table (was incorrectly dropped by aa834f32e5ed).
    Includes quality_score column added in Sprint 8.3."""
    op.create_table(
        'knowledge_records',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('source', sa.VARCHAR(length=50), nullable=False),
        sa.Column('source_id', sa.VARCHAR(length=200), nullable=False),
        sa.Column('source_url', sa.TEXT(), nullable=True),
        sa.Column('ingested_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('title', sa.VARCHAR(length=500), nullable=False),
        sa.Column('vuln_class', sa.VARCHAR(length=50), nullable=False),
        sa.Column('vuln_subclass', sa.VARCHAR(length=200), server_default=sa.text("''::character varying"), nullable=False),
        sa.Column('severity', sa.VARCHAR(length=20), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.VARCHAR(length=200), nullable=True),
        sa.Column('cve_id', sa.VARCHAR(length=50), nullable=True),
        sa.Column('program', sa.VARCHAR(length=200), nullable=False),
        sa.Column('tech_stack', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('platform_type', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('endpoint_pattern', sa.VARCHAR(length=500), server_default=sa.text("''::character varying"), nullable=False),
        sa.Column('http_method', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('auth_required', sa.BOOLEAN(), server_default=sa.text('true'), nullable=False),
        sa.Column('attack_technique', sa.TEXT(), server_default=sa.text("''::text"), nullable=False),
        sa.Column('attack_steps', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('payload_pattern', sa.TEXT(), nullable=True),
        sa.Column('indicators', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('prerequisites', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('what_tools_missed', sa.TEXT(), nullable=True),
        sa.Column('chained_with', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('impact', sa.TEXT(), server_default=sa.text("''::text"), nullable=False),
        sa.Column('impact_category', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('bounty_usd', sa.INTEGER(), nullable=True),
        sa.Column('key_insight', sa.TEXT(), server_default=sa.text("''::text"), nullable=False),
        sa.Column('unique_factor', sa.TEXT(), server_default=sa.text("''::text"), nullable=False),
        sa.Column('pentra_tags', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('quality_score', sa.Float(), server_default=sa.text('0.0'), nullable=False, comment='Completeness score 0.0-1.0 -- used to boost retrieval rank'),
        sa.Column('embedding_model', sa.VARCHAR(length=50), server_default=sa.text("'bge-m3'::character varying"), nullable=False),
        sa.Column('embedding_version', sa.INTEGER(), server_default=sa.text('1'), nullable=False),
        sa.Column('is_embedded', sa.BOOLEAN(), server_default=sa.text('false'), nullable=False),
        sa.Column('full_text', sa.TEXT(), nullable=True),
        sa.PrimaryKeyConstraint('id', name='knowledge_records_pkey'),
    )
    # Standard indexes
    op.create_index('idx_kr_vuln_class', 'knowledge_records', ['vuln_class'], unique=False)
    op.create_index('idx_kr_tech_stack_gin', 'knowledge_records', ['tech_stack'], unique=False, postgresql_using='gin')
    op.create_index('idx_kr_source_id', 'knowledge_records', ['source_id'], unique=True)
    op.create_index('idx_kr_severity', 'knowledge_records', ['severity'], unique=False)
    op.create_index('idx_kr_program', 'knowledge_records', ['program'], unique=False)
    op.create_index('idx_kr_pentra_tags_gin', 'knowledge_records', ['pentra_tags'], unique=False, postgresql_using='gin')
    op.create_index('idx_kr_is_embedded', 'knowledge_records', ['is_embedded'], unique=False)
    op.create_index(
        'idx_kr_fts',
        'knowledge_records',
        [sa.literal_column(
            "to_tsvector('english'::regconfig, "
            "(((COALESCE(title, ''::character varying)::text || ' '::text) "
            "|| COALESCE(attack_technique, ''::text)) || ' '::text) "
            "|| COALESCE(key_insight, ''::text))"
        )],
        unique=False,
        postgresql_using='gin',
    )
    op.create_index('ix_knowledge_records_quality_score', 'knowledge_records', ['quality_score'], unique=False)


def downgrade() -> None:
    """Drop knowledge_records table."""
    op.drop_index('ix_knowledge_records_quality_score', table_name='knowledge_records')
    op.drop_index('idx_kr_fts', table_name='knowledge_records')
    op.drop_index('idx_kr_is_embedded', table_name='knowledge_records')
    op.drop_index('idx_kr_pentra_tags_gin', table_name='knowledge_records')
    op.drop_index('idx_kr_program', table_name='knowledge_records')
    op.drop_index('idx_kr_severity', table_name='knowledge_records')
    op.drop_index('idx_kr_source_id', table_name='knowledge_records')
    op.drop_index('idx_kr_tech_stack_gin', table_name='knowledge_records')
    op.drop_index('idx_kr_vuln_class', table_name='knowledge_records')
    op.drop_table('knowledge_records')
