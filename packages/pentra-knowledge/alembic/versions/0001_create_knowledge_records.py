"""Create knowledge_records table

Revision ID: 0001
Revises: 
Create Date: 2026-05-21

Columns follow the KnowledgeRecordORM model exactly.
JSONB is used for all list fields (tech_stack, attack_steps, indicators, etc.)
so PostgreSQL GIN indexes can accelerate array containment queries.

Indexes created:
    - idx_kr_source_id          UNIQUE — deduplication gate
    - idx_kr_vuln_class         B-tree — filter by vulnerability class
    - idx_kr_severity           B-tree — filter by severity
    - idx_kr_program            B-tree — filter by bug bounty program
    - idx_kr_is_embedded        B-tree — queue for Qdrant embedding worker
    - idx_kr_tech_stack_gin     GIN    — fast array @> / ?| queries on tech_stack
    - idx_kr_pentra_tags_gin    GIN    — fast tag lookups
    - idx_kr_fts                GIN (tsvector) — PostgreSQL full-text search
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "knowledge_records",
        # ── Identity ──────────────────────────────────────────────────────
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("source_id", sa.String(200), nullable=False),
        sa.Column("source_url", sa.Text, nullable=True),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # ── Classification ─────────────────────────────────────────────────
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("vuln_class", sa.String(50), nullable=False),
        sa.Column("vuln_subclass", sa.String(200), nullable=False, server_default=""),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("cvss_vector", sa.String(200), nullable=True),
        sa.Column("cve_id", sa.String(50), nullable=True),
        # ── Target Context ─────────────────────────────────────────────────
        sa.Column("program", sa.String(200), nullable=False),
        sa.Column("tech_stack", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("platform_type", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("endpoint_pattern", sa.String(500), nullable=False, server_default=""),
        sa.Column("http_method", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("auth_required", sa.Boolean, nullable=False, server_default="true"),
        # ── Attack Intelligence ────────────────────────────────────────────
        sa.Column("attack_technique", sa.Text, nullable=False, server_default=""),
        sa.Column("attack_steps", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("payload_pattern", sa.Text, nullable=True),
        sa.Column("indicators", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("prerequisites", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("what_tools_missed", sa.Text, nullable=True),
        # ── Chain & Impact ─────────────────────────────────────────────────
        sa.Column("chained_with", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("impact", sa.Text, nullable=False, server_default=""),
        sa.Column("impact_category", JSONB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("bounty_usd", sa.Integer, nullable=True),
        # ── Learning ──────────────────────────────────────────────────────
        sa.Column("key_insight", sa.Text, nullable=False, server_default=""),
        sa.Column("unique_factor", sa.Text, nullable=False, server_default=""),
        sa.Column("pentra_tags", JSONB, nullable=False, server_default=sa.text("'[]'")),
        # ── Embedding Metadata ─────────────────────────────────────────────
        sa.Column("embedding_model", sa.String(50), nullable=False, server_default="bge-m3"),
        sa.Column("embedding_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("is_embedded", sa.Boolean, nullable=False, server_default="false"),
        # ── Full-text Cache ────────────────────────────────────────────────
        sa.Column("full_text", sa.Text, nullable=True),
    )

    # ── Scalar indexes ─────────────────────────────────────────────────────
    op.create_index(
        "idx_kr_source_id",
        "knowledge_records",
        ["source_id"],
        unique=True,
    )
    op.create_index("idx_kr_vuln_class", "knowledge_records", ["vuln_class"])
    op.create_index("idx_kr_severity", "knowledge_records", ["severity"])
    op.create_index("idx_kr_program", "knowledge_records", ["program"])
    op.create_index("idx_kr_is_embedded", "knowledge_records", ["is_embedded"])

    # ── GIN indexes for JSONB array queries ────────────────────────────────
    op.create_index(
        "idx_kr_tech_stack_gin",
        "knowledge_records",
        ["tech_stack"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_kr_pentra_tags_gin",
        "knowledge_records",
        ["pentra_tags"],
        postgresql_using="gin",
    )

    # ── Full-text search index ─────────────────────────────────────────────
    # Combines title + attack_technique + key_insight into a searchable tsvector
    op.execute(
        """
        CREATE INDEX idx_kr_fts ON knowledge_records
        USING gin (
            to_tsvector(
                'english',
                coalesce(title, '') || ' ' ||
                coalesce(attack_technique, '') || ' ' ||
                coalesce(key_insight, '')
            )
        )
        """
    )


def downgrade() -> None:
    op.drop_index("idx_kr_fts", table_name="knowledge_records")
    op.drop_index("idx_kr_pentra_tags_gin", table_name="knowledge_records")
    op.drop_index("idx_kr_tech_stack_gin", table_name="knowledge_records")
    op.drop_index("idx_kr_is_embedded", table_name="knowledge_records")
    op.drop_index("idx_kr_program", table_name="knowledge_records")
    op.drop_index("idx_kr_severity", table_name="knowledge_records")
    op.drop_index("idx_kr_vuln_class", table_name="knowledge_records")
    op.drop_index("idx_kr_source_id", table_name="knowledge_records")
    op.drop_table("knowledge_records")
