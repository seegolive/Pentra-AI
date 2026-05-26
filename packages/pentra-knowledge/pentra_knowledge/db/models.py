from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pentra_knowledge.db.base import Base


class KnowledgeRecordORM(Base):
    """SQLAlchemy ORM model for the ``knowledge_records`` table.

    Stores structured metadata and full text in PostgreSQL.
    Dense + sparse embedding vectors are stored separately in Qdrant,
    referenced by the same ``id``.

    Relationship to Pydantic schema:
        ``pentra_shared.types.KnowledgeRecord`` is the canonical type used
        across the system. This ORM model is only used at the DB layer;
        ``KnowledgeRepository`` converts between the two.
    """

    __tablename__ = "knowledge_records"

    # ── Identity ─────────────────────────────────────────────────────────
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    source_id: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        unique=True,
        index=True,
        comment="Original report ID in the source system",
    )
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # ── Vulnerability Classification ──────────────────────────────────────
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    vuln_class: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    vuln_subclass: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # ── Target Context ────────────────────────────────────────────────────
    program: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    tech_stack: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="e.g. ['Ruby on Rails', 'PostgreSQL']",
    )
    platform_type: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="e.g. ['web', 'api']",
    )
    endpoint_pattern: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        default="",
        comment="Generalised URL pattern, e.g. /api/v{n}/users/{id}",
    )
    http_method: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    auth_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # ── Attack Intelligence ───────────────────────────────────────────────
    attack_technique: Mapped[str] = mapped_column(Text, nullable=False, default="")
    attack_steps: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    payload_pattern: Mapped[str | None] = mapped_column(Text, nullable=True)
    indicators: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    prerequisites: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    what_tools_missed: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Chain & Impact ────────────────────────────────────────────────────
    chained_with: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    impact: Mapped[str] = mapped_column(Text, nullable=False, default="")
    impact_category: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    bounty_usd: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── Learning ──────────────────────────────────────────────────────────
    key_insight: Mapped[str] = mapped_column(Text, nullable=False, default="")
    unique_factor: Mapped[str] = mapped_column(Text, nullable=False, default="")
    pentra_tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    # ── Quality Scoring ───────────────────────────────────────────────────
    quality_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        index=True,
        comment="Completeness score 0.0–1.0 — used to boost retrieval rank",
    )

    # ── Embedding Metadata (vectors live in Qdrant, not here) ─────────────
    embedding_model: Mapped[str] = mapped_column(
        String(50), nullable=False, default="bge-m3"
    )
    embedding_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_embedded: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="True once the record has been embedded and indexed in Qdrant",
    )

    # ── Full-text Cache ───────────────────────────────────────────────────
    full_text: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Concatenated text used to build the BGE-M3 embedding",
    )
