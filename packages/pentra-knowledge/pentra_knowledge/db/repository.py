from typing import Any
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_knowledge.db.models import KnowledgeRecordORM
from pentra_shared.types import KnowledgeRecord


def _orm_to_schema(orm: KnowledgeRecordORM) -> KnowledgeRecord:
    """Convert an ORM row into the canonical Pydantic ``KnowledgeRecord``.

    Embedding vectors are not stored in PostgreSQL — they are set to empty
    defaults here and retrieved from Qdrant when needed.
    """
    return KnowledgeRecord(
        id=orm.id,
        source=orm.source,  # type: ignore[arg-type]
        source_id=orm.source_id,
        source_url=orm.source_url,
        ingested_at=orm.ingested_at,
        updated_at=orm.updated_at,
        title=orm.title,
        vuln_class=orm.vuln_class,  # type: ignore[arg-type]
        vuln_subclass=orm.vuln_subclass,
        severity=orm.severity,  # type: ignore[arg-type]
        cvss_score=orm.cvss_score,
        cvss_vector=orm.cvss_vector,
        cve_id=orm.cve_id,
        program=orm.program,
        tech_stack=orm.tech_stack,
        platform_type=orm.platform_type,  # type: ignore[arg-type]
        endpoint_pattern=orm.endpoint_pattern,
        http_method=orm.http_method,
        auth_required=orm.auth_required,
        attack_technique=orm.attack_technique,
        attack_steps=orm.attack_steps,
        payload_pattern=orm.payload_pattern,
        indicators=orm.indicators,
        prerequisites=orm.prerequisites,
        what_tools_missed=orm.what_tools_missed,
        chained_with=orm.chained_with,
        impact=orm.impact,
        impact_category=orm.impact_category,
        bounty_usd=orm.bounty_usd,
        key_insight=orm.key_insight,
        unique_factor=orm.unique_factor,
        pentra_tags=orm.pentra_tags,
        quality_score=orm.quality_score,
        # Vectors not stored in Postgres — return empty; Qdrant is the source
        embedding_dense=[],
        embedding_sparse={},
        embedding_model=orm.embedding_model,
        embedding_version=orm.embedding_version,
    )


class KnowledgeRepository:
    """Data access layer for ``knowledge_records``.

    All methods are async and use SQLAlchemy ORM — no raw SQL.
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get_by_id(self, record_id: UUID) -> KnowledgeRecord | None:
        result = await self._db.execute(
            select(KnowledgeRecordORM).where(KnowledgeRecordORM.id == record_id)
        )
        orm = result.scalar_one_or_none()
        return _orm_to_schema(orm) if orm else None

    async def get_by_source_id(self, source_id: str) -> KnowledgeRecord | None:
        result = await self._db.execute(
            select(KnowledgeRecordORM).where(KnowledgeRecordORM.source_id == source_id)
        )
        orm = result.scalar_one_or_none()
        return _orm_to_schema(orm) if orm else None

    async def get_many_by_ids(self, ids: list[UUID]) -> list[KnowledgeRecord]:
        result = await self._db.execute(
            select(KnowledgeRecordORM).where(KnowledgeRecordORM.id.in_(ids))
        )
        return [_orm_to_schema(row) for row in result.scalars().all()]

    async def create(self, data: dict) -> KnowledgeRecordORM:
        """Insert a new record. ``data`` must match ORM column names."""
        orm = KnowledgeRecordORM(**data)
        self._db.add(orm)
        await self._db.flush()
        await self._db.refresh(orm)
        return orm

    async def mark_embedded(self, record_id: UUID, *, model: str, version: int) -> None:
        """Update the embedding metadata flags after Qdrant indexing."""
        await self._db.execute(
            update(KnowledgeRecordORM)
            .where(KnowledgeRecordORM.id == record_id)
            .values(is_embedded=True, embedding_model=model, embedding_version=version)
        )

    async def list_unembedded(self, limit: int = 100) -> list[KnowledgeRecordORM]:
        """Return ORM rows that have not yet been indexed in Qdrant."""
        result = await self._db.execute(
            select(KnowledgeRecordORM)
            .where(KnowledgeRecordORM.is_embedded.is_(False))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def exists_by_source_id(self, source_id: str) -> bool:
        result = await self._db.execute(
            select(KnowledgeRecordORM.id).where(
                KnowledgeRecordORM.source_id == source_id
            )
        )
        return result.scalar_one_or_none() is not None

    async def update(self, record_id: UUID, data: dict[str, Any]) -> None:
        """Update fields of an existing record by UUID."""
        await self._db.execute(
            update(KnowledgeRecordORM)
            .where(KnowledgeRecordORM.id == record_id)
            .values(**data)
        )

    async def count_all(self) -> int:
        result = await self._db.execute(
            select(func.count(KnowledgeRecordORM.id))
        )
        return result.scalar_one()

    async def count_embedded(self) -> int:
        result = await self._db.execute(
            select(func.count(KnowledgeRecordORM.id)).where(
                KnowledgeRecordORM.is_embedded.is_(True)
            )
        )
        return result.scalar_one()

    async def count_by_field(self, field: str) -> dict[str, int]:
        """Return {value: count} for a text column, ordered by count desc."""
        col = getattr(KnowledgeRecordORM, field)
        rows = await self._db.execute(
            select(col, func.count(KnowledgeRecordORM.id).label("cnt"))
            .group_by(col)
            .order_by(func.count(KnowledgeRecordORM.id).desc())
            .limit(50)
        )
        return {str(row[0]): row[1] for row in rows.all() if row[0] is not None}
