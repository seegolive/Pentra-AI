from typing import Any
from uuid import UUID
import re

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_knowledge.db.models import KnowledgeRecordORM
from pentra_shared.types import KnowledgeRecord

# ---------------------------------------------------------------------------
# Normalisation helpers — the DB stores raw strings (H1 CWE names, scraper
# output) that must be mapped to the strict Pydantic enums before Pydantic
# validation runs.
# ---------------------------------------------------------------------------

# Maps substrings (lower-cased) found in raw vuln_class values → VulnClass enum values.
_VULN_CLASS_MAP: list[tuple[str, str]] = [
    # Access Control
    ("insecure direct object", "idor"),
    ("idor", "idor"),
    ("broken object level", "bola"),
    ("broken function level", "bfla"),
    ("improper authorization", "bfla"),
    ("improper access control", "bfla"),
    ("privilege escalation", "privilege_escalation"),
    # Injection
    ("sql injection", "sqli"),
    ("sqli", "sqli"),
    ("xss) - stored", "xss_stored"),
    ("xss_stored", "xss_stored"),
    ("xss) - dom", "xss_dom"),
    ("xss_dom", "xss_dom"),
    ("xss) - reflected", "xss_reflected"),
    ("xss) - generic", "xss_reflected"),
    ("cross-site scripting", "xss_reflected"),
    ("xss", "xss_reflected"),
    ("mxss", "mxss"),
    ("xml external entity", "xxe"),
    ("xxe", "xxe"),
    ("template injection", "ssti"),
    ("ssti", "ssti"),
    ("command injection", "cmdi"),
    ("cmdi", "cmdi"),
    ("code injection", "rce"),
    # Auth
    ("authentication bypass", "auth_bypass"),
    ("improper authentication", "auth_bypass"),
    ("auth bypass", "auth_bypass"),
    ("auth_bypass", "auth_bypass"),
    ("session", "session"),
    ("jwt", "jwt_issues"),
    ("oauth", "oauth_misconfig"),
    # Server-side
    ("server-side request forgery", "ssrf"),
    ("ssrf", "ssrf"),
    ("path traversal", "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("remote code execution", "rce"),
    ("deserialization", "deserialization"),
    # Business Logic
    ("race condition", "race_condition"),
    ("mass assignment", "mass_assignment"),
    ("parameter pollution", "param_pollution"),
    ("param pollution", "param_pollution"),
    ("business logic", "workflow_bypass"),
    ("workflow", "workflow_bypass"),
    ("csrf", "workflow_bypass"),
    ("cross-site request forgery", "workflow_bypass"),
    # Info Disclosure
    ("api key", "api_key_leak"),
    ("credential", "api_key_leak"),
    ("cleartext", "api_key_leak"),
    ("insufficiently protected", "api_key_leak"),
    ("insecure storage", "api_key_leak"),
    ("pii", "pii_exposure"),
    ("information disclosure", "pii_exposure"),
    ("information exposure", "pii_exposure"),
    ("exposure of data", "pii_exposure"),
    ("debug", "debug_info"),
    ("insufficient logging", "debug_info"),
    ("source code", "source_code"),
    # Infrastructure
    ("subdomain takeover", "subdomain_takeover"),
    ("cache poisoning", "cache_poisoning"),
    ("cloud", "cloud_misconfig"),
    ("misconfiguration", "cloud_misconfig"),
    ("cors", "cors"),
    # GraphQL
    ("introspection", "introspection"),
    ("query depth", "query_depth"),
    ("batch", "batch_abuse"),
    ("field suggestion", "field_suggestion"),
    # Availability
    ("denial of service", "dos"),
    ("uncontrolled resource", "dos"),
    ("allocation of resources", "dos"),
    ("open redirect", "open_redirect"),
    # Memory Safety
    ("heap overflow", "buffer_overflow"),
    ("stack overflow", "buffer_overflow"),
    ("buffer overflow", "buffer_overflow"),
    ("buffer over-read", "buffer_overflow"),
    ("out-of-bounds", "buffer_overflow"),
    ("memory corruption", "buffer_overflow"),
    ("use after free", "use_after_free"),
    ("double free", "use_after_free"),
    ("integer overflow", "integer_overflow"),
    # Crypto
    ("weak algo", "weak_algo"),
    ("cryptographic", "weak_algo"),
    ("padding oracle", "padding_oracle"),
    ("timing attack", "timing_attack"),
]

# Valid VulnClass enum values (string form)
_VALID_VULN_CLASSES = {
    "idor", "bola", "bfla", "privilege_escalation",
    "sqli", "xss_stored", "xss_reflected", "xss_dom", "mxss",
    "xxe", "ssti", "cmdi",
    "auth_bypass", "session", "oauth_misconfig", "jwt_issues",
    "ssrf", "path_traversal", "rce", "deserialization",
    "race_condition", "mass_assignment", "param_pollution", "workflow_bypass",
    "api_key_leak", "pii_exposure", "debug_info", "source_code",
    "subdomain_takeover", "cache_poisoning", "cloud_misconfig", "cors",
    "introspection", "query_depth", "batch_abuse", "field_suggestion",
    "dos", "open_redirect",
    "buffer_overflow", "use_after_free", "integer_overflow",
    "weak_algo", "padding_oracle", "timing_attack",
    "other",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

_VALID_SOURCES = {"hackerone", "bugcrowd", "intigriti", "writeup", "pentra_finding", "custom"}
_SOURCE_MAP: dict[str, str] = {
    "bughunter": "hackerone",
    "h1": "hackerone",
    "hackerone_graphql": "hackerone",
    "bc": "bugcrowd",
    "intigriti": "intigriti",
}


def _normalize_source(raw: str | None) -> str:
    """Map any source string to a valid KnowledgeSource literal."""
    s = (raw or "").lower().strip()
    if s in _VALID_SOURCES:
        return s
    return _SOURCE_MAP.get(s, "custom")


def _normalize_vuln_class(raw: str | None) -> str:
    """Map raw H1/LLM vuln_class strings to a valid VulnClass enum value."""
    if not raw:
        return "other"
    # Already a valid enum value
    if raw.lower() in _VALID_VULN_CLASSES:
        return raw.lower()
    raw_lower = raw.lower()
    for substring, mapped in _VULN_CLASS_MAP:
        if substring in raw_lower:
            return mapped
    return "other"


def _normalize_severity(raw: str | None) -> str:
    """Map any severity string to a valid Severity enum value."""
    s = (raw or "").lower().strip()
    return s if s in _VALID_SEVERITIES else "info"


def _ensure_list(raw: Any) -> list:
    """Ensure a JSONB field value is always a list.

    The LLM sometimes returns a plain string instead of a single-element list,
    and older records may have been stored that way.  Always return a list.
    """
    if not raw:
        return []
    if isinstance(raw, str):
        return [raw.strip()] if raw.strip() else []
    if isinstance(raw, list):
        return raw
    return []


def _orm_to_schema(orm: KnowledgeRecordORM) -> KnowledgeRecord:
    """Convert an ORM row into the canonical Pydantic ``KnowledgeRecord``.

    Embedding vectors are not stored in PostgreSQL — they are set to empty
    defaults here and retrieved from Qdrant when needed.
    """
    return KnowledgeRecord(
        id=orm.id,
        source=_normalize_source(orm.source),  # type: ignore[arg-type]
        source_id=orm.source_id,
        source_url=orm.source_url,
        ingested_at=orm.ingested_at,
        updated_at=orm.updated_at,
        title=orm.title,
        vuln_class=_normalize_vuln_class(orm.vuln_class),  # type: ignore[arg-type]
        vuln_subclass=orm.vuln_subclass,
        severity=_normalize_severity(orm.severity),  # type: ignore[arg-type]
        cvss_score=orm.cvss_score,
        cvss_vector=orm.cvss_vector,
        cve_id=orm.cve_id,
        program=orm.program,
        tech_stack=_ensure_list(orm.tech_stack),
        platform_type=_ensure_list(orm.platform_type),  # type: ignore[arg-type]
        endpoint_pattern=orm.endpoint_pattern,
        http_method=_ensure_list(orm.http_method),
        auth_required=orm.auth_required,
        attack_technique=orm.attack_technique,
        attack_steps=_ensure_list(orm.attack_steps),
        payload_pattern=orm.payload_pattern,
        indicators=_ensure_list(orm.indicators),
        prerequisites=_ensure_list(orm.prerequisites),
        what_tools_missed=orm.what_tools_missed,
        chained_with=_ensure_list(orm.chained_with),
        impact=orm.impact,
        impact_category=_ensure_list(orm.impact_category),
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

    async def reset_embeddings(self) -> int:
        """Mark all embedded records as unembedded so they will be re-processed.

        Used when switching embedding models (e.g. bge-m3).  Returns the number
        of records that were reset.
        """
        result = await self._db.execute(
            update(KnowledgeRecordORM)
            .where(KnowledgeRecordORM.is_embedded.is_(True))
            .values(is_embedded=False)
        )
        await self._db.commit()
        return result.rowcount  # type: ignore[return-value]

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

    async def full_text_search(
        self,
        query: str,
        *,
        vuln_class: list[str] | None = None,
        severity: list[str] | None = None,
        tech_stack: list[str] | None = None,
        limit: int = 10,
    ) -> list[KnowledgeRecord]:
        """PostgreSQL full-text fallback for when Qdrant has no embedded vectors.

        Used automatically by hybrid_search() when Qdrant returns 0 results
        (cold-start, after kb:reembed, or before the worker embeds records).

        Searches title, key_insight, and attack_technique using ILIKE so it
        works without any GIN index (though adding one would speed it up).
        Deduplicates keywords and caps at 8 terms to keep query fast.

        Returns records ordered by quality_score desc, then ingested_at desc.
        """
        # Extract alphanumeric keywords ≥3 chars, deduplicate, cap at 8
        words = list(dict.fromkeys(re.findall(r"[a-zA-Z0-9]{3,}", query)))[:8]

        if not words:
            # Filter-only mode: apply metadata filters, order by quality
            stmt = select(KnowledgeRecordORM)
            if vuln_class:
                stmt = stmt.where(KnowledgeRecordORM.vuln_class.in_(vuln_class))
            if severity:
                stmt = stmt.where(KnowledgeRecordORM.severity.in_(severity))
            stmt = stmt.order_by(
                KnowledgeRecordORM.quality_score.desc(),
                KnowledgeRecordORM.ingested_at.desc(),
            ).limit(limit)
            result = await self._db.execute(stmt)
            return [_orm_to_schema(row) for row in result.scalars().all()]

        # Each word must appear in at least one of the key text columns
        word_conditions = [
            or_(
                KnowledgeRecordORM.title.ilike(f"%{w}%"),
                KnowledgeRecordORM.key_insight.ilike(f"%{w}%"),
                KnowledgeRecordORM.attack_technique.ilike(f"%{w}%"),
            )
            for w in words
        ]

        # ANY word matches (OR semantics) — better recall than AND for short KB queries
        stmt = select(KnowledgeRecordORM).where(or_(*word_conditions))

        if vuln_class:
            stmt = stmt.where(KnowledgeRecordORM.vuln_class.in_(vuln_class))
        if severity:
            stmt = stmt.where(KnowledgeRecordORM.severity.in_(severity))
        if tech_stack:
            # Cast JSONB array to text and use ILIKE — avoids jsonpath type casting issues
            from sqlalchemy import cast
            from sqlalchemy.dialects.postgresql import TEXT
            for tech in tech_stack[:3]:
                stmt = stmt.where(
                    cast(KnowledgeRecordORM.tech_stack, TEXT).ilike(f"%{re.escape(tech)}%")
                )

        stmt = stmt.order_by(
            KnowledgeRecordORM.quality_score.desc(),
            KnowledgeRecordORM.ingested_at.desc(),
        ).limit(limit)

        result = await self._db.execute(stmt)
        return [_orm_to_schema(row) for row in result.scalars().all()]

