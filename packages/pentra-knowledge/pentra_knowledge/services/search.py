"""Hybrid search service — the main RAG entry point for Pentra AI.

Search strategy:
    1. Embed the query with BGE-M3 (dense + sparse)
    2. Run Qdrant hybrid search (dense cosine + sparse lexical via stable hash indices)
    3. Filter by metadata (vuln_class, severity, tech_stack, source)
    4. Reciprocal Rank Fusion to merge dense + sparse result lists
    5. Fetch full records from PostgreSQL by the returned IDs
    6. PostgreSQL full-text fallback when Qdrant has 0 vectors (cold-start)
    7. Return ordered list[KnowledgeRecord] ready for LangGraph context injection

RAG quality guarantees:
    - Sparse indices are stable: hash(token) % 2^20, never sequential range()
    - score_threshold=0.0 on dense search — RRF + quality_boost do ranking
    - PostgreSQL ilike fallback prevents empty results during cold-start
    - format_kb_compact() trims records to title+insight+technique (no raw_text dump)
"""

import re
from uuid import UUID

from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qdrant_models
from qdrant_client.models import (
    Distance,
    SparseVector,
    SparseVectorParams,
    VectorParams,
)
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_knowledge.config import get_settings
from pentra_knowledge.db.repository import KnowledgeRepository
from pentra_knowledge.services.embedding import EmbeddingResult, embed, sparse_to_qdrant
from pentra_shared.types import KnowledgeRecord


def _get_qdrant_client() -> AsyncQdrantClient:
    settings = get_settings()
    return AsyncQdrantClient(url=settings.qdrant_url)


async def ensure_collection_exists() -> None:
    """Create the Qdrant knowledge collection if it does not already exist.

    Call once at application startup (or migration time).
    Collection uses:
    - ``dense``  — 1024-dim cosine (BGE-M3 dense output)
    - ``sparse`` — SPLADE-style sparse weights for lexical matching
    """
    settings = get_settings()
    client = _get_qdrant_client()

    existing = await client.get_collections()
    names = {c.name for c in existing.collections}

    if settings.qdrant_collection_knowledge not in names:
        await client.create_collection(
            collection_name=settings.qdrant_collection_knowledge,
            vectors_config={
                "dense": VectorParams(
                    size=settings.qdrant_dense_dim,
                    distance=Distance.COSINE,
                )
            },
            sparse_vectors_config={
                "sparse": SparseVectorParams()
            },
        )


def _build_qdrant_filter(
    vuln_class: list[str] | None,
    severity: list[str] | None,
    tech_stack: list[str] | None,
    source: list[str] | None,
    min_quality_score: float | None = None,
) -> qdrant_models.Filter | None:
    """Translate search filter params into a Qdrant payload filter."""
    conditions: list[qdrant_models.Condition] = []

    if vuln_class:
        conditions.append(
            qdrant_models.FieldCondition(
                key="vuln_class",
                match=qdrant_models.MatchAny(any=vuln_class),
            )
        )
    if severity:
        conditions.append(
            qdrant_models.FieldCondition(
                key="severity",
                match=qdrant_models.MatchAny(any=severity),
            )
        )
    if tech_stack:
        # Match records that contain ANY of the requested stack entries
        conditions.append(
            qdrant_models.FieldCondition(
                key="tech_stack",
                match=qdrant_models.MatchAny(any=tech_stack),
            )
        )
    if source:
        conditions.append(
            qdrant_models.FieldCondition(
                key="source",
                match=qdrant_models.MatchAny(any=source),
            )
        )

    if min_quality_score is not None and min_quality_score > 0.0:
        conditions.append(
            qdrant_models.FieldCondition(
                key="quality_score",
                range=qdrant_models.Range(gte=min_quality_score),
            )
        )

    if not conditions:
        return None

    return qdrant_models.Filter(must=conditions)


async def hybrid_search(
    query: str,
    db: AsyncSession,
    *,
    vuln_class: list[str] | None = None,
    severity: list[str] | None = None,
    tech_stack: list[str] | None = None,
    source: list[str] | None = None,
    top_k: int | None = None,
    min_quality_score: float | None = None,
    quality_boost: float = 0.1,
) -> list[KnowledgeRecord]:
    """Search the knowledge base using BGE-M3 hybrid retrieval.

    Args:
        query:             Natural-language search string (agent hypothesis or user query).
        db:                Active async SQLAlchemy session (used to fetch full records).
        vuln_class:        Filter by one or more VulnClass values (e.g. ['idor', 'ssrf']).
        severity:          Filter by severity (e.g. ['critical', 'high']).
        tech_stack:        Filter by tech stack entries (e.g. ['Ruby on Rails']).
        source:            Filter by source system (e.g. ['hackerone']).
        top_k:             Number of results to return. Capped by settings.knowledge_search_max_top_k.
        min_quality_score: Exclude records below this quality threshold (0.0–1.0).
        quality_boost:     Weight applied to quality_score when re-ranking (default 0.1).

    Returns:
        Ordered list of KnowledgeRecord, highest relevance first.
        Records are populated from PostgreSQL; embedding vectors are not included.
    """
    settings = get_settings()
    client = _get_qdrant_client()
    repo = KnowledgeRepository(db)

    # Clamp top_k
    effective_top_k = min(
        top_k or settings.knowledge_search_default_top_k,
        settings.knowledge_search_max_top_k,
    )

    # 1. Embed the query
    embedding = await embed(query)

    # 2. Build optional payload filter
    payload_filter = _build_qdrant_filter(vuln_class, severity, tech_stack, source, min_quality_score)

    # 3. Dense vector search — score_threshold=0.0 so RRF does the ranking.
    # Previously 0.60 blocked most results from under-enriched records.
    dense_response = await client.query_points(
        collection_name=settings.qdrant_collection_knowledge,
        query=embedding.dense,
        using="dense",
        query_filter=payload_filter,
        limit=effective_top_k,
        score_threshold=0.0,
        with_payload=False,  # IDs only — full data fetched from Postgres
    )
    dense_results = dense_response.points

    # 4. Sparse vector search — uses stable hash indices via sparse_to_qdrant().
    # Previously used list(range(len(sparse))) which mapped tokens to random
    # sequential indices, making lexical matching meaningless.
    sparse_indices, sparse_values = sparse_to_qdrant(embedding.sparse)

    sparse_response = await client.query_points(
        collection_name=settings.qdrant_collection_knowledge,
        query=SparseVector(indices=sparse_indices, values=sparse_values),
        using="sparse",
        query_filter=payload_filter,
        limit=effective_top_k,
        score_threshold=0.0,
        with_payload=False,
    )
    sparse_results = sparse_response.points

    # 5. Reciprocal Rank Fusion — merge dense + sparse result lists
    rrf_scores: dict[str, float] = {}
    rrf_k = 60  # standard RRF constant

    for rank, hit in enumerate(dense_results):
        point_id = str(hit.id)
        rrf_scores[point_id] = rrf_scores.get(point_id, 0.0) + 1.0 / (rrf_k + rank + 1)

    for rank, hit in enumerate(sparse_results):
        point_id = str(hit.id)
        rrf_scores[point_id] = rrf_scores.get(point_id, 0.0) + 1.0 / (rrf_k + rank + 1)

    # 6. Sort by merged RRF score, take top_k
    sorted_ids = sorted(rrf_scores, key=lambda k: rrf_scores[k], reverse=True)[:effective_top_k]

    # NOTE: quality_boost re-ranking happens after DB fetch (see below)

    if not sorted_ids:
        # Cold-start fallback: Qdrant has 0 embedded vectors → use PostgreSQL.
        # This happens when is_embedded=False for all records (e.g. after
        # kb:reembed or fresh install before the worker runs embed_pending_records).
        return await repo.full_text_search(
            query,
            vuln_class=vuln_class,
            severity=severity,
            tech_stack=tech_stack,
            limit=effective_top_k,
        )

    # 7. Fetch full records from PostgreSQL
    uuid_ids = [UUID(sid) for sid in sorted_ids]
    records = await repo.get_many_by_ids(uuid_ids)

    # Restore the RRF order (get_many_by_ids may return in any order)
    id_to_record = {str(r.id): r for r in records}
    ordered = [id_to_record[sid] for sid in sorted_ids if sid in id_to_record]

    if quality_boost > 0.0:
        # Re-rank: final_score = rrf_score + quality_boost * quality_score
        ordered.sort(
            key=lambda r: rrf_scores.get(str(r.id), 0.0) + quality_boost * r.quality_score,
            reverse=True,
        )

    return ordered


async def upsert_to_qdrant(
    record_id: UUID,
    dense: list[float],
    sparse: dict[str, float],
    payload: dict,
) -> None:
    """Insert or update a single record's vectors in Qdrant.

    ``payload`` should contain the filterable metadata fields:
    vuln_class, severity, tech_stack, source, program.
    """
    settings = get_settings()
    client = _get_qdrant_client()

    # Use stable hash indices — sequential range() was broken (wrong token→dim mapping)
    sparse_indices, sparse_values = sparse_to_qdrant(sparse)

    await client.upsert(
        collection_name=settings.qdrant_collection_knowledge,
        points=[
            qdrant_models.PointStruct(
                id=str(record_id),
                vector={
                    "dense": dense,
                    "sparse": SparseVector(
                        indices=sparse_indices,
                        values=sparse_values,
                    ),
                },
                payload=payload,
            )
        ],
    )


async def upsert_batch_to_qdrant(
    records: list[tuple[UUID, EmbeddingResult, dict]],
    batch_size: int = 100,
) -> int:
    """Batch-upsert vectors into Qdrant, processing in windows of ``batch_size``.

    Args:
        records:    List of (record_id, embedding_result, payload_dict) tuples.
                    ``payload_dict`` should contain filterable metadata:
                    vuln_class, severity, tech_stack, source, program, quality_score.
        batch_size: How many points to upsert per Qdrant call.

    Returns:
        Total number of records upserted.
    """
    settings = get_settings()
    client = _get_qdrant_client()
    total = 0

    for i in range(0, len(records), batch_size):
        window = records[i : i + batch_size]
        points = []
        for record_id, emb, payload in window:
            sparse_indices, sparse_values = sparse_to_qdrant(emb.sparse)
            points.append(
                qdrant_models.PointStruct(
                    id=str(record_id),
                    vector={
                        "dense": emb.dense,
                        "sparse": SparseVector(
                            indices=sparse_indices,
                            values=sparse_values,
                        ),
                    },
                    payload=payload,
                )
            )
        await client.upsert(
            collection_name=settings.qdrant_collection_knowledge,
            points=points,
        )
        total += len(points)

    return total


def format_kb_compact(
    records: "list[KnowledgeRecord | dict]",
    max_records: int = 8,
) -> str:
    """Compact KB context string safe to inject into LLM prompts.

    Extracts only title, vuln_class, severity, key_insight, and attack_technique.
    Hard-truncates each field to prevent context-window overflow.
    A full json.dumps() of 5 records can easily be 40-80 KB; this keeps
    the block under ~2 KB regardless of record size.

    Args:
        records:     List of KnowledgeRecord (Pydantic) or plain dicts.
        max_records: Upper bound on included records (default 8).

    Returns:
        Multi-line string, one block per record, or a placeholder if empty.
    """
    if not records:
        return "(no matching historical patterns found in knowledge base)"

    blocks = []
    for r in list(records)[:max_records]:
        d = r if isinstance(r, dict) else r.model_dump()

        vc       = (d.get("vuln_class") or "?").upper()
        sev      = (d.get("severity") or "?").upper()
        title    = (d.get("title") or "?")[:80]
        program  = (d.get("program") or "").strip()

        # key_insight and attack_technique carry the real intelligence
        insight   = (d.get("key_insight") or "").strip()
        technique = (d.get("attack_technique") or d.get("technique") or "").strip()
        payload_pat = (d.get("payload_pattern") or "").strip()

        # Skip placeholder values left by extraction pipeline
        if insight in ("---", ""):   insight = ""
        if technique in ("---", ""): technique = ""

        block = f"[{vc}|{sev}] {title}"
        if program and program not in ("manual", ""):
            block += f"  (via {program})"
        if insight:
            block += f"\n  Insight: {insight[:200]}"
        if technique:
            block += f"\n  Technique: {technique[:200]}"
        if payload_pat:
            block += f"\n  Payload: {payload_pat[:120]}"

        blocks.append(block)

    return "\n\n".join(blocks)

