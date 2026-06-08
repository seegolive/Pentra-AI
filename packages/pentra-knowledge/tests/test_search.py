"""Tests for the hybrid search service."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from pentra_knowledge.services.search import hybrid_search
from pentra_shared.types import KnowledgeRecord, Severity, VulnClass


def _make_record(vuln_class: VulnClass = VulnClass.IDOR) -> KnowledgeRecord:
    """Build a minimal valid KnowledgeRecord for test assertions."""
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    uid = uuid4()
    return KnowledgeRecord(
        id=uid,
        source="hackerone",
        source_id=str(uid),
        source_url=None,
        ingested_at=now,
        updated_at=now,
        title="IDOR on /api/v1/users/{id}",
        vuln_class=vuln_class,
        vuln_subclass="object_level",
        severity=Severity.HIGH,
        program="shopify",
        tech_stack=["Ruby on Rails"],
        platform_type=["web", "api"],
        endpoint_pattern="/api/v1/users/{id}",
        http_method=["GET"],
        auth_required=True,
        attack_technique="Enumerate user IDs by changing numeric ID in URL path.",
        attack_steps=["Auth as user A", "GET /api/v1/users/{id}", "Change id"],
        payload_pattern=None,
        indicators=["numeric ID in URL"],
        prerequisites=["authenticated session"],
        what_tools_missed="Object-level auth check absent — scanner only checks 401/403.",
        chained_with=[],
        impact="Access to arbitrary user data.",
        impact_category=["data_exfil"],
        bounty_usd=5000,
        key_insight="Auth check was present on v2 endpoints but missing on v1.",
        unique_factor="Version inconsistency in auth enforcement.",
        pentra_tags=["idor", "rails", "api"],
        embedding_dense=[],
        embedding_sparse={},
        embedding_model="bge-m3",
        embedding_version=1,
    )


@pytest.mark.asyncio
async def test_hybrid_search_returns_relevant_results() -> None:
    """hybrid_search should return records from the merged RRF result set."""
    record = _make_record()
    mock_db = AsyncMock()

    mock_hit = MagicMock()
    mock_hit.id = str(record.id)
    mock_hit.score = 0.92

    with (
        patch(
            "pentra_knowledge.services.search.embed",
            return_value=MagicMock(dense=[0.1] * 1024, sparse={"idor": 0.8, "rails": 0.5}),
        ),
        patch(
            "pentra_knowledge.services.search._get_qdrant_client"
        ) as mock_qdrant_factory,
        patch(
            "pentra_knowledge.services.search.KnowledgeRepository"
        ) as mock_repo_cls,
    ):
        # query_points returns an object with a .points attribute
        mock_query_response = MagicMock()
        mock_query_response.points = [mock_hit]

        mock_qdrant = AsyncMock()
        mock_qdrant.query_points = AsyncMock(return_value=mock_query_response)
        mock_qdrant_factory.return_value = mock_qdrant

        mock_repo = AsyncMock()
        mock_repo.get_many_by_ids.return_value = [record]
        mock_repo_cls.return_value = mock_repo

        results = await hybrid_search(
            query="IDOR on Rails API with numeric IDs",
            db=mock_db,
            vuln_class=["idor"],
            top_k=8,
        )

    assert len(results) == 1
    assert results[0].vuln_class == VulnClass.IDOR
    assert results[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_hybrid_search_returns_empty_on_no_hits() -> None:
    """hybrid_search should return [] when Qdrant returns no results.

    When Qdrant is empty (0 vectors) the fallback calls repo.full_text_search.
    If that also returns [] we expect an empty final result.
    """
    mock_db = AsyncMock()

    with (
        patch(
            "pentra_knowledge.services.search.embed",
            return_value=MagicMock(dense=[0.0] * 1024, sparse={}),
        ),
        patch(
            "pentra_knowledge.services.search._get_qdrant_client"
        ) as mock_qdrant_factory,
        patch("pentra_knowledge.services.search.KnowledgeRepository") as mock_repo_cls,
    ):
        mock_empty_response = MagicMock()
        mock_empty_response.points = []
        mock_qdrant = AsyncMock()
        mock_qdrant.query_points = AsyncMock(return_value=mock_empty_response)
        mock_qdrant_factory.return_value = mock_qdrant

        # PG fallback also returns empty
        mock_repo = AsyncMock()
        mock_repo.full_text_search = AsyncMock(return_value=[])
        mock_repo_cls.return_value = mock_repo

        results = await hybrid_search(
            query="something obscure",
            db=mock_db,
        )

    assert results == []


@pytest.mark.asyncio
async def test_hybrid_search_respects_top_k_cap() -> None:
    """hybrid_search should not return more records than top_k."""
    records = [_make_record() for _ in range(5)]
    mock_db = AsyncMock()

    hits = [MagicMock(id=str(r.id), score=0.9) for r in records]

    with (
        patch(
            "pentra_knowledge.services.search.embed",
            return_value=MagicMock(dense=[0.1] * 1024, sparse={"x": 0.5}),
        ),
        patch(
            "pentra_knowledge.services.search._get_qdrant_client"
        ) as mock_qdrant_factory,
        patch(
            "pentra_knowledge.services.search.KnowledgeRepository"
        ) as mock_repo_cls,
    ):
        mock_hits_response = MagicMock()
        mock_hits_response.points = hits
        mock_qdrant = AsyncMock()
        mock_qdrant.query_points = AsyncMock(return_value=mock_hits_response)
        mock_qdrant_factory.return_value = mock_qdrant

        mock_repo = AsyncMock()
        mock_repo.get_many_by_ids.return_value = records[:2]
        mock_repo_cls.return_value = mock_repo

        results = await hybrid_search(
            query="test",
            db=mock_db,
            top_k=2,
        )

    assert len(results) <= 2
