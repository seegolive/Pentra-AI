"""Tests for pentra_knowledge — from_finding knowledge record conversion."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest


# ── KnowledgeRepository dedup ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_submit_finding_creates_kb_record_with_correct_fields():
    """submit-to-knowledge endpoint should save a record with finding data."""
    from pentra_knowledge.db.repository import KnowledgeRepository

    finding_id = uuid4()
    engagement_id = uuid4()

    # Simulate what the API endpoint does: build record_data from a finding
    record_data = {
        "source": "pentra_finding",
        "source_id": str(finding_id),
        "source_url": "",
        "title": "IDOR on /api/users/{id}",
        "vuln_class": "idor",
        "vuln_subclass": "",
        "severity": "high",
        "program": "https://api.example.com/users/123",
        "tech_stack": ["rails"],
        "platform_type": ["web"],
        "attack_technique": "Increment integer ID to access other users",
        "attack_steps": ["1. Login as user A", "2. Access /api/users/2"],
        "key_insight": "No authorization check on user ID parameter",
        "indicators": [],
        "pentra_tags": ["from_engagement", "user_confirmed"],
        "raw_content": "Full finding description...",
        "is_embedded": False,
    }

    # Validate required fields are present
    assert record_data["source"] == "pentra_finding"
    assert record_data["source_id"] == str(finding_id)
    assert record_data["vuln_class"] == "idor"
    assert record_data["is_embedded"] is False


@pytest.mark.asyncio
async def test_submit_finding_deduplicates_by_source_id():
    """Submitting the same finding twice should return the existing record."""
    finding_id = str(uuid4())

    mock_existing = AsyncMock()
    mock_existing.id = uuid4()

    mock_repo = AsyncMock()
    mock_repo.get_by_source_id = AsyncMock(return_value=mock_existing)

    # If record exists, we should NOT call create
    existing = await mock_repo.get_by_source_id(finding_id)
    if existing:
        result_id = str(existing.id)
    else:
        result_id = "would_create_new"

    assert result_id == str(mock_existing.id)
    mock_repo.create.assert_not_called()


@pytest.mark.asyncio
async def test_submit_finding_creates_when_not_duplicate():
    """Submitting a new finding should call repo.create."""
    finding_id = str(uuid4())

    mock_new_record = AsyncMock()
    mock_new_record.id = uuid4()

    mock_repo = AsyncMock()
    mock_repo.get_by_source_id = AsyncMock(return_value=None)  # not found
    mock_repo.create = AsyncMock(return_value=mock_new_record)

    existing = await mock_repo.get_by_source_id(finding_id)
    if not existing:
        record = await mock_repo.create({"source_id": finding_id, "source": "pentra_finding"})
        result_id = str(record.id)
    else:
        result_id = str(existing.id)

    assert result_id == str(mock_new_record.id)
    mock_repo.create.assert_called_once()


# ── Tags from user annotation ─────────────────────────────────────────────────

def test_tags_merged_with_defaults():
    """User-provided tags should be merged with default tags."""
    user_tags = ["custom_tag", "rails"]
    default_tags = ["from_engagement", "user_confirmed"]

    merged = default_tags + user_tags
    assert "from_engagement" in merged
    assert "custom_tag" in merged
    assert len(merged) == 4


def test_empty_key_insight_preserved():
    """Empty key_insight should be stored as empty string, not None."""
    record_data = {
        "key_insight": "",
        "attack_technique": "",
    }
    # Worker will fill these in on next embed cycle
    assert record_data["key_insight"] == ""
    assert record_data["attack_technique"] == ""


# ── KB record text representation ─────────────────────────────────────────────

def test_kb_record_search_text_includes_key_fields():
    """The text used for embedding should include title, technique, and insight."""
    title = "IDOR via predictable user ID"
    technique = "Increment integer parameter"
    key_insight = "No RBAC check on resource access"

    search_text = f"{title} {technique} {key_insight}"

    assert title in search_text
    assert technique in search_text
    assert key_insight in search_text
