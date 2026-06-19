"""Tests for /internal/* endpoints (Sprint 35).

The internal router uses a shared-secret header (X-Internal-Token) instead of
JWT. All tests exercise the endpoint functions directly via mocked DB sessions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.api.internal_router import (
    BulkFindingsRequest,
    FindingPayload,
    bulk_create_findings,
    verify_internal_token,
)
from app.db.models import EngagementORM


# ── Helpers ───────────────────────────────────────────────────────────────────

_GOOD_TOKEN = "supersecret-internal-token"


def _make_engagement() -> EngagementORM:
    e = EngagementORM()
    e.id = uuid4()
    e.workspace_id = uuid4()
    e.name = "Agent Test Engagement"
    e.description = None
    e.mode = "agentic"
    e.status = "running"
    e.in_scope = ["target.com"]
    e.out_of_scope = []
    e.llm_model = "qwen2.5-coder:32b"
    e.langgraph_thread_id = str(uuid4())
    e.opsec_mode = False
    e.request_jitter_ms = 0
    e.created_by = uuid4()
    e.created_at = datetime.now(timezone.utc)
    e.updated_at = datetime.now(timezone.utc)
    e.started_at = None
    e.completed_at = None
    e.monitoring_enabled = False
    e.monitoring_interval_hours = 24
    return e


def _make_payload(**kwargs) -> FindingPayload:
    defaults = dict(
        title="XSS in search",
        vuln_class="xss",
        severity="medium",
        target_url="https://target.com/search",
        http_method="GET",
        request_raw="GET /search?q=<script>alert(1)</script> HTTP/1.1",
        response_raw="HTTP/1.1 200 OK",
        description="Reflected XSS",
        impact="Session hijacking",
        remediation="Encode output",
        reproduction_steps=["Visit URL", "Observe alert"],
    )
    defaults.update(kwargs)
    return FindingPayload(**defaults)


def _mock_db_for_bulk(eng, existing_keys=None):
    """Return a mock AsyncSession for bulk_create_findings."""
    db = AsyncMock()
    db.get = AsyncMock(return_value=eng)

    existing_rows = []
    if existing_keys:
        for title, url in existing_keys:
            row = MagicMock()
            row.title = title
            row.target_url = url
            existing_rows.append(row)

    existing_result = MagicMock()
    existing_result.__iter__ = MagicMock(return_value=iter(existing_rows))
    db.execute.return_value = existing_result

    return db


# ── verify_internal_token tests ───────────────────────────────────────────────

def test_verify_internal_token_valid():
    from app.core.config import get_api_settings
    with patch("app.api.internal_router.get_api_settings") as mock_s:
        mock_s.return_value.internal_api_token = _GOOD_TOKEN
        # Should not raise
        verify_internal_token(x_internal_token=_GOOD_TOKEN)


def test_verify_internal_token_wrong_raises_403():
    from fastapi import HTTPException
    with patch("app.api.internal_router.get_api_settings") as mock_s:
        mock_s.return_value.internal_api_token = _GOOD_TOKEN
        with pytest.raises(HTTPException) as exc_info:
            verify_internal_token(x_internal_token="wrongtoken")
        assert exc_info.value.status_code == 403


def test_verify_internal_token_not_configured_raises_503():
    from fastapi import HTTPException
    with patch("app.api.internal_router.get_api_settings") as mock_s:
        mock_s.return_value.internal_api_token = None
        with pytest.raises(HTTPException) as exc_info:
            verify_internal_token(x_internal_token=_GOOD_TOKEN)
        assert exc_info.value.status_code == 503


# ── bulk_create_findings tests ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_bulk_create_findings_creates_all():
    eng = _make_engagement()
    db = _mock_db_for_bulk(eng, existing_keys=[])

    body = BulkFindingsRequest(
        engagement_id=str(eng.id),
        findings=[_make_payload(), _make_payload(title="SQLi", target_url="https://target.com/login")],
    )
    result = await bulk_create_findings(body=body, db=db)

    assert result.created == 2
    assert result.skipped == 0
    assert result.engagement_id == str(eng.id)
    assert db.add.call_count == 2
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_bulk_create_findings_skips_duplicates():
    eng = _make_engagement()
    existing = [("XSS in search", "https://target.com/search")]
    db = _mock_db_for_bulk(eng, existing_keys=existing)

    body = BulkFindingsRequest(
        engagement_id=str(eng.id),
        findings=[
            _make_payload(),  # duplicate of existing
            _make_payload(title="New Finding", target_url="https://target.com/api"),
        ],
    )
    result = await bulk_create_findings(body=body, db=db)

    assert result.created == 1
    assert result.skipped == 1


@pytest.mark.asyncio
async def test_bulk_create_findings_empty_list():
    eng = _make_engagement()
    db = _mock_db_for_bulk(eng)

    body = BulkFindingsRequest(engagement_id=str(eng.id), findings=[])
    result = await bulk_create_findings(body=body, db=db)

    assert result.created == 0
    assert result.skipped == 0
    db.add.assert_not_called()
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_bulk_create_findings_404_if_engagement_missing():
    from fastapi import HTTPException
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)
    db.execute = AsyncMock(return_value=MagicMock(__iter__=MagicMock(return_value=iter([]))))

    body = BulkFindingsRequest(engagement_id=str(uuid4()), findings=[_make_payload()])
    with pytest.raises(HTTPException) as exc_info:
        await bulk_create_findings(body=body, db=db)
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_bulk_create_findings_invalid_uuid_raises_400():
    from fastapi import HTTPException
    db = AsyncMock()

    body = BulkFindingsRequest(engagement_id="not-a-uuid", findings=[])
    with pytest.raises(HTTPException) as exc_info:
        await bulk_create_findings(body=body, db=db)
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_bulk_create_findings_severity_lowercased():
    """Severity is always stored lowercase regardless of what agent sends."""
    eng = _make_engagement()
    db = _mock_db_for_bulk(eng)

    body = BulkFindingsRequest(
        engagement_id=str(eng.id),
        findings=[_make_payload(severity="CRITICAL")],
    )
    await bulk_create_findings(body=body, db=db)

    added_finding = db.add.call_args[0][0]
    assert added_finding.severity == "critical"


@pytest.mark.asyncio
async def test_bulk_create_findings_deduplication_within_batch():
    """Two identical findings in the same batch — only one should be created."""
    eng = _make_engagement()
    db = _mock_db_for_bulk(eng)

    same_payload = _make_payload(title="Dupe", target_url="https://target.com/dupe")
    body = BulkFindingsRequest(
        engagement_id=str(eng.id),
        findings=[same_payload, same_payload],
    )
    result = await bulk_create_findings(body=body, db=db)

    assert result.created == 1
    assert result.skipped == 1
