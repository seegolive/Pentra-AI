"""Tests for GET /api/v1/findings global endpoint.

HTTP-level tests (401, 422) are marked skip — they require `client` and
`auth_client` AsyncClient fixtures not yet wired in conftest.py.

Unit tests call the handler function directly with mocked DB/user objects,
matching the pattern in test_findings_router.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.api.router import list_all_findings
from app.api.schemas import FindingWithEngagementResponse, PaginatedFindingsResponse
from app.db.models import FindingORM, UserORM


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_user() -> UserORM:
    user = UserORM()
    user.id = uuid4()
    user.username = f"user_{user.id.hex[:6]}"
    user.email = f"{user.username}@test.local"
    user.hashed_password = "hashed"
    user.is_active = True
    user.is_admin = False
    return user


def _make_finding_orm(engagement_id=None, severity: str = "high") -> FindingORM:
    finding = FindingORM()
    finding.id = uuid4()
    finding.engagement_id = engagement_id or uuid4()
    finding.title = "XSS in search"
    finding.vuln_class = "xss"
    finding.severity = severity
    finding.cvss_score = 6.5
    finding.cvss_vector = None
    finding.target_url = "https://acme.test/search"
    finding.http_method = "GET"
    finding.status = "open"
    finding.discovered_by = "agent"
    finding.discovered_at = datetime.now(timezone.utc)
    finding.description = "Reflected XSS"
    finding.impact = None
    finding.remediation = None
    finding.request_raw = ""
    finding.response_raw = ""
    finding.reproduction_steps = []
    finding.cve_ids = []
    finding.cve_data = None
    finding.chains = None
    return finding


def _db_with_rows(rows: list) -> AsyncMock:
    """Return a mocked AsyncSession whose execute() yields a row-iterable result.

    First call: count query → returns scalar_one() == len(rows).
    Second call: data query → rows are iterable.
    """
    db = AsyncMock()

    count_result = MagicMock()
    count_result.scalar_one.return_value = len(rows)

    data_result = MagicMock()
    data_result.__iter__ = MagicMock(return_value=iter(rows))

    db.execute.side_effect = [count_result, data_result]
    return db


# ── Unit tests (no HTTP client required) ──────────────────────────────────────

@pytest.mark.asyncio
async def test_list_all_findings_returns_empty_when_no_findings():
    user = _make_user()
    db = _db_with_rows([])

    result = await list_all_findings(
        severity=None,
        status=None,
        vuln_class=None,
        engagement_id=None,
        discovered_after=None,
        discovered_before=None,
        sort_by="discovered_at",
        sort_dir="desc",
        page=1,
        page_size=25,
        db=db,
        current_user=user,
    )

    assert isinstance(result, PaginatedFindingsResponse)
    assert result.results == []
    assert result.total == 0
    assert result.page == 1
    assert result.page_size == 25


@pytest.mark.asyncio
async def test_list_all_findings_returns_paginated_response():
    user = _make_user()
    engagement_id = uuid4()
    finding_orm = _make_finding_orm(engagement_id)
    eng_name = "Test Engagement"

    # Each row is a 2-tuple: (FindingORM, engagement_name string)
    db = _db_with_rows([(finding_orm, eng_name)])

    result = await list_all_findings(
        severity=None,
        status=None,
        vuln_class=None,
        engagement_id=None,
        discovered_after=None,
        discovered_before=None,
        sort_by="discovered_at",
        sort_dir="desc",
        page=1,
        page_size=25,
        db=db,
        current_user=user,
    )

    assert isinstance(result, PaginatedFindingsResponse)
    assert result.total == 1
    assert result.page == 1
    assert result.page_size == 25
    assert len(result.results) == 1

    finding_result = result.results[0]
    assert isinstance(finding_result, FindingWithEngagementResponse)
    assert finding_result.id == finding_orm.id
    assert finding_result.engagement_name == eng_name
    assert finding_result.severity == "high"


@pytest.mark.asyncio
async def test_list_all_findings_with_severity_filter():
    """Verify the handler accepts severity filter without error."""
    user = _make_user()
    finding_orm = _make_finding_orm(severity="critical")
    db = _db_with_rows([(finding_orm, "Crit Engagement")])

    result = await list_all_findings(
        severity=["critical"],
        status=None,
        vuln_class=None,
        engagement_id=None,
        discovered_after=None,
        discovered_before=None,
        sort_by="severity",
        sort_dir="desc",
        page=1,
        page_size=25,
        db=db,
        current_user=user,
    )

    assert result.total == 1
    assert result.results[0].severity == "critical"


@pytest.mark.asyncio
async def test_list_all_findings_sort_by_severity_asc():
    """sort_by=severity + sort_dir=asc uses severity_case.desc() ordering."""
    user = _make_user()
    db = _db_with_rows([])

    result = await list_all_findings(
        severity=None,
        status=None,
        vuln_class=None,
        engagement_id=None,
        discovered_after=None,
        discovered_before=None,
        sort_by="severity",
        sort_dir="asc",
        page=1,
        page_size=10,
        db=db,
        current_user=user,
    )

    assert isinstance(result, PaginatedFindingsResponse)
    assert result.total == 0


@pytest.mark.asyncio
async def test_list_all_findings_page_offset():
    """page=2, page_size=5 — handler executes without error."""
    user = _make_user()
    db = _db_with_rows([])

    result = await list_all_findings(
        severity=None,
        status=None,
        vuln_class=None,
        engagement_id=None,
        discovered_after=None,
        discovered_before=None,
        sort_by="discovered_at",
        sort_dir="desc",
        page=2,
        page_size=5,
        db=db,
        current_user=user,
    )

    assert result.page == 2
    assert result.page_size == 5


# ── HTTP-level tests (require AsyncClient fixtures — skipped) ─────────────────

@pytest.mark.xfail(reason="requires conftest.py HTTP test fixtures", strict=False)
@pytest.mark.asyncio
async def test_list_all_findings_requires_auth(client):
    resp = await client.get("/api/v1/findings")
    assert resp.status_code == 401


@pytest.mark.xfail(reason="requires conftest.py HTTP test fixtures", strict=False)
@pytest.mark.asyncio
async def test_list_all_findings_invalid_sort_by(auth_client):
    resp = await auth_client.get("/api/v1/findings?sort_by=invalid_field")
    assert resp.status_code == 422
