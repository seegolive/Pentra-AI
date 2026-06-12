"""Tests for the Bugcrowd public disclosures scraper (Sprint 28 — KB alternative source)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── _guess_vuln_class ───────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "category,title,expected",
    [
        ("Cross-Site Scripting (XSS)", "Reflected XSS on /search", "XSS"),
        ("SQL Injection", "Blind SQLi on login form", "SQLi"),
        (None, "IDOR allows access to other users' invoices", "IDOR"),
        ("Server-Side Request Forgery (SSRF)", "SSRF via image upload", "SSRF"),
        ("Remote Code Execution", "RCE via deserialization", "RCE"),
        (None, "Open redirect on /logout?next=", "Open Redirect"),
        ("Broken Access Control", "Admin panel reachable without auth", "Broken Access Control"),
        ("Some Unmapped Category", "Generic finding with no keywords", "Other"),
    ],
)
def test_guess_vuln_class(category, title, expected):
    from app.tasks.bugcrowd_scraper import _guess_vuln_class

    assert _guess_vuln_class(category, title) == expected


# ── _SEVERITY_MAP ────────────────────────────────────────────────────────────

def test_severity_map_covers_priority_and_named_severities():
    from app.tasks.bugcrowd_scraper import _SEVERITY_MAP

    assert _SEVERITY_MAP["p1"] == "critical"
    assert _SEVERITY_MAP["p2"] == "high"
    assert _SEVERITY_MAP["p3"] == "medium"
    assert _SEVERITY_MAP["p4"] == "low"
    assert _SEVERITY_MAP["p5"] == "info"
    assert _SEVERITY_MAP["critical"] == "critical"
    assert _SEVERITY_MAP["informational"] == "info"


# ── _scrape_all ──────────────────────────────────────────────────────────────

def _mock_response(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status = MagicMock()
    return resp


@pytest.mark.asyncio
async def test_scrape_all_paginates_until_has_next_page_false():
    """_scrape_all should follow has_next_page until it becomes false."""
    from app.tasks.bugcrowd_scraper import _scrape_all

    page1 = _mock_response({
        "disclosures": [{"id": 1, "title": "Finding 1"}, {"id": 2, "title": "Finding 2"}],
        "has_next_page": True,
    })
    page2 = _mock_response({
        "disclosures": [{"id": 3, "title": "Finding 3"}],
        "has_next_page": False,
    })

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=[page1, page2])
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.tasks.bugcrowd_scraper.httpx.AsyncClient", return_value=mock_client),
        patch("app.tasks.bugcrowd_scraper.asyncio.sleep", new=AsyncMock()),
    ):
        records = await _scrape_all(max_records=1000)

    assert len(records) == 3
    assert [r["id"] for r in records] == [1, 2, 3]
    assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_scrape_all_stops_at_max_records():
    """_scrape_all should truncate to max_records even if more pages are available."""
    from app.tasks.bugcrowd_scraper import _scrape_all

    page1 = _mock_response({
        "disclosures": [{"id": i, "title": f"Finding {i}"} for i in range(1, 6)],
        "has_next_page": True,
    })

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=page1)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.tasks.bugcrowd_scraper.httpx.AsyncClient", return_value=mock_client),
        patch("app.tasks.bugcrowd_scraper.asyncio.sleep", new=AsyncMock()),
    ):
        records = await _scrape_all(max_records=3)

    assert len(records) == 3


@pytest.mark.asyncio
async def test_scrape_all_stops_on_empty_disclosures():
    """An empty 'disclosures' list ends pagination even if has_next_page is true."""
    from app.tasks.bugcrowd_scraper import _scrape_all

    page1 = _mock_response({"disclosures": [], "has_next_page": True})

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=page1)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.tasks.bugcrowd_scraper.httpx.AsyncClient", return_value=mock_client),
        patch("app.tasks.bugcrowd_scraper.asyncio.sleep", new=AsyncMock()),
    ):
        records = await _scrape_all(max_records=1000)

    assert records == []
    assert mock_client.get.call_count == 1


@pytest.mark.asyncio
async def test_scrape_all_handles_http_error_gracefully():
    """An HTTP error on a page should stop pagination and return records gathered so far."""
    import httpx

    from app.tasks.bugcrowd_scraper import _scrape_all

    page1 = _mock_response({
        "disclosures": [{"id": 1, "title": "Finding 1"}],
        "has_next_page": True,
    })

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=[page1, httpx.HTTPError("boom")])
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.tasks.bugcrowd_scraper.httpx.AsyncClient", return_value=mock_client),
        patch("app.tasks.bugcrowd_scraper.asyncio.sleep", new=AsyncMock()),
    ):
        records = await _scrape_all(max_records=1000)

    assert len(records) == 1
    assert records[0]["id"] == 1
