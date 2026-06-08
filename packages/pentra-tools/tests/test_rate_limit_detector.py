"""Tests for RateLimitDetector.

All tests mock httpx.AsyncClient so no real network calls are made.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_mock_client(status_code: int, headers: dict) -> MagicMock:
    """Build a mock httpx.AsyncClient context manager."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.headers = headers

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)
    return mock_client


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_429_response():
    """HTTP 429 → is_rate_limited=True, safe_rps=1, delay=2000ms."""
    mock_client = _make_mock_client(status_code=429, headers={})

    with patch("httpx.AsyncClient", return_value=mock_client):
        from pentra_tools.recon.rate_limit_detector import probe_rate_limit
        result = await probe_rate_limit("http://target.com/", probe_count=2)

    assert result.is_rate_limited is True
    assert result.safe_rps == 1
    assert result.recommended_delay_ms == 2000
    assert any("429" in note for note in result.notes)


@pytest.mark.asyncio
async def test_detects_ratelimit_headers():
    """X-RateLimit-Remaining header → has_ratelimit_headers=True, safe_rps <= 5."""
    mock_client = _make_mock_client(
        status_code=200,
        headers={"X-RateLimit-Remaining": "10", "X-RateLimit-Limit": "100"},
    )

    with patch("httpx.AsyncClient", return_value=mock_client):
        from pentra_tools.recon.rate_limit_detector import probe_rate_limit
        result = await probe_rate_limit("http://target.com/", probe_count=2)

    assert result.has_ratelimit_headers is True
    assert result.safe_rps <= 5
    assert result.is_rate_limited is False


@pytest.mark.asyncio
async def test_no_rate_limit_returns_high_rps():
    """Clean 200 responses with no rate limit headers → safe_rps=20, delay=0."""
    mock_client = _make_mock_client(status_code=200, headers={})

    with patch("httpx.AsyncClient", return_value=mock_client):
        from pentra_tools.recon.rate_limit_detector import probe_rate_limit
        result = await probe_rate_limit("http://target.com/", probe_count=2)

    assert result.safe_rps == 20
    assert result.recommended_delay_ms == 0
    assert result.is_rate_limited is False
    assert result.has_ratelimit_headers is False
