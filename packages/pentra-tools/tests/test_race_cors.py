"""Tests for Race Condition (19.2) and CORS Tester (19.3)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_tools.vuln.race_condition import (
    RaceResult,
    identify_race_candidates,
    check_race_condition,
)
from pentra_tools.vuln.cors_tester import check_cors


# ── Task 19.2: Race Condition ─────────────────────────────────────────────────

def test_identify_race_candidates_filters_post_endpoints():
    endpoints = [
        {"url": "https://t.com/redeem", "method": "POST"},
        {"url": "https://t.com/view", "method": "GET"},  # GET — excluded
        {"url": "https://t.com/transfer", "method": "POST"},
        {"url": "https://t.com/static", "method": "POST"},  # no race pattern
    ]
    candidates = identify_race_candidates(endpoints)
    urls = [c["url"] for c in candidates]
    assert "https://t.com/redeem" in urls
    assert "https://t.com/transfer" in urls
    assert "https://t.com/view" not in urls  # GET excluded


def test_identify_race_candidates_only_state_changing():
    """GET endpoints should never be race candidates."""
    endpoints = [{"url": "https://t.com/vote", "method": "GET"}]
    candidates = identify_race_candidates(endpoints)
    assert len(candidates) == 0


@pytest.mark.asyncio
async def test_race_condition_detected_multiple_success():
    """Race condition should be detected when multiple requests succeed."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status": "redeemed"}'

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.request = AsyncMock(return_value=mock_resp)

    with patch("pentra_tools.vuln.race_condition.httpx.AsyncClient", return_value=mock_client):
        result = await check_race_condition(
            url="https://t.com/redeem",
            method="POST",
            concurrency=5,
        )

    assert result is not None
    assert result.race_detected is True
    assert result.successful_responses == 5
    assert result.severity in ("high", "medium")


@pytest.mark.asyncio
async def test_race_condition_not_detected_single_success():
    """No race condition when only 1 request succeeds."""
    call_count = [0]

    async def mock_request(*args, **kwargs):
        call_count[0] += 1
        resp = MagicMock()
        resp.status_code = 200 if call_count[0] == 1 else 400
        resp.text = "ok" if call_count[0] == 1 else "already used"
        return resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.request = mock_request

    with patch("pentra_tools.vuln.race_condition.httpx.AsyncClient", return_value=mock_client):
        result = await check_race_condition(
            url="https://t.com/coupon",
            method="POST",
            concurrency=5,
        )

    assert result is not None
    assert result.race_detected is False


def test_race_result_to_finding_format():
    result = RaceResult(
        endpoint="https://t.com/transfer",
        http_method="POST",
        concurrent_requests=20,
        successful_responses=7,
        unique_responses=2,
        race_detected=True,
        evidence="7/20 requests succeeded",
        severity="high",
    )
    finding = result.to_finding()
    assert finding["vuln_class"] == "RACE_CONDITION"
    assert finding["severity"] == "high"
    assert finding["source"] == "race_condition_tester"
    assert "remediation" in finding


def test_race_result_to_finding_empty_when_no_race():
    result = RaceResult(
        endpoint="https://t.com/safe",
        http_method="POST",
        concurrent_requests=5,
        successful_responses=1,
        unique_responses=1,
        race_detected=False,
        evidence="Only 1 succeeded",
        severity="info",
    )
    assert result.to_finding() == {}


# ── Task 19.3: CORS Tester ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cors_misconfiguration_detected():
    """CORS finding when ACAO reflects evil origin + credentials=true."""
    baseline_resp = MagicMock()
    baseline_resp.headers = {"Access-Control-Allow-Origin": ""}
    baseline_resp.status_code = 200

    evil_resp = MagicMock()
    evil_resp.headers = {
        "Access-Control-Allow-Origin": "https://evil.com",
        "Access-Control-Allow-Credentials": "true",
    }
    evil_resp.status_code = 200

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    # First call (baseline), subsequent calls return evil_resp
    mock_client.get = AsyncMock(side_effect=[baseline_resp, evil_resp] + [evil_resp] * 10)

    with patch("pentra_tools.vuln.cors_tester.httpx.AsyncClient", return_value=mock_client):
        findings = await check_cors("https://api.target.com/user")

    assert len(findings) >= 1
    assert findings[0]["vuln_class"] == "CORS_MISCONFIGURATION"
    assert findings[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_cors_no_finding_on_strict_config():
    """No CORS finding when server rejects arbitrary origins."""
    strict_resp = MagicMock()
    strict_resp.headers = {
        "Access-Control-Allow-Origin": "https://myapp.com",
    }

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=strict_resp)

    with patch("pentra_tools.vuln.cors_tester.httpx.AsyncClient", return_value=mock_client):
        findings = await check_cors("https://secure.target.com/api")

    assert len(findings) == 0
