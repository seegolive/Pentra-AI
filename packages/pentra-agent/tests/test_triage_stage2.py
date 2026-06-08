"""Tests for two-stage triage (Task 18.7)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_agent.nodes.triage_node import _reprobe_request, _stage2_reprobe


# ── Stage 2 re-probe tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stage2_skips_low_severity():
    """Stage 2 should not re-probe low/medium/info findings."""
    findings = [
        {
            "title": "Info finding",
            "severity": "info",
            "vuln_class": "info",
            "target_url": "https://target.com/",
            "param_name": "id",
            "param_location": "query",
            "payload": "",
        },
        {
            "title": "Low finding",
            "severity": "low",
            "vuln_class": "low",
            "target_url": "https://target.com/",
            "param_name": "id",
            "param_location": "query",
            "payload": "",
        },
    ]
    result = await _stage2_reprobe(findings)
    # Low/info pass through unchanged (no stage2_verified key set by _reprobe_request)
    assert len(result) == 2
    assert all(f.get("stage2_verified") is None for f in result)


@pytest.mark.asyncio
async def test_stage2_verifies_timebased_sqli_on_delay():
    """Stage 2: SLEEP-based SQLi confirmed when response takes ≥4s."""
    finding = {
        "title": "SQL Injection in id",
        "severity": "high",
        "vuln_class": "SQL Injection",
        "target_url": "https://target.com/comment.aspx?id=1",
        "param_name": "id",
        "param_location": "query",
        "payload": "' OR SLEEP(5)--",
    }

    mock_resp = MagicMock()
    mock_resp.text = "<html>Error</html>"
    mock_resp.status_code = 200

    # Simulate 5s delay by making elapsed time > 4s
    import time
    original_monotonic = time.monotonic

    call_count = 0

    def fake_monotonic():
        nonlocal call_count
        call_count += 1
        # First call (t0) returns 0, second call (elapsed) returns 5
        return 0.0 if call_count == 1 else 5.0

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.request = AsyncMock(return_value=mock_resp)

    with patch("pentra_agent.nodes.triage_node.time.monotonic", side_effect=fake_monotonic), \
         patch("pentra_agent.nodes.triage_node.httpx.AsyncClient", return_value=mock_client):
        result = await _stage2_reprobe([finding])

    assert len(result) == 1
    assert result[0]["stage2_verified"] is True
    assert "Time-based" in result[0]["stage2_note"]


@pytest.mark.asyncio
async def test_stage2_downgrades_when_no_delay():
    """Stage 2: HIGH SQLi downgraded to MEDIUM when timing anomaly not reproduced."""
    finding = {
        "title": "SQL Injection in id",
        "severity": "high",
        "vuln_class": "SQL Injection",
        "target_url": "https://target.com/page?id=1",
        "param_name": "id",
        "param_location": "query",
        "payload": "' OR SLEEP(5)--",
    }

    mock_resp = MagicMock()
    mock_resp.text = "<html>OK</html>"
    mock_resp.status_code = 200

    # Fast response: 0.3s (no delay)
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.request = AsyncMock(return_value=mock_resp)

    call_count = 0
    def fast_monotonic():
        nonlocal call_count
        call_count += 1
        return 0.0 if call_count == 1 else 0.3  # 0.3s response

    with patch("pentra_agent.nodes.triage_node.time.monotonic", side_effect=fast_monotonic), \
         patch("pentra_agent.nodes.triage_node.httpx.AsyncClient", return_value=mock_client):
        result = await _stage2_reprobe([finding])

    assert result[0]["stage2_verified"] is False
    assert result[0]["severity"] == "medium"  # Downgraded
    assert "Stage 2 downgrade" in result[0]["triage_reason"]


@pytest.mark.asyncio
async def test_stage2_verifies_xss_reflection():
    """Stage 2: XSS confirmed when payload reflected in response."""
    finding = {
        "title": "XSS in search",
        "severity": "high",
        "vuln_class": "XSS",
        "target_url": "https://target.com/search?q=test",
        "param_name": "q",
        "param_location": "query",
        "payload": "<script>alert(1)</script>",
    }

    mock_resp = MagicMock()
    mock_resp.text = "<html><p>Results for: <script>alert(1)</script></p></html>"
    mock_resp.status_code = 200

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.request = AsyncMock(return_value=mock_resp)

    with patch("pentra_agent.nodes.triage_node.httpx.AsyncClient", return_value=mock_client):
        verified, note = await _reprobe_request(
            url="https://target.com/search?q=test",
            param="q",
            param_loc="query",
            payload="<script>alert(1)</script>",
            vuln_class="xss",
            auth_headers={},
            auth_cookies={},
        )

    assert verified is True
    assert "reflected" in note.lower()


@pytest.mark.asyncio
async def test_stage2_skips_finding_without_payload():
    """Stage 2: findings with no payload evidence are passed through as-is."""
    finding = {
        "title": "Possible IDOR",
        "severity": "high",
        "vuln_class": "IDOR",
        "target_url": "https://target.com/user/1",
        "param_name": "",  # no param info
        "param_location": "path",
        "payload": "",  # no payload
    }
    result = await _stage2_reprobe([finding])
    assert result[0]["stage2_verified"] is None
    assert "Skipped" in result[0]["stage2_note"]


@pytest.mark.asyncio
async def test_stage2_handles_timeout_as_verification():
    """Stage 2: httpx timeout treated as time-based injection confirmation."""
    finding = {
        "title": "Blind SQLi",
        "severity": "critical",
        "vuln_class": "SQL Injection",
        "target_url": "https://target.com/api?id=1",
        "param_name": "id",
        "param_location": "query",
        "payload": "'; WAITFOR DELAY '0:0:10'--",
    }

    import httpx as _httpx
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.request = AsyncMock(side_effect=_httpx.TimeoutException("timeout"))

    with patch("pentra_agent.nodes.triage_node.httpx.AsyncClient", return_value=mock_client):
        result = await _stage2_reprobe([finding])

    assert result[0]["stage2_verified"] is True
    assert "timed out" in result[0]["stage2_note"].lower()
