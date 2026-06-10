"""Tests for SSRF + OOB Tester — Task 22.1 (Sprint 22)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_tools.vuln.ssrf_oob_tester import (
    SsrfFinding,
    identify_ssrf_candidates,
    check_ssrf,
    scan_ssrf_on_endpoints,
)


# ── Test 1: identify_ssrf_candidates ─────────────────────────────────────────

def test_identify_ssrf_candidates_detects_url_params():
    """Endpoints with SSRF-prone parameter names should be flagged as candidates."""
    endpoints = [
        {"url": "https://target.com/api/fetch?url=https://example.com", "method": "GET"},
        {"url": "https://target.com/render?src=image.png", "method": "GET"},
        {"url": "https://target.com/profile?name=alice", "method": "GET"},  # safe param
        {"url": "https://target.com/api/redirect?redirect_uri=https://x.com", "method": "GET"},
        {"url": "https://target.com/static/logo.png", "method": "GET"},  # no params
    ]
    candidates = identify_ssrf_candidates(endpoints)
    urls = [c["url"] for c in candidates]

    # SSRF-prone params
    assert any("fetch" in u for u in urls), "fetch endpoint should be detected"
    assert any("src" in u for u in urls), "src param endpoint should be detected"
    assert any("redirect_uri" in u for u in urls), "redirect_uri endpoint should be detected"

    # Safe params/static resources should be filtered out or have empty ssrf_params
    safe = next((c for c in candidates if "name=alice" in c["url"]), None)
    if safe:
        assert safe["ssrf_params"] == [], "safe param should have no ssrf_params"


def test_identify_ssrf_candidates_detects_path_patterns():
    """Endpoints with SSRF-prone path segments should be flagged."""
    endpoints = [
        {"url": "https://target.com/proxy/fetch", "method": "POST"},
        {"url": "https://target.com/webhook/register", "method": "POST"},
        {"url": "https://target.com/users/list", "method": "GET"},  # generic path
    ]
    candidates = identify_ssrf_candidates(endpoints)
    candidate_urls = [c["url"] for c in candidates]

    assert "https://target.com/proxy/fetch" in candidate_urls
    assert "https://target.com/webhook/register" in candidate_urls


# ── Test 2: SsrfFinding.to_finding schema ────────────────────────────────────

def test_ssrf_finding_to_finding_schema():
    """SsrfFinding.to_finding() must return a dict with required vuln schema keys."""
    finding = SsrfFinding(
        title="SSRF — AWS IMDSv1 metadata via parameter 'url'",
        severity="critical",
        attack_type="parameter_injection",
        target_url="https://target.com/fetch?url=http://169.254.169.254/",
        payload="http://169.254.169.254/latest/meta-data/",
        parameter="url",
        evidence="Indicator 'ami-id' found in response",
        remediation="Implement strict URL allowlist.",
    )
    d = finding.to_finding()

    assert d["vuln_class"] == "SSRF"
    assert d["severity"] == "critical"
    assert "SSRF" in d["title"]
    assert "target_url" in d
    assert "remediation" in d
    assert d["source"] == "ssrf_oob_tester"
    assert "parameter_injection" in d["description"]


# ── Test 3: check_ssrf detects SSRF via mock HTTP response ───────────────────

@pytest.mark.asyncio
async def test_check_ssrf_detects_aws_metadata_reflection():
    """check_ssrf should report finding when server reflects AWS metadata indicators."""
    # Simulate a vulnerable server that returns AWS metadata content
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ami-id: ami-0abcdef1234567890\ninstance-id: i-1234567890abcdef0"
    mock_resp.headers = {}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch("pentra_tools.vuln.ssrf_oob_tester.httpx.AsyncClient", return_value=mock_client):
        findings = await check_ssrf(
            url="https://target.com/fetch?url=https://example.com",
            auth_headers=None,
        )

    assert len(findings) >= 1
    assert findings[0]["vuln_class"] == "SSRF"
    assert findings[0]["severity"] == "critical"
    assert "url" in findings[0]["description"]


# ── Test 4: scan_ssrf_on_endpoints full pipeline ─────────────────────────────

@pytest.mark.asyncio
async def test_scan_ssrf_on_endpoints_returns_deduplicated_findings():
    """Full scan pipeline: identifies candidates, probes, deduplicates findings."""
    endpoints = [
        {"url": "https://target.com/api/load?src=https://cdn.com/img.png", "method": "GET"},
        {"url": "https://target.com/api/load?src=https://cdn.com/img.png", "method": "GET"},  # duplicate
        {"url": "https://target.com/about", "method": "GET"},  # no SSRF params
    ]

    # Mock: server reflects SSH banner (SSRF port probe indicator)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "SSH-2.0-OpenSSH_8.0"
    mock_resp.headers = {}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with patch("pentra_tools.vuln.ssrf_oob_tester.httpx.AsyncClient", return_value=mock_client):
        findings = await scan_ssrf_on_endpoints(
            endpoints=endpoints,
            oob_canary=None,
        )

    # Should have findings (SSH indicator detected)
    assert len(findings) >= 1

    # All findings must have vuln_class = SSRF
    for f in findings:
        assert f["vuln_class"] == "SSRF"

    # Deduplication: same URL+title should not appear twice
    keys = [f"{f['target_url']}|{f['title']}" for f in findings]
    assert len(keys) == len(set(keys)), "Findings should be deduplicated"


@pytest.mark.asyncio
async def test_scan_ssrf_returns_empty_for_no_candidates():
    """scan_ssrf_on_endpoints returns empty list when no SSRF candidates found."""
    endpoints = [
        {"url": "https://target.com/about", "method": "GET"},
        {"url": "https://target.com/contact", "method": "GET"},
        {"url": "https://target.com/api/users?page=1&limit=20", "method": "GET"},
    ]
    findings = await scan_ssrf_on_endpoints(endpoints=endpoints)
    assert findings == []
