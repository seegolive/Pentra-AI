"""Tests for Subdomain Takeover Detector — Task 20.2."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_tools.recon.takeover_detector import (
    TAKEOVER_FINGERPRINTS,
    TakeoverFinding,
    check_takeover_fingerprint,
)


def test_takeover_fingerprints_have_required_fields():
    """Every fingerprint entry must have cname_patterns, fingerprint, service, severity."""
    for name, config in TAKEOVER_FINGERPRINTS.items():
        assert "cname_patterns" in config, f"{name} missing cname_patterns"
        assert isinstance(config["cname_patterns"], list), f"{name}: cname_patterns must be a list"
        assert "fingerprint" in config, f"{name} missing fingerprint"
        assert "service" in config, f"{name} missing service"
        assert config.get("severity") in ("high", "medium", "low"), (
            f"{name} has invalid severity: {config.get('severity')}"
        )


@pytest.mark.asyncio
async def test_check_fingerprint_github_pages_detected():
    """GitHub Pages fingerprint should be detected in response body."""
    mock_resp = MagicMock()
    mock_resp.text = "<p>There isn't a GitHub Pages site here</p>"
    mock_resp.status_code = 404

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    result = await check_takeover_fingerprint(
        "blog.target.com",
        "target-org.github.io",
        mock_client,
    )

    assert result is not None
    assert result.service == "GitHub Pages"
    assert result.confidence == "certain"
    assert result.severity == "high"
    assert result.subdomain == "blog.target.com"
    assert result.cname_target == "target-org.github.io"


@pytest.mark.asyncio
async def test_check_fingerprint_normal_site_returns_none():
    """Normal site without takeover fingerprint should return None."""
    mock_resp = MagicMock()
    mock_resp.text = "<html><body><h1>Welcome to our blog</h1></body></html>"
    mock_resp.status_code = 200

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    result = await check_takeover_fingerprint(
        "blog.target.com",
        "target-org.github.io",
        mock_client,
    )

    assert result is None


def test_takeover_finding_to_dict_schema():
    """TakeoverFinding.to_finding() should return a valid Pentra AI finding dict."""
    finding = TakeoverFinding(
        subdomain="old-cdn.target.com",
        cname_target="target-company.github.io",
        service="GitHub Pages",
        severity="high",
        fingerprint="There isn't a GitHub Pages site here",
        confidence="certain",
    )
    d = finding.to_finding()

    assert d["vuln_class"] == "SUBDOMAIN_TAKEOVER"
    assert d["severity"] == "high"
    assert d["source"] == "takeover_detector"
    assert "old-cdn.target.com" in d["title"]
    assert "GitHub Pages" in d["title"]
    assert "remediation" in d
    assert "dangling CNAME" in d["description"]
