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


# ── Sprint 21.7 — Mock tests for all 3 services ───────────────────────────────

@pytest.mark.asyncio
async def test_check_fingerprint_heroku_detected():
    """Heroku 'No such app' fingerprint should be detected."""
    mock_resp = MagicMock()
    mock_resp.text = "<html><p>No such app</p></html>"
    mock_resp.status_code = 404

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    result = await check_takeover_fingerprint(
        "app.target.com",
        "target.herokuapp.com",
        mock_client,
    )

    assert result is not None, "Heroku takeover should be detected"
    assert result.service == "Heroku"
    assert result.confidence == "certain"
    assert result.severity == "high"


@pytest.mark.asyncio
async def test_check_fingerprint_aws_s3_detected():
    """AWS S3 'NoSuchBucket' fingerprint should be detected."""
    mock_resp = MagicMock()
    mock_resp.text = "<Error><Code>NoSuchBucket</Code></Error>"
    mock_resp.status_code = 404

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    result = await check_takeover_fingerprint(
        "media.target.com",
        "target.s3.amazonaws.com",
        mock_client,
    )

    assert result is not None, "AWS S3 takeover should be detected"
    assert result.service == "AWS S3"
    assert result.confidence == "certain"
    assert result.severity == "high"


@pytest.mark.asyncio
async def test_sprint21_all_three_takeover_services():
    """Sprint 21.7: All 3 required services (GitHub, Heroku, S3) detected."""
    tests = [
        ("old-blog.target.com", "target-org.github.io",
         "There isn't a GitHub Pages site here", "GitHub Pages"),
        ("app.target.com", "target.herokuapp.com",
         "No such app", "Heroku"),
        ("media.target.com", "target.s3.amazonaws.com",
         "NoSuchBucket", "AWS S3"),
    ]

    passed = 0
    for subdomain, cname, body, expected_service in tests:
        mock_resp = MagicMock()
        mock_resp.text = f"<html><p>{body}</p></html>"
        mock_resp.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        result = await check_takeover_fingerprint(subdomain, cname, mock_client)
        assert result is not None, f"{expected_service}: expected finding, got None"
        assert result.service == expected_service, f"Expected {expected_service}, got {result.service}"
        passed += 1

    assert passed == 3, f"Expected 3/3 passed, got {passed}/3"

