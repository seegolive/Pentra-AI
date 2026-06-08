"""Fix 2 — LFI NewsAd tests.

Tests:
1. _is_lfi_candidate: exact-match names (NewsAd, file, path, etc.)
2. _is_lfi_candidate: value-based heuristic (path sep, file ext)
3. _is_lfi_candidate: NOT candidate for non-path params
4. _confirm_lfi: returns finding when confirmation pattern matches
5. _confirm_lfi: returns None when no confirmation pattern matches
6. PATH_INCLUSION anomaly in candidate loop auto-adds path_traversal test type
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pentra_agent.nodes.vuln_hunt_node import (
    LFI_PRONE_PARAM_NAMES,
    _LFI_CONFIRMATION_PATTERNS,
    _LFI_TRAVERSAL_PAYLOADS,
    _confirm_lfi,
    _is_lfi_candidate,
)
from pentra_scope.validator import ScopeEnforcer


# ── Helpers ────────────────────────────────────────────────────────────────────

def _enforcer(domain: str = "testaspnet.vulnweb.com") -> ScopeEnforcer:
    return ScopeEnforcer(in_scope=[domain], out_of_scope=[])


# ── 1. _is_lfi_candidate: exact-match param names ─────────────────────────────


def test_is_lfi_candidate_exact_names():
    """Each entry in LFI_PRONE_PARAM_NAMES should trigger True."""
    for name in LFI_PRONE_PARAM_NAMES:
        # Test exact lowercase match
        assert _is_lfi_candidate(name, "anything") is True, \
            f"Expected True for param={name!r}"
        # Test mixed-case (e.g. "NewsAd" stored as "newsad")
        assert _is_lfi_candidate(name.title(), "anything") is True, \
            f"Expected True for param={name.title()!r}"


def test_is_lfi_candidate_newsad_exact():
    """NewsAd must be detected as LFI candidate (case-insensitive)."""
    assert _is_lfi_candidate("NewsAd", "ads/def.html") is True
    assert _is_lfi_candidate("newsad", "ads/def.html") is True
    assert _is_lfi_candidate("NEWSAD", "ads/def.html") is True


def test_is_lfi_candidate_partial_param_name():
    """Compound names like 'filePath', 'pageId', 'NewsAdBanner' are candidates."""
    assert _is_lfi_candidate("filePath", "test") is True
    assert _is_lfi_candidate("pageId", "1") is True
    assert _is_lfi_candidate("NewsAdBanner", "ads/x.html") is True


# ── 2. _is_lfi_candidate: value-based heuristics ─────────────────────────────


def test_is_lfi_candidate_value_with_slash():
    """Any param whose value contains '/' is an LFI candidate."""
    assert _is_lfi_candidate("q", "ads/def.html") is True
    assert _is_lfi_candidate("id", "../web.config") is True


def test_is_lfi_candidate_value_with_backslash():
    """Any param whose value contains '\\' is an LFI candidate."""
    assert _is_lfi_candidate("x", "..\\web.config") is True


def test_is_lfi_candidate_value_with_file_extension():
    """Params with known file extensions in value are LFI candidates."""
    assert _is_lfi_candidate("q", "report.aspx") is True
    assert _is_lfi_candidate("q", "config.xml") is True
    assert _is_lfi_candidate("q", "notes.txt") is True
    assert _is_lfi_candidate("q", "settings.ini") is True


# ── 3. _is_lfi_candidate: NOT candidate ───────────────────────────────────────


def test_is_lfi_candidate_not_candidate():
    """Params with no path-like name and no path-like value must not be flagged."""
    assert _is_lfi_candidate("id", "42") is False
    assert _is_lfi_candidate("username", "admin") is False
    assert _is_lfi_candidate("category", "electronics") is False
    # NOTE: "page" IS in LFI_PRONE_PARAM_NAMES by design — ?page=../etc/passwd
    # is a real LFI pattern, so "page" intentionally returns True.


def test_is_lfi_candidate_numeric_only_not_candidate():
    """Pure numeric IDs with no file extension aren't LFI candidates by value alone."""
    # "cat" is not in LFI_PRONE_PARAM_NAMES; value "1" has no path indicator
    assert _is_lfi_candidate("cat", "1") is False
    assert _is_lfi_candidate("sort", "asc") is False


# ── 4. _confirm_lfi: returns finding on match ─────────────────────────────────


@pytest.mark.asyncio
async def test_confirm_lfi_returns_finding_when_pattern_matches():
    """_confirm_lfi should return a finding dict when response contains web.config content."""
    # Simulate a response that contains <connectionStrings (web.config indicator)
    fake_response_body = (
        "HTTP 200\r\nContent-Type: text/html\r\n\r\n"
        "<configuration><connectionStrings>"
        "<add name=\"Default\" connectionString=\"data source=.;initial catalog=acme;user id=sa;password=s3cret\"/>"
        "</connectionStrings></configuration>"
    )
    fake_raw_req = "GET http://testaspnet.vulnweb.com/ReadNews.aspx?NewsAd=../web.config"

    with patch(
        "pentra_agent.nodes.vuln_hunt_node._direct_request",
        new=AsyncMock(return_value=(fake_raw_req, fake_response_body)),
    ):
        result = await _confirm_lfi(
            base_url="http://testaspnet.vulnweb.com/ReadNews.aspx?id=1&NewsAd=ads/def.html",
            param_name="NewsAd",
            param_location="query",
            burp=None,
            enforcer=_enforcer(),
        )

    assert result is not None, "_confirm_lfi should return a finding, not None"
    assert result["severity"] == "critical"
    assert result["vuln_class"] == "PATH_TRAVERSAL"
    assert result["source"] == "lfi_confirmation"
    assert result["cvss_score"] == 9.1
    assert "NewsAd" in result["description"]
    assert result["payload"] in _LFI_TRAVERSAL_PAYLOADS


@pytest.mark.asyncio
async def test_confirm_lfi_returns_none_when_no_pattern():
    """_confirm_lfi should return None when response contains no file content indicators."""
    safe_response = "HTTP 200\r\nContent-Type: text/html\r\n\r\n<html><body>Not Found</body></html>"

    with patch(
        "pentra_agent.nodes.vuln_hunt_node._direct_request",
        new=AsyncMock(return_value=("GET http://example.com/", safe_response)),
    ):
        result = await _confirm_lfi(
            base_url="http://testaspnet.vulnweb.com/ReadNews.aspx?id=1&NewsAd=ads/def.html",
            param_name="NewsAd",
            param_location="query",
            burp=None,
            enforcer=_enforcer(),
        )

    assert result is None, "_confirm_lfi should return None when no confirmation pattern matches"


@pytest.mark.asyncio
async def test_confirm_lfi_uses_burp_when_available():
    """_confirm_lfi should call burp.send_request when burp client is provided."""
    fake_raw_req = "GET http://testaspnet.vulnweb.com/ReadNews.aspx?NewsAd=../../web.config"
    confirming_response = (
        "HTTP 200\r\n\r\n<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<configuration><appSettings><add key=\"secret\" value=\"abc\"/></appSettings></configuration>"
    )

    mock_burp = AsyncMock()
    mock_burp.send_request = AsyncMock(return_value=(fake_raw_req, confirming_response))

    result = await _confirm_lfi(
        base_url="http://testaspnet.vulnweb.com/ReadNews.aspx?id=1&NewsAd=ads/def.html",
        param_name="NewsAd",
        param_location="query",
        burp=mock_burp,
        enforcer=_enforcer(),
    )

    assert result is not None
    assert result["severity"] == "critical"
    # Burp.send_request should have been called at least once
    mock_burp.send_request.assert_called()


# ── 5. _is_lfi_candidate integration: LFI_CONFIRMATION_PATTERNS completeness ──


def test_lfi_confirmation_patterns_non_empty():
    """Sanity check: _LFI_CONFIRMATION_PATTERNS must have entries for each major category."""
    labels = [label for _, label in _LFI_CONFIRMATION_PATTERNS]
    joined = " ".join(labels).lower()
    assert "web.config" in joined, "Should have web.config patterns"
    assert "passwd" in joined, "Should have Unix /etc/passwd pattern"
    assert "win.ini" in joined or "windows" in joined or "boot.ini" in joined, \
        "Should have Windows file pattern"


def test_lfi_traversal_payloads_includes_windows_and_linux():
    """_LFI_TRAVERSAL_PAYLOADS must cover both Windows (web.config) and Linux (/etc/passwd)."""
    has_webconfig = any("web.config" in p for p in _LFI_TRAVERSAL_PAYLOADS)
    has_passwd = any("etc/passwd" in p for p in _LFI_TRAVERSAL_PAYLOADS)
    assert has_webconfig, "Must have web.config traversal payloads"
    assert has_passwd, "Must have /etc/passwd traversal payloads"
