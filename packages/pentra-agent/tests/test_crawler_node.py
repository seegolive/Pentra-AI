"""Tests for crawler_node — SPA endpoint discovery via Playwright."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from pentra_tools.crawlers.js_crawler import CrawlResult, DiscoveredEndpoint
from pentra_agent.nodes.crawler_node import crawler_node, _parse_cookies


# ── _parse_cookies ────────────────────────────────────────────────────────────

def test_parse_cookies_single_cookie():
    result = _parse_cookies("session=abc123")
    assert result == [{"name": "session", "value": "abc123"}]


def test_parse_cookies_multiple_cookies():
    result = _parse_cookies("session=abc; csrf=xyz123")
    assert len(result) == 2
    assert result[0] == {"name": "session", "value": "abc"}
    assert result[1] == {"name": "csrf", "value": "xyz123"}


# ── crawler_node ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_crawler_node_skips_if_no_hosts():
    state = {"subdomains": [], "auth_credentials": None}
    result = await crawler_node(state)
    assert result["js_crawl_result"]["skipped"] is True
    assert result["js_crawl_result"]["endpoints"] == []


@pytest.mark.asyncio
async def test_crawler_node_returns_js_crawl_result_key():
    state = {
        "subdomains": [{"host": "target.com", "is_alive": True}],
        "auth_credentials": None,
    }
    with patch("pentra_agent.nodes.crawler_node.JSCrawler") as MockCrawler:
        mock_result = CrawlResult(
            endpoints=[DiscoveredEndpoint(url="http://target.com/api/v1", method="GET")],
            forms=[],
            js_files=[],
            api_calls=[],
            crawl_time_ms=500.0,
        )
        MockCrawler.return_value.crawl = AsyncMock(return_value=mock_result)

        result = await crawler_node(state)

    assert "js_crawl_result" in result
    assert "endpoints" in result["js_crawl_result"]
    assert len(result["js_crawl_result"]["endpoints"]) == 1


@pytest.mark.asyncio
async def test_crawler_node_playwright_unavailable_graceful():
    state = {
        "subdomains": [{"host": "target.com", "is_alive": True}],
        "auth_credentials": None,
    }
    with patch("pentra_agent.nodes.crawler_node.JSCrawler") as MockCrawler:
        mock_result = CrawlResult(
            endpoints=[],
            forms=[],
            js_files=[],
            api_calls=[],
            crawl_time_ms=0,
            error="Playwright not installed. Run: pip install playwright",
            used_js_crawler=False,
        )
        MockCrawler.return_value.crawl = AsyncMock(return_value=mock_result)

        result = await crawler_node(state)

    assert "js_crawl_result" in result
    # No exception raised — graceful
    assert result["js_crawl_result"]["endpoints"] == []
