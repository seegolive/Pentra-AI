from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from pentra_tools.crawlers.wayback_crawler import WaybackCrawler, WaybackResult


@pytest.mark.asyncio
async def test_get_urls_success():
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = [
        ["original"],
        ["https://example.com/api/v1/users?id=1"],
        ["https://example.com/admin/dashboard"],
        ["https://example.com/static/style.css"],
        ["https://example.com/logo.png"],
    ]

    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.get = AsyncMock(return_value=response)
        result = await WaybackCrawler().get_urls("example.com")

    assert isinstance(result, WaybackResult)
    assert result.error is None
    assert len(result.urls) == 2
    assert "https://example.com/api/v1/users?id=1" in result.urls
    assert all("style.css" not in url for url in result.urls)
    assert all("logo.png" not in url for url in result.urls)
    assert result.unique_params == ["id"]


def test_filter_urls_filters_static_files():
    crawler = WaybackCrawler()
    raw = [
        "https://example.com/page",
        "https://example.com/image.jpg",
        "https://example.com/font.woff2",
        "https://example.com/style.min.css",
        "https://example.com/script.min.js.map",
        "https://example.com/api?q=test",
    ]

    filtered = crawler._filter_urls(raw, "example.com")

    assert filtered == ["https://example.com/api?q=test", "https://example.com/page"]


def test_filter_urls_deduplicates_fragments_and_trailing_slashes():
    crawler = WaybackCrawler()
    raw = [
        "https://example.com/page",
        "https://example.com/page/",
        "https://example.com/page#anchor",
        "https://example.com/other",
    ]

    filtered = crawler._filter_urls(raw, "example.com")

    assert filtered == ["https://example.com/other", "https://example.com/page"]


@pytest.mark.asyncio
async def test_get_urls_commoncrawl_fallback():
    commoncrawl_response = MagicMock()
    commoncrawl_response.text = '{"url":"https://example.com/api"}\n'

    with patch("httpx.AsyncClient") as client_cls:
        client = client_cls.return_value.__aenter__.return_value
        client.get = AsyncMock(
            side_effect=[
                httpx.TimeoutException("timeout"),
                commoncrawl_response,
            ]
        )
        result = await WaybackCrawler().get_urls("example.com")

    assert result.source == "commoncrawl"
    assert result.urls == ["https://example.com/api"]


@pytest.mark.asyncio
async def test_get_urls_empty_response():
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = []

    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.get = AsyncMock(return_value=response)
        result = await WaybackCrawler().get_urls("example.com")

    assert result.urls == []
    assert result.error is None


@pytest.mark.asyncio
async def test_get_urls_timeout_graceful_when_both_sources_fail():
    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.get = AsyncMock(
            side_effect=httpx.TimeoutException("timeout")
        )
        result = await WaybackCrawler().get_urls("example.com")

    assert result.urls == []
    assert result.error is not None
    assert result.source == "both"


def test_filter_urls_domain_check():
    crawler = WaybackCrawler()
    raw = [
        "https://example.com/page",
        "https://evil.com/page",
        "https://sub.example.com/page",
        "https://notexample.com/page",
    ]

    filtered = crawler._filter_urls(raw, "example.com")

    assert filtered == ["https://example.com/page", "https://sub.example.com/page"]


def test_extract_params():
    crawler = WaybackCrawler()
    urls = [
        "https://example.com/search?q=test&page=1",
        "https://example.com/api?id=5&q=hello",
        "https://example.com/products?cat=2",
        "https://example.com/noparams",
    ]

    params = crawler._extract_params(urls)

    assert params == ["cat", "id", "page", "q"]


def test_normalize_domain_accepts_url_or_host():
    crawler = WaybackCrawler()

    assert crawler._normalize_domain("https://www.example.com/path") == "www.example.com"
    assert crawler._normalize_domain("example.com.") == "example.com"
