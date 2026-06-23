from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from pentra_tools.osint.dorking import DorkResult, DorkScanner, SECURITY_DORKS


@pytest.mark.asyncio
async def test_run_dorks_returns_result():
    scanner = DorkScanner(delay_between_dorks=0)
    scanner._search = AsyncMock(return_value=["https://example.com/login"])  # type: ignore[method-assign]

    result = await scanner.run_dorks("example.com", categories=["login_pages"])

    assert isinstance(result, DorkResult)
    assert result.domain == "example.com"
    assert result.total_results == 1
    assert result.login_pages == ["https://example.com/login"]


@pytest.mark.asyncio
async def test_run_dorks_formats_domain_in_queries():
    scanner = DorkScanner(delay_between_dorks=0)
    scanner._search = AsyncMock(return_value=[])  # type: ignore[method-assign]

    await scanner.run_dorks("example.com", categories=["api_endpoints"])

    queries = [call.args[0] for call in scanner._search.call_args_list]
    assert all("example.com" in query for query in queries)
    assert len(queries) == len(SECURITY_DORKS["api_endpoints"])


@pytest.mark.asyncio
async def test_run_dorks_deduplicates_results():
    scanner = DorkScanner(delay_between_dorks=0)
    scanner._search = AsyncMock(
        return_value=["https://example.com/login", "https://example.com/login"]
    )  # type: ignore[method-assign]

    result = await scanner.run_dorks("example.com", categories=["login_pages"])

    assert result.total_results == 1
    assert result.login_pages == ["https://example.com/login"]


@pytest.mark.asyncio
async def test_run_dorks_populates_high_risk_urls():
    scanner = DorkScanner(delay_between_dorks=0)

    async def fake_search(query: str) -> list[str]:
        if "login" in query:
            return ["https://example.com/login"]
        if "admin" in query:
            return ["https://example.com/admin"]
        if "env" in query:
            return ["https://example.com/.env"]
        return []

    scanner._search = fake_search  # type: ignore[method-assign]

    result = await scanner.run_dorks(
        "example.com",
        categories=["login_pages", "admin_panels", "sensitive_files"],
    )

    assert set(result.high_risk_urls) == {
        "https://example.com/.env",
        "https://example.com/admin",
        "https://example.com/login",
    }


@pytest.mark.asyncio
async def test_run_dorks_handles_search_error():
    scanner = DorkScanner(delay_between_dorks=0)
    scanner._search = AsyncMock(side_effect=RuntimeError("blocked"))  # type: ignore[method-assign]

    result = await scanner.run_dorks("example.com", categories=["login_pages"])

    assert result.total_results == 0
    assert result.login_pages == []


@pytest.mark.asyncio
async def test_run_dorks_unknown_category_is_empty():
    scanner = DorkScanner(delay_between_dorks=0)
    scanner._search = AsyncMock(return_value=["https://example.com/login"])  # type: ignore[method-assign]

    result = await scanner.run_dorks("example.com", categories=["unknown"])

    assert result.by_category["unknown"] == []
    scanner._search.assert_not_called()


def test_categorize_url_login():
    assert DorkScanner().categorize_url("https://example.com/login") == "login"


def test_categorize_url_admin():
    assert DorkScanner().categorize_url("https://example.com/wp-admin/") == "admin"


def test_categorize_url_api_and_sensitive():
    scanner = DorkScanner()

    assert scanner.categorize_url("https://example.com/graphql") == "api"
    assert scanner.categorize_url("https://example.com/backups/db.sql") == "sensitive"


def test_categorize_url_other():
    assert DorkScanner().categorize_url("https://example.com/about") == "other"


def test_normalize_domain_accepts_full_url():
    scanner = DorkScanner()

    assert scanner._normalize_domain("https://sub.example.com/path") == "sub.example.com"
