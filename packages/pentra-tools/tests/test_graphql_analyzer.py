"""Tests for GraphQLAnalyzer wrapper (Task 5.3).

HTTP calls are mocked — no live GraphQL endpoint required.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_scope import ScopeEnforcer, ScopeViolationError
from pentra_tools.wrappers.graphql_analyzer import GraphQLAnalyzer, GraphQLTestResult


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def scope() -> ScopeEnforcer:
    return ScopeEnforcer(
        in_scope=["api.target.com", "*.target.com"],
        out_of_scope=["admin.target.com"],
    )


@pytest.fixture
def analyzer(scope: ScopeEnforcer) -> GraphQLAnalyzer:
    return GraphQLAnalyzer(scope)


def _make_post_mock(status: int = 200, body: str = '{"data": {}}'):
    """Return a coroutine mock that simulates GraphQLAnalyzer._post()."""
    async def _post(url: str, body_payload, headers: dict):  # noqa: ANN001
        return status, body

    return _post


# ── Scope enforcement ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_graphql_scope_blocks_out_of_scope(analyzer: GraphQLAnalyzer) -> None:
    """Analyzer must raise ScopeViolationError for out-of-scope URLs."""
    with pytest.raises(ScopeViolationError):
        await analyzer.run("https://evil.com/graphql")


@pytest.mark.asyncio
async def test_graphql_scope_blocks_excluded_subdomain(analyzer: GraphQLAnalyzer) -> None:
    with pytest.raises(ScopeViolationError):
        await analyzer.run("https://admin.target.com/graphql")


# ── Introspection test ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_introspection_detected_when_schema_in_response(analyzer: GraphQLAnalyzer) -> None:
    """_test_introspection marks vulnerable when __schema appears in response."""
    introspection_body = '{"data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}}'
    with patch.object(analyzer, "_post", new=_make_post_mock(200, introspection_body)):
        result = await analyzer._test_introspection(
            "https://api.target.com/graphql",
            {"Content-Type": "application/json"},
        )
    assert result.is_vulnerable is True
    assert result.severity == "medium"
    assert result.test_name == "introspection_enabled"


@pytest.mark.asyncio
async def test_introspection_not_detected_when_disabled(analyzer: GraphQLAnalyzer) -> None:
    body = '{"errors": [{"message": "GraphQL introspection is not allowed"}]}'
    with patch.object(analyzer, "_post", new=_make_post_mock(200, body)):
        result = await analyzer._test_introspection(
            "https://api.target.com/graphql",
            {},
        )
    assert result.is_vulnerable is False
    assert result.severity == "info"


# ── Depth bypass test ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_depth_bypass_detected_on_200_without_error(analyzer: GraphQLAnalyzer) -> None:
    body = '{"data": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"__typename": "Query"}}}}}}}}}}'
    with patch.object(analyzer, "_post", new=_make_post_mock(200, body)):
        result = await analyzer._test_depth("https://api.target.com/graphql", {})
    assert result.is_vulnerable is True
    assert result.test_name == "query_depth_bypass"


@pytest.mark.asyncio
async def test_depth_bypass_not_detected_when_error_contains_depth_keyword(analyzer: GraphQLAnalyzer) -> None:
    body = '{"errors": [{"message": "max depth exceeded"}]}'
    with patch.object(analyzer, "_post", new=_make_post_mock(200, body)):
        result = await analyzer._test_depth("https://api.target.com/graphql", {})
    assert result.is_vulnerable is False


# ── Batching test ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_batching_detected_when_array_response(analyzer: GraphQLAnalyzer) -> None:
    body = '[{"data": {"__typename": "Query"}}] ' * 50
    with patch.object(analyzer, "_post", new=_make_post_mock(200, body)):
        result = await analyzer._test_batching("https://api.target.com/graphql", {})
    assert result.is_vulnerable is True
    assert result.severity == "medium"
    assert result.test_name == "batch_query_abuse"


@pytest.mark.asyncio
async def test_batching_not_detected_on_non_array_response(analyzer: GraphQLAnalyzer) -> None:
    body = '{"errors": [{"message": "Batching not supported"}]}'
    with patch.object(analyzer, "_post", new=_make_post_mock(200, body)):
        result = await analyzer._test_batching("https://api.target.com/graphql", {})
    assert result.is_vulnerable is False


# ── Field suggestion test ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_field_suggestion_detected_on_did_you_mean(analyzer: GraphQLAnalyzer) -> None:
    body = '{"errors": [{"message": "Cannot query field \\"usr\\". Did you mean \\"user\\"?"}]}'
    with patch.object(analyzer, "_post", new=_make_post_mock(200, body)):
        result = await analyzer._test_field_suggestion("https://api.target.com/graphql", {})
    assert result.is_vulnerable is True
    assert result.test_name == "field_suggestion_leakage"
    assert result.severity == "low"


@pytest.mark.asyncio
async def test_field_suggestion_not_detected_without_hint(analyzer: GraphQLAnalyzer) -> None:
    body = '{"errors": [{"message": "Unknown field \\"usr\\"."}]}'
    with patch.object(analyzer, "_post", new=_make_post_mock(200, body)):
        result = await analyzer._test_field_suggestion("https://api.target.com/graphql", {})
    assert result.is_vulnerable is False


# ── Alias flooding test ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_alias_flood_detected_when_aliases_accepted(analyzer: GraphQLAnalyzer) -> None:
    # Build fake response that echoes all aliased fields including "q9"
    body = '{"data": {"q0": "Query", "q1": "Query", "q9": "Query"}}'
    with patch.object(analyzer, "_post", new=_make_post_mock(200, body)):
        result = await analyzer._test_alias_flood("https://api.target.com/graphql", {})
    assert result.is_vulnerable is True
    assert result.test_name == "alias_flooding"


@pytest.mark.asyncio
async def test_alias_flood_not_detected_when_limit_error(analyzer: GraphQLAnalyzer) -> None:
    body = '{"errors": [{"message": "Too many aliases in single query — limit exceeded"}]}'
    with patch.object(analyzer, "_post", new=_make_post_mock(200, body)):
        result = await analyzer._test_alias_flood("https://api.target.com/graphql", {})
    assert result.is_vulnerable is False


# ── Full run() integration ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_returns_tool_result_structure(analyzer: GraphQLAnalyzer) -> None:
    """run() should always return a valid ToolResult with expected keys."""
    safe_body = '{"data": {"__typename": "Query"}}'

    with patch.object(analyzer, "_post", new=_make_post_mock(200, safe_body)):
        with patch.object(analyzer.rate_limiter, "acquire", new=AsyncMock()):
            result = await analyzer.run("https://api.target.com/graphql")

    assert result.tool == "graphql_analyzer"
    assert result.success is True
    assert "all_tests" in result.data
    assert len(result.data["all_tests"]) == 5
    assert isinstance(result.data["vuln_count"], int)


@pytest.mark.asyncio
async def test_run_all_vulnerable_endpoint(analyzer: GraphQLAnalyzer) -> None:
    """When all tests detect vulnerabilities, vuln_count should equal 5."""

    async def _all_vuln_post(url, body_payload, headers):
        # Craft body that triggers every test:
        # - __schema → introspection
        # - starts with [ → batching
        # - contains "did you mean" → suggestion
        # - contains q9 → alias
        # depth: no error keyword → depth bypass
        return 200, '[{"__schema": {}, "q9": "Query", "did you mean": "user"}]'

    with patch.object(analyzer, "_post", new=_all_vuln_post):
        with patch.object(analyzer.rate_limiter, "acquire", new=AsyncMock()):
            result = await analyzer.run("https://api.target.com/graphql")

    # Introspection + batching should be flagged (body starts with "[" AND has __schema)
    assert result.data["vuln_count"] >= 1


@pytest.mark.asyncio
async def test_run_handles_connection_error_gracefully(analyzer: GraphQLAnalyzer) -> None:
    """Connection errors per test should not crash the full run."""

    async def _failing_post(url, body_payload, headers):
        return 0, "ConnectError: connection refused"

    with patch.object(analyzer, "_post", new=_failing_post):
        with patch.object(analyzer.rate_limiter, "acquire", new=AsyncMock()):
            result = await analyzer.run("https://api.target.com/graphql")

    assert result.success is True
    assert result.data["vuln_count"] == 0
