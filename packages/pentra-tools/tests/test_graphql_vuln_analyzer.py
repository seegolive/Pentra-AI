"""Tests for GraphQL Analyzer — Task 19.1 (Sprint 19).

Tests the new pentra_tools.vuln.graphql_analyzer module.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_detect_graphql_endpoint_found():
    """Endpoint that responds with data.__typename should be detected."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.text = '{"data": {"__typename": "Query"}}'
    mock_resp.json.return_value = {"data": {"__typename": "Query"}}

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)

    from pentra_tools.vuln.graphql_analyzer import detect_graphql_endpoints
    result = await detect_graphql_endpoints("http://target.com", mock_client)

    assert len(result) > 0
    assert any("graphql" in url or "query" in url for url in result)


def test_parse_schema_extracts_queries():
    """parse_schema should extract query and mutation names."""
    from pentra_tools.vuln.graphql_analyzer import parse_schema

    schema = {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [{"name": "getUser"}, {"name": "listProducts"}]},
            {"name": "Mutation", "fields": [{"name": "createUser"}, {"name": "updateUser"}]},
            {"name": "User", "fields": [{"name": "id"}, {"name": "email"}]},
        ],
    }
    queries, mutations = parse_schema(schema)
    assert "getUser" in queries
    assert "listProducts" in queries
    assert "createUser" in mutations
    assert "updateUser" in mutations
    # User type should not appear in queries or mutations
    assert "id" not in queries


@pytest.mark.asyncio
async def test_introspection_enabled_returns_finding():
    """test_introspection_enabled should return a finding when schema is present."""
    from pentra_tools.vuln.graphql_analyzer import test_introspection_enabled

    fake_schema = {
        "queryType": {"name": "Query"},
        "types": [{"name": "Query"}, {"name": "User"}, {"name": "Product"}],
    }
    result = await test_introspection_enabled("http://t.com/graphql", fake_schema)

    assert result is not None
    assert result.severity == "low"
    assert "Introspection" in result.title
    assert result.vuln_class == "INFORMATION_DISCLOSURE"


@pytest.mark.asyncio
async def test_introspection_disabled_returns_none():
    """test_introspection_enabled should return None when schema is None."""
    from pentra_tools.vuln.graphql_analyzer import test_introspection_enabled

    result = await test_introspection_enabled("http://t.com/graphql", None)
    assert result is None


@pytest.mark.asyncio
async def test_sqli_detection_via_sql_error():
    """SQLi should be detected when response contains SQL error string."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"errors": [{"message": "mysql error: syntax error near SELECT"}]}'

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)

    from pentra_tools.vuln.graphql_analyzer import test_sqli_via_graphql

    results = await test_sqli_via_graphql(
        "http://t.com/graphql",
        mock_client,
        queries=["getProduct"],
    )

    assert len(results) > 0
    assert results[0].vuln_class == "SQL_INJECTION"
    assert results[0].severity == "critical"
    assert "mysql error" in results[0].evidence.lower() or "SQL_INJECTION" in results[0].vuln_class
