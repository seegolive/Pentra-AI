"""Tests for OSINT Node — Task 15.5"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_crt_sh_returns_subdomains():
    """_query_crt_sh harus return list subdomain dari response crt.sh."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {"name_value": "api.target.com"},
        {"name_value": "admin.target.com"},
        {"name_value": "*.target.com"},  # wildcard harus di-strip ke target.com → excluded (== domain)
    ]

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("httpx.AsyncClient", return_value=mock_client):
        from pentra_agent.nodes.osint_node import _query_crt_sh
        result = await _query_crt_sh("target.com")

    assert "api.target.com" in result
    assert "admin.target.com" in result
    # root domain itself should be excluded
    assert "target.com" not in result


@pytest.mark.asyncio
async def test_osint_node_graceful_on_all_sources_fail():
    """osint_node harus return dict kosong + AIMessage jika semua sources gagal."""
    with (
        patch("pentra_agent.nodes.osint_node._query_crt_sh", AsyncMock(return_value=[])),
        patch("pentra_agent.nodes.osint_node._lookup_h1_program", AsyncMock(return_value=None)),
        patch.dict("os.environ", {}, clear=False),
    ):
        # Remove SHODAN_API_KEY if set
        import os
        os.environ.pop("SHODAN_API_KEY", None)

        from pentra_agent.nodes.osint_node import osint_node

        state = {
            "target": {"domain": "testaspnet.vulnweb.com"},
            "scope": {"in_scope": ["testaspnet.vulnweb.com"], "out_of_scope": []},
        }

        result = await osint_node(state)  # type: ignore[arg-type]

    assert "osint_results" in result
    assert result["osint_results"] == {}
    assert "messages" in result
    assert len(result["messages"]) == 1
    # Message should mention "No significant OSINT data"
    assert "No significant OSINT data" in result["messages"][0].content


@pytest.mark.asyncio
async def test_osint_node_enriches_subdomains_from_crt():
    """osint_node harus seed subdomains dari CT data."""
    ct_subs = ["api.target.com", "admin.target.com"]

    with (
        patch("pentra_agent.nodes.osint_node._query_crt_sh", AsyncMock(return_value=ct_subs)),
        patch("pentra_agent.nodes.osint_node._lookup_h1_program", AsyncMock(return_value=None)),
    ):
        import os
        os.environ.pop("SHODAN_API_KEY", None)

        from pentra_agent.nodes.osint_node import osint_node

        state = {
            "target": {"domain": "target.com"},
            "scope": {"in_scope": ["target.com"], "out_of_scope": []},
        }

        result = await osint_node(state)  # type: ignore[arg-type]

    assert len(result["subdomains"]) == 2
    hosts = [s["host"] for s in result["subdomains"]]
    assert "api.target.com" in hosts
    assert "admin.target.com" in hosts
    assert all(s["source"] == "crt.sh" for s in result["subdomains"])
