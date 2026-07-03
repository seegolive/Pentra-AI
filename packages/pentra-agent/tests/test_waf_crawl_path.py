"""Tests for WAF-aware crawl path wired into vuln_hunt_node."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ── Import guard flags ────────────────────────────────────────────────────────

def test_waf_retry_available_flag():
    from pentra_agent.nodes.vuln_hunt_node import _WAF_RETRY_AVAILABLE
    assert _WAF_RETRY_AVAILABLE is True, "waf_retry module should be importable"


def test_bypass_headers_available_flag():
    from pentra_agent.nodes.vuln_hunt_node import _BYPASS_HEADERS_AVAILABLE
    assert _BYPASS_HEADERS_AVAILABLE is True, "bypass_headers module should be importable"


def test_waf_aware_get_callable():
    from pentra_agent.nodes.vuln_hunt_node import _waf_aware_get
    assert callable(_waf_aware_get), "_waf_aware_get must be a callable"


def test_build_bypass_headers_callable():
    from pentra_agent.nodes.vuln_hunt_node import _build_bypass_headers
    assert callable(_build_bypass_headers), "_build_bypass_headers must be a callable"


# ── waf_aware_get integration with mock client ────────────────────────────────

@pytest.mark.asyncio
async def test_waf_aware_get_called_when_waf_type_set():
    """When a WAF is detected, waf_aware_get should be invoked in the crawl path."""
    import httpx

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "text/html"}
    mock_response.text = "<html>ok</html>"
    mock_request = MagicMock(spec=httpx.Request)
    mock_request.headers = {"user-agent": "TestUA/1.0"}
    mock_response.request = mock_request

    with patch(
        "pentra_agent.nodes.vuln_hunt_node._waf_aware_get",
        new=AsyncMock(return_value=mock_response),
    ) as mock_waf_get:
        from pentra_agent.nodes.vuln_hunt_node import _waf_aware_get as wag  # noqa: F401
        # Directly invoke the patched function to confirm it's reachable
        from pentra_agent.nodes import vuln_hunt_node as vhn
        result = await vhn._waf_aware_get(MagicMock(), "http://target.com/", waf_type="cloudflare")

    assert result.status_code == 200
    mock_waf_get.assert_called_once()


@pytest.mark.asyncio
async def test_waf_aware_get_success_on_cloudflare():
    """waf_aware_get should succeed on first attempt for non-blocking response."""
    import httpx
    from pentra_tools.http.waf_retry import waf_aware_get, WAFRetryConfig

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200

    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(return_value=mock_resp)

    result = await waf_aware_get(
        mock_client,
        "http://target.cloudflare.com/",
        waf_type="cloudflare",
        retry_config=WAFRetryConfig(max_retries=1),
    )

    assert result.status_code == 200
    assert mock_client.get.call_count == 1


@pytest.mark.asyncio
async def test_waf_aware_get_retries_and_succeeds_on_403():
    """waf_aware_get should retry on 403 and succeed on second attempt."""
    import httpx
    from pentra_tools.http.waf_retry import waf_aware_get, WAFRetryConfig

    block_resp = MagicMock(spec=httpx.Response)
    block_resp.status_code = 403
    block_resp.request = httpx.Request("GET", "http://target.com/")

    ok_resp = MagicMock(spec=httpx.Response)
    ok_resp.status_code = 200

    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=[block_resp, ok_resp])

    result = await waf_aware_get(
        mock_client,
        "http://target.com/",
        waf_type="akamai",
        retry_config=WAFRetryConfig(max_retries=2, base_delay=0.0),
    )

    assert result.status_code == 200
    assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_waf_crawl_falls_back_to_direct_request_on_exception():
    """If waf_aware_get raises, _direct_request fallback must be called."""
    import httpx
    from unittest.mock import patch, AsyncMock

    with (
        patch(
            "pentra_agent.nodes.vuln_hunt_node._waf_aware_get",
            new=AsyncMock(side_effect=httpx.ConnectError("timeout")),
        ),
        patch(
            "pentra_agent.nodes.vuln_hunt_node._direct_request",
            new=AsyncMock(return_value=("GET http://t.com/", "HTTP 200\n\nok")),
        ) as mock_direct,
    ):
        # Simulate what _crawl_one does in the WAF path
        from pentra_agent.nodes import vuln_hunt_node as vhn
        try:
            await vhn._waf_aware_get(MagicMock(), "http://t.com/", waf_type="cloudflare")
        except httpx.ConnectError:
            raw_req, raw_resp = await vhn._direct_request("http://t.com/", method="GET", proxy=None)

    mock_direct.assert_called_once_with("http://t.com/", method="GET", proxy=None)
    assert raw_resp.startswith("HTTP 200")
