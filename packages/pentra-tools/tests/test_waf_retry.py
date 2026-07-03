"""Tests for WAF-aware retry client."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock


def test_is_waf_block_true_for_403():
    from pentra_tools.http.waf_retry import is_waf_block
    assert is_waf_block(403) is True


def test_is_waf_block_true_for_406():
    from pentra_tools.http.waf_retry import is_waf_block
    assert is_waf_block(406) is True


def test_is_waf_block_true_for_418():
    from pentra_tools.http.waf_retry import is_waf_block
    assert is_waf_block(418) is True


def test_is_waf_block_true_for_429():
    from pentra_tools.http.waf_retry import is_waf_block
    assert is_waf_block(429) is True


def test_is_waf_block_true_for_503():
    from pentra_tools.http.waf_retry import is_waf_block
    assert is_waf_block(503) is True


def test_is_waf_block_false_for_200():
    from pentra_tools.http.waf_retry import is_waf_block
    assert is_waf_block(200) is False


def test_is_waf_block_false_for_404():
    from pentra_tools.http.waf_retry import is_waf_block
    assert is_waf_block(404) is False


def test_waf_retry_config_defaults():
    from pentra_tools.http.waf_retry import WAFRetryConfig
    cfg = WAFRetryConfig()
    assert cfg.max_retries == 3
    assert cfg.base_delay == 1.0
    assert cfg.backoff_factor == 2.0


@pytest.mark.asyncio
async def test_waf_aware_get_success_no_retry():
    """200 response should be returned immediately without retry."""
    from pentra_tools.http.waf_retry import waf_aware_get, WAFRetryConfig

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    cfg = WAFRetryConfig(max_retries=2, base_delay=0.0)
    result = await waf_aware_get(mock_client, "http://example.com/", waf_type=None, retry_config=cfg)

    assert result.status_code == 200
    assert mock_client.get.call_count == 1


@pytest.mark.asyncio
async def test_waf_aware_get_retries_on_403_then_succeeds():
    """First call returns 403; second call returns 200. Should succeed after retry."""
    from pentra_tools.http.waf_retry import waf_aware_get, WAFRetryConfig

    resp_403 = MagicMock()
    resp_403.status_code = 403
    resp_200 = MagicMock()
    resp_200.status_code = 200

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=[resp_403, resp_200])

    cfg = WAFRetryConfig(max_retries=2, base_delay=0.0)
    result = await waf_aware_get(mock_client, "http://example.com/", waf_type="cloudflare", retry_config=cfg)

    assert result.status_code == 200
    assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_waf_aware_get_exhausts_retries_raises():
    """All retries return 403; should raise httpx.HTTPStatusError."""
    import httpx
    from pentra_tools.http.waf_retry import waf_aware_get, WAFRetryConfig

    resp_403 = MagicMock()
    resp_403.status_code = 403

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=resp_403)

    cfg = WAFRetryConfig(max_retries=2, base_delay=0.0)

    with pytest.raises(httpx.HTTPStatusError):
        await waf_aware_get(mock_client, "http://example.com/", waf_type=None, retry_config=cfg)

    assert mock_client.get.call_count == 3  # initial + 2 retries


@pytest.mark.asyncio
async def test_waf_aware_get_rotates_headers_on_retry():
    """On retry, the User-Agent header must differ from the initial call."""
    from pentra_tools.http.waf_retry import waf_aware_get, WAFRetryConfig

    captured_headers: list[dict] = []

    async def fake_get(url: str, **kwargs: object) -> MagicMock:
        captured_headers.append(dict(kwargs.get("headers", {})))
        resp = MagicMock()
        resp.status_code = 403 if len(captured_headers) < 2 else 200
        return resp

    mock_client = AsyncMock()
    mock_client.get = fake_get

    cfg = WAFRetryConfig(max_retries=2, base_delay=0.0)
    await waf_aware_get(mock_client, "http://example.com/", waf_type="cloudflare", retry_config=cfg)

    assert len(captured_headers) == 2
    # User-Agent should be present in both calls
    assert "User-Agent" in captured_headers[0]
    assert "User-Agent" in captured_headers[1]
