import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_waf_detection_cloudflare():
    """Cloudflare header harus terdeteksi."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"cf-ray": "abc123-SIN", "content-type": "text/html"}
    mock_resp.content = b"ok"
    mock_resp.text = "ok"

    with patch("httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_client

        from pentra_tools.recon.waf_profiler import profile_waf
        result = await profile_waf("http://target.com/")

    assert result.waf_detected is True
    assert result.waf_type == "cloudflare"


@pytest.mark.asyncio
async def test_no_waf_detected():
    """Normal server tanpa WAF headers."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/html", "server": "nginx"}
    mock_resp.content = b"ok"
    mock_resp.text = "ok"

    with patch("httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_client

        from pentra_tools.recon.waf_profiler import profile_waf
        result = await profile_waf("http://target.com/")

    assert result.waf_detected is False
    assert result.waf_type is None
