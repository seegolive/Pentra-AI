"""WAF-aware HTTP GET with automatic retry on block responses.

When a WAF blocks a request (403/406/418/429/503), this module retries
with a fresh User-Agent and bypass headers so the scanner can continue.
"""
from __future__ import annotations
import asyncio
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

WAF_BLOCK_CODES: frozenset[int] = frozenset({403, 406, 418, 429, 503})


@dataclass
class WAFRetryConfig:
    max_retries: int = 3
    base_delay: float = 1.0
    backoff_factor: float = 2.0


def is_waf_block(status_code: int) -> bool:
    """Return True if the status code indicates a WAF block."""
    return status_code in WAF_BLOCK_CODES


async def waf_aware_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    waf_type: str | None = None,
    retry_config: WAFRetryConfig | None = None,
    extra_headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Perform a GET request with automatic retry on WAF block responses.

    On each retry:
    1. A fresh random User-Agent is selected (or WAF-preferred UA)
    2. Bypass headers (X-Forwarded-For etc.) are injected with a new IP
    3. Exponential backoff is applied between retries

    Args:
        client: An existing httpx.AsyncClient instance
        url: URL to GET
        waf_type: WAF type string for targeted UA/header selection
        retry_config: Retry behaviour. If None, uses WAFRetryConfig defaults
        extra_headers: Additional headers to merge (caller-supplied, not overridden)

    Returns:
        httpx.Response on success (non-block status code)

    Raises:
        httpx.HTTPStatusError: If all retries are exhausted and last response is a block
    """
    cfg = retry_config or WAFRetryConfig()

    try:
        from pentra_tools.http.user_agent_rotator import get_ua_for_waf
        from pentra_tools.http.bypass_headers import build_bypass_headers
    except ImportError:
        get_ua_for_waf = lambda _wt: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"  # noqa: E731
        build_bypass_headers = lambda _wt, spoof_ip=None: {}  # noqa: E731

    last_response: httpx.Response | None = None
    attempts = 0
    max_attempts = 1 + cfg.max_retries

    while attempts < max_attempts:
        ua = get_ua_for_waf(waf_type)
        headers: dict[str, str] = {"User-Agent": ua}
        if attempts > 0:
            # Only inject bypass headers on retry attempts
            bypass = build_bypass_headers(waf_type)
            headers.update(bypass)
        if extra_headers:
            headers.update(extra_headers)

        try:
            response = await client.get(url, headers=headers)
        except httpx.RequestError:
            raise

        if not is_waf_block(response.status_code):
            return response

        last_response = response
        attempts += 1

        if attempts < max_attempts:
            delay = cfg.base_delay * (cfg.backoff_factor ** (attempts - 1))
            logger.debug(
                "[waf_retry] WAF block %d on %s — retry %d/%d in %.1fs (UA rotated)",
                response.status_code, url, attempts, cfg.max_retries, delay,
            )
            if delay > 0:
                await asyncio.sleep(delay)

    logger.warning(
        "[waf_retry] All %d attempts blocked for %s (last status=%d)",
        max_attempts, url, last_response.status_code if last_response else 0,
    )
    raise httpx.HTTPStatusError(
        f"WAF block after {max_attempts} attempts: {last_response.status_code if last_response else '?'}",
        request=last_response.request if last_response else httpx.Request("GET", url),
        response=last_response or httpx.Response(503),
    )
