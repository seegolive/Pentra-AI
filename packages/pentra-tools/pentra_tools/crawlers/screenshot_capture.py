"""
Screenshot capture for each live host using Playwright.
Playwright is an optional dependency (extras: screenshot).
When unavailable, all results return error='Playwright not available'.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class ScreenshotResult:
    url: str
    host: str
    screenshot_bytes: Optional[bytes]
    title: Optional[str]
    status_code: Optional[int]
    error: Optional[str]
    captured_at: datetime
    minio_url: Optional[str] = None


def _check_playwright() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


class ScreenshotCapture:
    """Playwright-based screenshot capture for reconnaissance.

    Requires the optional 'screenshot' extras group:
        uv add --optional screenshot playwright

    Falls back gracefully when Playwright is not installed — all
    ``capture`` / ``capture_batch`` calls return results with
    ``error='Playwright not available'`` instead of raising.
    """

    VIEWPORT = {"width": 1280, "height": 800}
    PAGE_TIMEOUT_MS = 10_000  # 10 s per page

    def __init__(self, headless: bool = True):
        self.headless = headless
        self._available = _check_playwright()
        if not self._available:
            logger.info(
                "[screenshot] Playwright not installed — "
                "screenshots disabled. Install with: uv add playwright"
            )

    async def capture(
        self,
        url: str,
        cookies: Optional[list[dict]] = None,
    ) -> ScreenshotResult:
        """Capture a screenshot of ``url``.

        Returns a ``ScreenshotResult`` — never raises.
        ``screenshot_bytes`` is ``None`` if capture fails.
        """
        host = urlparse(url).netloc or url
        now = datetime.utcnow()

        if not self._available:
            return ScreenshotResult(
                url=url,
                host=host,
                screenshot_bytes=None,
                title=None,
                status_code=None,
                error="Playwright not available",
                captured_at=now,
            )

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                ctx = await browser.new_context(
                    viewport=self.VIEWPORT,
                    ignore_https_errors=True,
                )
                if cookies:
                    await ctx.add_cookies(cookies)

                page = await ctx.new_page()
                resp = await page.goto(
                    url,
                    timeout=self.PAGE_TIMEOUT_MS,
                    wait_until="domcontentloaded",
                )
                await asyncio.sleep(1)  # let JS finish rendering

                title = await page.title()
                screenshot = await page.screenshot(full_page=False)
                status = resp.status if resp else None

                await browser.close()

                logger.info("[screenshot] Captured %s (status=%s title=%r)", url, status, title[:60] if title else "")
                return ScreenshotResult(
                    url=url,
                    host=host,
                    screenshot_bytes=screenshot,
                    title=title,
                    status_code=status,
                    error=None,
                    captured_at=now,
                )

        except Exception as exc:
            logger.warning("[screenshot] Failed for %s: %s", url, exc)
            return ScreenshotResult(
                url=url,
                host=host,
                screenshot_bytes=None,
                title=None,
                status_code=None,
                error=str(exc),
                captured_at=now,
            )

    async def capture_batch(
        self,
        urls: list[str],
        max_concurrent: int = 3,
    ) -> list[ScreenshotResult]:
        """Capture screenshots for multiple URLs concurrently.

        At most ``max_concurrent`` browsers run at the same time.
        Never raises — returns partial results if individual captures fail.
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _one(url: str) -> ScreenshotResult:
            async with semaphore:
                return await self.capture(url)

        return list(await asyncio.gather(*[_one(u) for u in urls]))

    async def save_to_minio(
        self,
        result: ScreenshotResult,
        engagement_id: str,
        minio_client=None,
    ) -> Optional[str]:
        """Save screenshot bytes to MinIO.

        Returns the object URL (``/bucket/path``) or ``None`` on failure.
        Path pattern: ``screenshots/{engagement_id}/{host}.png``
        """
        if not result.screenshot_bytes:
            return None

        try:
            import io

            bucket = "pentra-screenshots"
            object_name = f"screenshots/{engagement_id}/{result.host}.png"

            if minio_client is None:
                try:
                    from app.storage import get_minio_client
                    minio_client = get_minio_client()
                except ImportError:
                    logger.debug("[screenshot] app.storage not available — skipping MinIO save")
                    return None

            minio_client.put_object(
                bucket,
                object_name,
                io.BytesIO(result.screenshot_bytes),
                length=len(result.screenshot_bytes),
                content_type="image/png",
            )
            url = f"/{bucket}/{object_name}"
            logger.info("[screenshot] Saved %s → %s", result.host, url)
            return url

        except Exception as exc:
            logger.warning("[screenshot] MinIO save failed for %s: %s", result.host, exc)
            return None
