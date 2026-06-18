"""
Playwright-based JavaScript crawler for SPA endpoint discovery.
Falls back gracefully if Playwright is not available.
"""
from __future__ import annotations
import logging
import asyncio
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str
    params: dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None
    content_type: Optional[str] = None
    source: str = "js_crawler"


@dataclass
class CrawlResult:
    endpoints: list[DiscoveredEndpoint]
    forms: list[dict]
    js_files: list[str]
    api_calls: list[DiscoveredEndpoint]
    crawl_time_ms: float
    error: Optional[str] = None
    used_js_crawler: bool = True


class JSCrawler:
    """
    Playwright-based crawler for JavaScript-heavy apps (React, Angular, Vue).
    Discovers API endpoints by intercepting XHR/fetch calls during navigation.
    """

    MAX_INTERACTIONS = 20
    PAGE_TIMEOUT_MS = 15000
    NETWORK_IDLE_TIMEOUT_MS = 5000

    def __init__(self, headless: bool = True):
        self.headless = headless
        self._playwright_available = self._check_playwright()

    def _check_playwright(self) -> bool:
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    async def crawl(
        self,
        url: str,
        cookies: Optional[list[dict]] = None,
        headers: Optional[dict] = None,
        timeout_ms: int = 30000,
    ) -> CrawlResult:
        """
        Crawl a URL using headless Chromium.

        Args:
            url: Target URL to crawl
            cookies: Auth cookies to inject
            headers: Additional request headers
            timeout_ms: Total crawl timeout in milliseconds

        Returns:
            CrawlResult with all discovered endpoints
        """
        if not self._playwright_available:
            logger.warning("Playwright not available — falling back to static crawl hint")
            return CrawlResult(
                endpoints=[],
                forms=[],
                js_files=[],
                api_calls=[],
                crawl_time_ms=0,
                error="Playwright not installed. Run: pip install playwright && playwright install chromium",
                used_js_crawler=False,
            )

        import time
        start = time.monotonic()

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=headers or {},
                )

                if cookies:
                    await context.add_cookies(cookies)

                api_calls: list[DiscoveredEndpoint] = []
                base_domain = urlparse(url).netloc

                page = await context.new_page()

                async def handle_request(request):
                    req_url = request.url
                    req_domain = urlparse(req_url).netloc
                    if req_domain and (req_domain == base_domain or
                                       req_domain.endswith("." + base_domain)):
                        if request.resource_type in ("xhr", "fetch"):
                            api_calls.append(DiscoveredEndpoint(
                                url=req_url,
                                method=request.method,
                                post_data=request.post_data,
                                content_type=request.headers.get("content-type"),
                                source="js_crawler",
                            ))

                page.on("request", handle_request)

                try:
                    await page.goto(url, wait_until="networkidle",
                                    timeout=self.PAGE_TIMEOUT_MS)
                except Exception as nav_err:
                    logger.warning(f"Navigation issue (continuing): {nav_err}")

                await asyncio.sleep(1)

                forms = await self._extract_forms(page)

                links = await page.query_selector_all("a[href]")
                js_files = []

                interaction_count = 0
                current_url = page.url

                for link in links[:self.MAX_INTERACTIONS]:
                    if interaction_count >= self.MAX_INTERACTIONS:
                        break
                    try:
                        href = await link.get_attribute("href")
                        if not href or href.startswith("#") or href.startswith("javascript:"):
                            continue
                        full_url = urljoin(current_url, href)
                        if urlparse(full_url).netloc != base_domain:
                            continue
                        await link.click(timeout=2000)
                        await asyncio.sleep(0.5)
                        await page.go_back(timeout=3000)
                        interaction_count += 1
                    except Exception:
                        pass

                script_tags = await page.query_selector_all("script[src]")
                for script in script_tags:
                    src = await script.get_attribute("src")
                    if src:
                        js_files.append(urljoin(url, src))

                endpoints = list(api_calls)

                await browser.close()

                elapsed_ms = (time.monotonic() - start) * 1000
                logger.info(
                    f"JS crawl complete: {len(endpoints)} endpoints, "
                    f"{len(forms)} forms, {len(js_files)} JS files "
                    f"in {elapsed_ms:.0f}ms"
                )

                return CrawlResult(
                    endpoints=endpoints,
                    forms=forms,
                    js_files=js_files,
                    api_calls=api_calls,
                    crawl_time_ms=elapsed_ms,
                    used_js_crawler=True,
                )

        except asyncio.TimeoutError:
            elapsed_ms = (time.monotonic() - start) * 1000
            return CrawlResult(
                endpoints=[], forms=[], js_files=[], api_calls=[],
                crawl_time_ms=elapsed_ms,
                error=f"Crawl timed out after {timeout_ms}ms",
                used_js_crawler=True,
            )
        except Exception as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error(f"JS crawler error: {e}")
            return CrawlResult(
                endpoints=[], forms=[], js_files=[], api_calls=[],
                crawl_time_ms=elapsed_ms,
                error=str(e),
                used_js_crawler=True,
            )

    async def _extract_forms(self, page) -> list[dict]:
        """Extract all forms and their fields from current page."""
        try:
            return await page.evaluate("""
                () => Array.from(document.forms).map(form => ({
                    action: form.action,
                    method: form.method || 'GET',
                    fields: Array.from(form.elements)
                        .filter(el => el.name)
                        .map(el => ({
                            name: el.name,
                            type: el.type,
                            value: el.type === 'password' ? '' : (el.value || ''),
                        }))
                }))
            """)
        except Exception:
            return []
