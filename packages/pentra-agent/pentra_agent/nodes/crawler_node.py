"""
Crawler node — discovers endpoints using JS crawler (Playwright)
and merges with static crawl results from recon_node.
"""
from __future__ import annotations
import logging
from typing import Any

try:
    from pentra_tools.crawlers.js_crawler import JSCrawler
    _JS_CRAWLER_AVAILABLE = True
except ImportError:
    JSCrawler = None  # type: ignore[assignment,misc]
    _JS_CRAWLER_AVAILABLE = False

logger = logging.getLogger(__name__)


async def crawler_node(state: dict) -> dict[str, Any]:
    """
    LangGraph node: run JS crawler on live hosts, merge with recon endpoints.
    Gracefully skips if Playwright not available.
    """
    logger.info("[crawler_node] Starting JS endpoint discovery...")

    if not _JS_CRAWLER_AVAILABLE or JSCrawler is None:
        logger.warning("[crawler_node] pentra-tools JSCrawler not importable — skipping")
        return {"js_crawl_result": {"endpoints": [], "skipped": True, "error": "import_error"}}

    subdomains = state.get("subdomains", [])
    live_hosts = [
        s["host"] for s in subdomains
        if isinstance(s, dict) and s.get("is_alive", False)
    ]

    auth_credentials = state.get("auth_credentials") or {}
    auth_cookies_str = auth_credentials.get("cookies", "") if isinstance(auth_credentials, dict) else ""

    if not live_hosts:
        logger.info("[crawler_node] No live hosts found — skipping JS crawl")
        return {"js_crawl_result": {"endpoints": [], "skipped": True}}

    crawler = JSCrawler(headless=True)
    all_endpoints = []
    crawl_summary = []

    cookies = _parse_cookies(auth_cookies_str) if auth_cookies_str else None

    for host in live_hosts[:15]:
        url = host if host.startswith("http") else f"https://{host}"
        logger.info(f"[crawler_node] JS crawling: {url}")

        result = await crawler.crawl(url, cookies=cookies, timeout_ms=30000)

        if result.error:
            if "Playwright not installed" in (result.error or ""):
                logger.warning("[crawler_node] Playwright not available — using static crawl only")
                break
            logger.warning(f"[crawler_node] Crawl error for {url}: {result.error}")
        else:
            all_endpoints.extend(result.endpoints)
            crawl_summary.append({
                "host": url,
                "endpoints_found": len(result.endpoints),
                "forms_found": len(result.forms),
                "js_files": len(result.js_files),
                "crawl_time_ms": result.crawl_time_ms,
            })

    logger.info(f"[crawler_node] Complete: {len(all_endpoints)} JS endpoints discovered")

    return {
        "js_crawl_result": {
            "endpoints": [
                {
                    "url": ep.url,
                    "method": ep.method,
                    "params": list(ep.params.keys()),
                    "source": ep.source,
                }
                for ep in all_endpoints
            ],
            "summary": crawl_summary,
        }
    }


def _parse_cookies(cookie_string: str) -> list[dict]:
    """Parse 'key=value; key2=value2' format into Playwright cookie list."""
    cookies = []
    for part in cookie_string.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            cookies.append({"name": name.strip(), "value": value.strip()})
    return cookies
