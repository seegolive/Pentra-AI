"""Security dorking and sensitive page categorization."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

log = logging.getLogger(__name__)

SECURITY_DORKS = {
    "login_pages": [
        "site:{domain} inurl:login",
        "site:{domain} inurl:signin",
        "site:{domain} inurl:auth",
    ],
    "admin_panels": [
        "site:{domain} inurl:admin",
        "site:{domain} inurl:dashboard",
        "site:{domain} inurl:manage",
        "site:{domain} inurl:wp-admin",
        "site:{domain} inurl:control-panel",
    ],
    "sensitive_files": [
        "site:{domain} filetype:env",
        "site:{domain} filetype:sql",
        "site:{domain} filetype:bak",
        'site:{domain} "Index of" backup',
        "site:{domain} filetype:config",
    ],
    "api_endpoints": [
        "site:{domain} inurl:api",
        "site:{domain} inurl:swagger",
        "site:{domain} inurl:graphql",
    ],
    "error_pages": [
        'site:{domain} "stack trace"',
        'site:{domain} "SQL syntax"',
        'site:{domain} "Warning: mysql"',
    ],
}

URL_CATEGORIES = {
    "login": ["/login", "/signin", "/auth", "/sso"],
    "admin": ["/admin", "/dashboard", "/manage", "/wp-admin", "/control"],
    "api": ["/api", "/swagger", "/graphql", "/rest"],
    "sensitive": [".env", ".sql", ".bak", ".config", "backup"],
    "error": ["stacktrace", "debug", "error"],
}


@dataclass(slots=True)
class DorkResult:
    domain: str
    total_results: int = 0
    by_category: dict[str, list[str]] = field(default_factory=dict)
    login_pages: list[str] = field(default_factory=list)
    admin_panels: list[str] = field(default_factory=list)
    sensitive_files: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    high_risk_urls: list[str] = field(default_factory=list)
    error: str | None = None


class DorkScanner:
    """Run passive search dorks for security-sensitive URLs."""

    def __init__(
        self,
        delay_between_dorks: float = 2.0,
        max_results_per_dork: int = 5,
    ) -> None:
        self.delay = delay_between_dorks
        self.max_results = max_results_per_dork

    async def run_dorks(
        self,
        domain: str,
        categories: list[str] | None = None,
    ) -> DorkResult:
        """Run dork categories for a domain and summarize high-risk URLs."""
        domain = self._normalize_domain(domain)
        result = DorkResult(domain=domain)
        all_urls: list[str] = []
        selected = categories or list(SECURITY_DORKS.keys())

        for category in selected:
            category_urls: list[str] = []
            for template in SECURITY_DORKS.get(category, []):
                query = template.format(domain=domain)
                try:
                    urls = await self._search(query)
                    category_urls.extend(urls)
                    all_urls.extend(urls)
                    if urls and self.delay > 0:
                        await asyncio.sleep(self.delay)
                except Exception as exc:
                    log.warning("[dork] Failed %r: %s", query, exc)
            result.by_category[category] = sorted(set(category_urls))

        result.login_pages = result.by_category.get("login_pages", [])
        result.admin_panels = result.by_category.get("admin_panels", [])
        result.sensitive_files = result.by_category.get("sensitive_files", [])
        result.api_endpoints = result.by_category.get("api_endpoints", [])
        result.high_risk_urls = sorted(
            set(result.login_pages + result.admin_panels + result.sensitive_files)
        )
        result.total_results = len(set(all_urls))
        log.info(
            "[dork] %s: %d total results, %d high-risk",
            domain,
            result.total_results,
            len(result.high_risk_urls),
        )
        return result

    async def _search(self, query: str) -> list[str]:
        """Execute a search query via googlesearch-python when installed."""
        try:
            from googlesearch import search as google_search
        except ImportError:
            log.info("[dork] googlesearch-python not installed — skipping")
            return []

        try:
            urls = await asyncio.to_thread(
                lambda: list(google_search(query, num_results=self.max_results))
            )
        except Exception as exc:
            if "429" in str(exc) or "rate" in str(exc).lower():
                log.warning("[dork] Search rate limited; increase delay_between_dorks")
            else:
                log.warning("[dork] Search failed: %s", exc)
            return []
        return [url for url in urls if isinstance(url, str) and url.startswith("http")]

    def categorize_url(self, url: str) -> str:
        """Categorize a URL path using simple security-sensitive patterns."""
        parsed = urlparse(url)
        haystack = f"{parsed.path.lower()}?{parsed.query.lower()}"
        for category, patterns in URL_CATEGORIES.items():
            if any(pattern in haystack for pattern in patterns):
                return category
        return "other"

    def _normalize_domain(self, domain: str) -> str:
        parsed = urlparse(domain if "://" in domain else f"https://{domain}")
        return (parsed.hostname or domain).lower().strip(".")
