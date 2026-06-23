"""Wayback Machine URL miner for historical endpoint discovery."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse

import httpx

log = logging.getLogger(__name__)

SKIP_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".bmp",
        ".css",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".mp4",
        ".mp3",
        ".wav",
        ".ogg",
        ".avi",
        ".mov",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".rar",
        ".7z",
        ".map",
        ".min.js.map",
    }
)


@dataclass(slots=True)
class WaybackResult:
    """Historical URL mining result."""

    domain: str
    urls: list[str] = field(default_factory=list)
    unique_params: list[str] = field(default_factory=list)
    source: str = "wayback"
    error: str | None = None
    total_raw: int = 0


class WaybackCrawler:
    """Fetch historical URLs from Wayback CDX, with CommonCrawl fallback."""

    WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
    COMMONCRAWL_URL = "https://index.commoncrawl.org/CC-MAIN-2024-51-index"
    DEFAULT_TIMEOUT = 30.0
    DEFAULT_LIMIT = 500

    async def get_urls(
        self,
        domain: str,
        limit: int = DEFAULT_LIMIT,
        include_subdomains: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> WaybackResult:
        """Fetch filtered historical URLs for a domain."""
        domain = self._normalize_domain(domain)
        pattern = f"*.{domain}/*" if include_subdomains else f"{domain}/*"
        params = {
            "url": pattern,
            "output": "json",
            "limit": str(limit),
            "fl": "original",
            "collapse": "urlkey",
            "filter": "statuscode:200",
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(self.WAYBACK_CDX_URL, params=params)
                response.raise_for_status()
                data = response.json()

            if not data or len(data) <= 1:
                log.info("[wayback] No results for %s", domain)
                return WaybackResult(domain=domain, source="wayback")

            raw_urls = [row[0] for row in data[1:] if row]
            filtered = self._filter_urls(raw_urls, domain)
            unique_params = self._extract_params(filtered)

            log.info(
                "[wayback] %s: %d raw -> %d filtered, %d unique params",
                domain,
                len(raw_urls),
                len(filtered),
                len(unique_params),
            )
            return WaybackResult(
                domain=domain,
                urls=filtered,
                unique_params=unique_params,
                source="wayback",
                total_raw=len(raw_urls),
            )
        except httpx.TimeoutException:
            log.warning("[wayback] Timeout for %s; trying CommonCrawl fallback", domain)
            return await self._get_urls_commoncrawl(domain, limit=limit, timeout=timeout)
        except Exception as exc:
            log.warning("[wayback] Error for %s: %s", domain, exc)
            return WaybackResult(domain=domain, source="wayback", error=str(exc))

    async def _get_urls_commoncrawl(
        self,
        domain: str,
        limit: int = DEFAULT_LIMIT,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> WaybackResult:
        """Fallback historical URL source using the CommonCrawl index API."""
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(
                    self.COMMONCRAWL_URL,
                    params={
                        "url": f"*.{domain}",
                        "output": "json",
                        "limit": str(limit),
                        "fl": "url",
                    },
                )

            raw_urls: list[str] = []
            for line in response.text.strip().splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = item.get("url")
                if isinstance(url, str):
                    raw_urls.append(url)

            filtered = self._filter_urls(raw_urls, domain)
            unique_params = self._extract_params(filtered)
            log.info(
                "[commoncrawl] %s: %d raw -> %d filtered",
                domain,
                len(raw_urls),
                len(filtered),
            )
            return WaybackResult(
                domain=domain,
                urls=filtered,
                unique_params=unique_params,
                source="commoncrawl",
                total_raw=len(raw_urls),
            )
        except Exception as exc:
            log.warning("[commoncrawl] Error for %s: %s", domain, exc)
            return WaybackResult(
                domain=domain,
                source="both",
                error=f"Both Wayback and CommonCrawl failed: {exc}",
            )

    def _filter_urls(self, urls: list[str], domain: str) -> list[str]:
        """Remove static files, out-of-scope hosts, fragments, and duplicates."""
        domain = self._normalize_domain(domain)
        seen: set[str] = set()
        filtered: list[str] = []

        for url in urls:
            if not url or not url.startswith(("http://", "https://")):
                continue

            try:
                parsed = urlparse(url)
            except Exception:
                continue

            host = parsed.hostname.lower() if parsed.hostname else ""
            if host != domain and not host.endswith(f".{domain}"):
                continue

            filename = parsed.path.lower().rsplit("/", 1)[-1]
            extension = ""
            if "." in filename:
                extension = "." + filename.rsplit(".", 1)[-1]
                if filename.endswith(".min.js.map"):
                    extension = ".min.js.map"
            if extension in SKIP_EXTENSIONS:
                continue

            normalized = url.split("#", 1)[0].rstrip("/") or url
            if normalized in seen:
                continue
            seen.add(normalized)
            filtered.append(normalized)

        return sorted(filtered)

    def _extract_params(self, urls: list[str]) -> list[str]:
        """Extract sorted unique query parameter names from URLs."""
        params: set[str] = set()
        for url in urls:
            try:
                parsed = urlparse(url)
            except Exception:
                continue
            params.update(parse_qs(parsed.query).keys())
        return sorted(params)

    def _normalize_domain(self, domain: str) -> str:
        parsed = urlparse(domain if "://" in domain else f"https://{domain}")
        return (parsed.hostname or domain).lower().strip(".")
