"""Katana wrapper — web crawling and endpoint discovery."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

from pentra_scope import ScopeEnforcer

from pentra_tools.base import AsyncToolWrapper, RateLimiter, ToolResult

log = logging.getLogger(__name__)


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    source: str = "katana"
    content_type: str | None = None
    status_code: int | None = None
    params: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


class KatanaWrapper(AsyncToolWrapper):
    """Web crawling and endpoint discovery via katana (ProjectDiscovery).

    Crawls a URL recursively, optionally parsing JavaScript files and using
    headless Chromium for SPA targets.  All discovered endpoints are scope-
    checked individually before being returned.

    Parameters
    ----------
    scope_enforcer:
        Scope gate — validated before crawling begins.
    depth:
        Crawl depth (default 3).
    js_crawl:
        Parse discovered JS files for additional endpoints (default True).
    headless:
        Use headless Chromium for JS-heavy SPAs (default False, slower).
    """

    name = "katana"
    description = "Web crawling and endpoint discovery via katana"
    timeout = 300
    rate_limiter = RateLimiter(max_calls=5, period=60)

    def __init__(
        self,
        scope_enforcer: ScopeEnforcer,
        depth: int = 3,
        js_crawl: bool = True,
        headless: bool = False,
    ) -> None:
        super().__init__(scope_enforcer)
        self._depth = depth
        self._js_crawl = js_crawl
        self._headless = headless

    async def run(self, target: str, **kwargs: object) -> ToolResult:  # type: ignore[override]
        # 1. Scope check — ALWAYS first
        self.scope.validate_or_raise(target)

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        cmd = [
            "katana",
            "-u", target,
            "-d", str(self._depth),
            "-json",
            "-silent",
            "-timeout", "20",
            "-c", "10",        # concurrency
        ]
        if self._js_crawl:
            cmd.append("-jc")
        if self._headless:
            cmd.extend(["-headless", "-system-chrome"])

        log.info("[katana] starting crawl of %s (depth=%d)", target, self._depth)
        t0 = time.monotonic()
        stdout, stderr, returncode = await self._exec(cmd)
        duration = time.monotonic() - t0

        endpoints = self._parse(stdout)
        log.info("[katana] found %d endpoints for %s in %.1fs", len(endpoints), target, duration)

        return ToolResult(
            tool=self.name,
            success=returncode == 0 or bool(endpoints),
            data=endpoints,
            raw=stdout,
            target=target,
            command=cmd,
            duration_seconds=duration,
            error=stderr if returncode != 0 and not endpoints else None,
        )

    def _parse(self, raw: str) -> list[Endpoint]:
        results: list[Endpoint] = []
        seen: set[str] = set()
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # katana JSON format: {"timestamp":"...","request":{"method":"GET","endpoint":"...",...},...}
                req = obj.get("request", {})
                url = req.get("endpoint") or obj.get("endpoint") or ""
                if not url or url in seen:
                    continue
                # Only include in-scope endpoints
                if not self.scope.is_allowed(url):
                    continue
                seen.add(url)

                method = req.get("method", "GET").upper()
                tag = obj.get("tag", "")
                results.append(
                    Endpoint(
                        url=url,
                        method=method,
                        tags=[tag] if tag else [],
                    )
                )
            except (json.JSONDecodeError, KeyError):
                # Plain URL fallback (katana can output plain URLs too)
                if line.startswith("http") and line not in seen:
                    if self.scope.is_allowed(line):
                        seen.add(line)
                        results.append(Endpoint(url=line))
        return results
