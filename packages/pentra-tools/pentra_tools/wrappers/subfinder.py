"""Subfinder wrapper — passive subdomain enumeration."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass

from pentra_scope import ScopeEnforcer

from pentra_tools.base import AsyncToolWrapper, RateLimiter, ToolResult

log = logging.getLogger(__name__)


@dataclass
class Subdomain:
    host: str
    source: str = "subfinder"
    ip: str | None = None


class SubfinderWrapper(AsyncToolWrapper):
    """Runs subfinder for passive subdomain discovery."""

    name = "subfinder"
    description = "Passive subdomain enumeration using subfinder"
    timeout = 300
    rate_limiter = RateLimiter(max_calls=5, period=60)

    def __init__(self, scope_enforcer: ScopeEnforcer) -> None:
        super().__init__(scope_enforcer)

    async def run(self, target: str, **kwargs: object) -> ToolResult:  # type: ignore[override]
        # 1. Scope check — ALWAYS first
        self.scope.validate_or_raise(target)

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        cmd = [
            "subfinder",
            "-d", target,
            "-all",
            "-silent",
            "-json",
            "-timeout", "30",
        ]

        log.info("[subfinder] starting scan on %s", target)
        t0 = time.monotonic()
        stdout, stderr, returncode = await self._exec(cmd)
        duration = time.monotonic() - t0

        subdomains = self._parse(stdout)

        log.info("[subfinder] found %d subdomains for %s in %.1fs", len(subdomains), target, duration)

        return ToolResult(
            tool=self.name,
            success=returncode == 0 or bool(subdomains),
            data=subdomains,
            raw=stdout,
            target=target,
            command=cmd,
            duration_seconds=duration,
            error=stderr.strip() if (returncode != 0 and not subdomains) else None,
        )

    def _parse(self, raw: str) -> list[Subdomain]:
        results: list[Subdomain] = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append(
                    Subdomain(
                        host=obj["host"],
                        source=obj.get("source", "subfinder"),
                        ip=obj.get("ip"),
                    )
                )
            except (json.JSONDecodeError, KeyError):
                # Plain-text fallback (some subfinder versions)
                if line and "." in line:
                    results.append(Subdomain(host=line))
        return results
