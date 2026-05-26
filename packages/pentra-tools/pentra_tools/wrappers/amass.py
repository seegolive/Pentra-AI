"""Amass wrapper — deep OSINT subdomain enumeration."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Literal

from pentra_scope import ScopeEnforcer

from pentra_tools.base import AsyncToolWrapper, RateLimiter, ToolResult

log = logging.getLogger(__name__)


@dataclass
class AmassSubdomain:
    host: str
    source: str = "amass"
    ip: str | None = None
    asn: int | None = None
    cidr: str | None = None
    tag: str | None = None


class AmassWrapper(AsyncToolWrapper):
    """Deep OSINT subdomain enumeration via amass.

    Slower and more thorough than subfinder — leverages OSINT sources
    (certificates, APIs, DNS brute-force in active mode).

    Parameters
    ----------
    scope_enforcer:
        Scope gate — validated before any network activity.
    mode:
        ``"passive"`` (default) performs only OSINT lookups.
        ``"active"`` adds DNS brute-force (louder, takes longer).
    """

    name = "amass"
    description = "Deep OSINT subdomain enumeration via amass"
    timeout = 600
    rate_limiter = RateLimiter(max_calls=3, period=60)

    def __init__(
        self,
        scope_enforcer: ScopeEnforcer,
        mode: Literal["passive", "active"] = "passive",
    ) -> None:
        super().__init__(scope_enforcer)
        self._mode = mode

    async def run(self, target: str, **kwargs: object) -> ToolResult:  # type: ignore[override]
        # 1. Scope check — ALWAYS first
        self.scope.validate_or_raise(target)

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        cmd = [
            "amass", "enum",
            "-passive" if self._mode == "passive" else "-active",
            "-d", target,
            "-json",
            "-timeout", "20",
        ]

        log.info("[amass] starting %s scan on %s", self._mode, target)
        t0 = time.monotonic()
        stdout, stderr, returncode = await self._exec(cmd)
        duration = time.monotonic() - t0

        subdomains = self._parse(stdout)
        log.info(
            "[amass] found %d subdomains for %s in %.1fs", len(subdomains), target, duration
        )

        return ToolResult(
            tool=self.name,
            success=returncode == 0 or bool(subdomains),
            data=subdomains,
            raw=stdout,
            target=target,
            command=cmd,
            duration_seconds=duration,
            error=stderr if returncode != 0 and not subdomains else None,
        )

    def _parse(self, raw: str) -> list[AmassSubdomain]:
        results: list[AmassSubdomain] = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # amass v3 format: {"name": "sub.target.com", "addresses": [...], "tag": "..."}
                host = obj.get("name", "")
                addresses = obj.get("addresses", [])
                ip = addresses[0].get("ip") if addresses else None
                asn = addresses[0].get("asn") if addresses else None
                cidr = addresses[0].get("cidr") if addresses else None
                if host:
                    results.append(
                        AmassSubdomain(
                            host=host,
                            ip=ip,
                            asn=asn,
                            cidr=cidr,
                            tag=obj.get("tag"),
                        )
                    )
            except (json.JSONDecodeError, KeyError, IndexError):
                # v4 plain-text fallback: one hostname per line
                if line and "." in line and " " not in line:
                    results.append(AmassSubdomain(host=line))
        return results
