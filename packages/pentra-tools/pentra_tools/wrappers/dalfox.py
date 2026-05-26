"""Dalfox wrapper — XSS parameter scanning."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass

from pentra_scope import ScopeEnforcer

from pentra_tools.base import AsyncToolWrapper, RateLimiter, ToolResult

log = logging.getLogger(__name__)


@dataclass
class XSSFinding:
    url: str
    param: str
    payload: str
    poc: str | None = None
    cwe: str | None = None
    severity: str = "medium"


class DalfoxWrapper(AsyncToolWrapper):
    """XSS scanning via dalfox.

    Should be run against specific parameters already identified by katana or
    similar crawlers — not as a blind scanner over unknown targets.

    Parameters
    ----------
    scope_enforcer:
        Scope gate — validated before any network activity.
    blind_xss_endpoint:
        Optional Burp Collaborator (or other OOB) endpoint for blind XSS
        detection, e.g. ``"xyz.oastify.com"``.
    """

    name = "dalfox"
    description = "XSS parameter scanning via dalfox"
    timeout = 300
    rate_limiter = RateLimiter(max_calls=3, period=60)

    def __init__(
        self,
        scope_enforcer: ScopeEnforcer,
        blind_xss_endpoint: str | None = None,
    ) -> None:
        super().__init__(scope_enforcer)
        self._blind_xss = blind_xss_endpoint

    async def run(self, target: str, **kwargs: object) -> ToolResult:  # type: ignore[override]
        """Scan *target* URL for XSS vulnerabilities.

        Parameters
        ----------
        target:
            Full URL with query parameters, e.g.
            ``https://target.com/search?q=test&page=1``
        """
        # 1. Scope check — ALWAYS first
        self.scope.validate_or_raise(target)

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        cmd = [
            "dalfox",
            "url", target,
            "--format", "json",
            "--no-color",
            "--silence",
        ]
        if self._blind_xss:
            cmd.extend(["--blind", self._blind_xss])

        log.info("[dalfox] starting XSS scan on %s", target)
        t0 = time.monotonic()
        stdout, stderr, returncode = await self._exec(cmd)
        duration = time.monotonic() - t0

        findings = self._parse(stdout)
        log.info("[dalfox] found %d XSS on %s in %.1fs", len(findings), target, duration)

        return ToolResult(
            tool=self.name,
            success=returncode == 0 or bool(findings),
            data=findings,
            raw=stdout,
            target=target,
            command=cmd,
            duration_seconds=duration,
            error=stderr if returncode != 0 and not findings else None,
        )

    def _parse(self, raw: str) -> list[XSSFinding]:
        results: list[XSSFinding] = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # dalfox JSON format: {"type":"G", "inject_type":"inHTML-none",
                # "poc":"<full-url>", "param":"q", "payload":"<script>..."}
                poc = obj.get("poc", "")
                url = poc.split("?")[0] if poc else ""
                results.append(
                    XSSFinding(
                        url=url,
                        param=obj.get("param", "unknown"),
                        payload=obj.get("payload", ""),
                        poc=poc,
                        cwe="CWE-79",
                        severity="medium",
                    )
                )
            except (json.JSONDecodeError, KeyError):
                pass
        return results
