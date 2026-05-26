"""httpx wrapper — live host probing and tech fingerprinting."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

from pentra_scope import ScopeEnforcer

from pentra_tools.base import AsyncToolWrapper, RateLimiter, ToolResult

log = logging.getLogger(__name__)


@dataclass
class HttpxHost:
    url: str
    host: str
    status_code: int | None
    title: str | None = None
    tech: list[str] = field(default_factory=list)
    content_length: int | None = None
    webserver: str | None = None
    cdn: str | None = None
    ip: str | None = None
    cname: list[str] = field(default_factory=list)


class HttpxWrapper(AsyncToolWrapper):
    """Runs projectdiscovery/httpx for live host detection and tech fingerprinting."""

    name = "httpx"
    description = "HTTP probing and technology fingerprinting"
    timeout = 120
    rate_limiter = RateLimiter(max_calls=20, period=60)

    def __init__(self, scope_enforcer: ScopeEnforcer) -> None:
        super().__init__(scope_enforcer)

    async def run(  # type: ignore[override]
        self,
        target: str,
        *,
        hosts: list[str] | None = None,
        **kwargs: object,
    ) -> ToolResult:
        # 1. Scope check — ALWAYS first
        self.scope.validate_or_raise(target)

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        probe_list = hosts or [target]

        # Probe each host and validate scope
        validated = [h for h in probe_list if self.scope.is_allowed(h)]

        if not validated:
            return ToolResult(
                tool=self.name,
                success=False,
                data=[],
                raw="",
                target=target,
                command=[],
                duration_seconds=0,
                error="All hosts failed scope check",
            )

        cmd = [
            "httpx",
            "-silent",
            "-json",
            "-tech-detect",
            "-title",
            "-status-code",
            "-content-length",
            "-web-server",
            "-ip",
            "-cdn",
            "-cname",
            "-rate-limit", "50",
            "-timeout", "10",
        ]
        # Pass hosts via stdin would be cleaner, but use -l flag with a temp list
        # For simplicity: pass a single target or join multiple with newlines via stdin
        if len(validated) == 1:
            cmd.extend(["-u", validated[0]])
        else:
            # Write to temp file approach is complex — use -l with piped stdin
            cmd.append("-l")
            cmd.append("-")  # read from stdin

        log.info("[httpx] probing %d host(s)", len(validated))
        t0 = time.monotonic()

        if len(validated) == 1:
            stdout, stderr, returncode = await self._exec(cmd)
        else:
            # pipe hosts list via stdin
            proc = __import__("asyncio").create_subprocess_exec(
                *cmd,
                stdin=__import__("asyncio").subprocess.PIPE,
                stdout=__import__("asyncio").subprocess.PIPE,
                stderr=__import__("asyncio").subprocess.PIPE,
            )
            import asyncio
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdin_data = "\n".join(validated).encode()
            raw_out, raw_err = await asyncio.wait_for(
                proc.communicate(input=stdin_data), timeout=self.timeout
            )
            stdout = raw_out.decode(errors="replace")
            stderr = raw_err.decode(errors="replace")
            returncode = proc.returncode or 0

        duration = time.monotonic() - t0
        hosts_out = self._parse(stdout)

        log.info("[httpx] %d live host(s) found in %.1fs", len(hosts_out), duration)

        return ToolResult(
            tool=self.name,
            success=returncode == 0 or bool(hosts_out),
            data=hosts_out,
            raw=stdout,
            target=target,
            command=cmd,
            duration_seconds=duration,
            error=stderr.strip() if returncode != 0 and not hosts_out else None,
        )

    def _parse(self, raw: str) -> list[HttpxHost]:
        results: list[HttpxHost] = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append(
                    HttpxHost(
                        url=obj.get("url", ""),
                        host=obj.get("host", ""),
                        status_code=obj.get("status-code"),
                        title=obj.get("title"),
                        tech=obj.get("tech", []),
                        content_length=obj.get("content-length"),
                        webserver=obj.get("webserver"),
                        cdn=obj.get("cdn-name"),
                        ip=obj.get("a", [None])[0] if obj.get("a") else None,
                        cname=obj.get("cname", []),
                    )
                )
            except (json.JSONDecodeError, KeyError, TypeError, IndexError):
                continue
        return results
