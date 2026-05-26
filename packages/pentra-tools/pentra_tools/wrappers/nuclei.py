"""Nuclei wrapper — template-based vulnerability scanning."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

from pentra_scope import ScopeEnforcer

from pentra_tools.base import AsyncToolWrapper, RateLimiter, ToolResult

log = logging.getLogger(__name__)


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: str | None = None
    reference: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    curl_command: str | None = None


class NucleiWrapper(AsyncToolWrapper):
    """Runs nuclei for template-based vulnerability scanning."""

    name = "nuclei"
    description = "Template-based vulnerability scanner"
    timeout = 600
    rate_limiter = RateLimiter(max_calls=3, period=60)  # nuclei is aggressive, limit hard

    # Safe default tags — exclude intrusive/dos templates by default
    DEFAULT_TAGS = ["cve", "misconfig", "exposure", "takeover", "tech", "info"]
    EXCLUDED_SEVERITY = []  # caller can override

    def __init__(self, scope_enforcer: ScopeEnforcer) -> None:
        super().__init__(scope_enforcer)

    async def run(  # type: ignore[override]
        self,
        target: str,
        *,
        tags: list[str] | None = None,
        severity: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        **kwargs: object,
    ) -> ToolResult:
        # 1. Scope check — ALWAYS first
        self.scope.validate_or_raise(target)

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        # Default: only safe template categories
        active_tags = tags or self.DEFAULT_TAGS
        # Always exclude intrusive/dos
        always_excluded = ["dos", "fuzz", "bruteforce", "intrusive"]
        all_excluded = list(set((exclude_tags or []) + always_excluded))

        cmd = [
            "nuclei",
            "-u", target,
            "-json",
            "-silent",
            "-nc",  # no color
            "-rate-limit", "50",
            "-bulk-size", "10",
            "-concurrency", "5",
        ]

        if active_tags:
            cmd.extend(["-tags", ",".join(active_tags)])

        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        if all_excluded:
            cmd.extend(["-exclude-tags", ",".join(all_excluded)])

        log.info("[nuclei] starting scan on %s (tags=%s)", target, active_tags)
        t0 = time.monotonic()
        stdout, stderr, returncode = await self._exec(cmd)
        duration = time.monotonic() - t0

        findings = self._parse(stdout)

        log.info("[nuclei] %s: %d finding(s) in %.1fs", target, len(findings), duration)

        return ToolResult(
            tool=self.name,
            success=returncode == 0,
            data=findings,
            raw=stdout,
            target=target,
            command=cmd,
            duration_seconds=duration,
            error=stderr.strip() if returncode != 0 else None,
        )

    def _parse(self, raw: str) -> list[NucleiFinding]:
        results: list[NucleiFinding] = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                info = obj.get("info", {})
                results.append(
                    NucleiFinding(
                        template_id=obj.get("template-id", ""),
                        name=info.get("name", obj.get("template-id", "")),
                        severity=info.get("severity", "info").lower(),
                        host=obj.get("host", ""),
                        matched_at=obj.get("matched-at", obj.get("host", "")),
                        description=info.get("description"),
                        reference=info.get("reference", []),
                        tags=info.get("tags", []),
                        curl_command=obj.get("curl-command"),
                    )
                )
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        return results
