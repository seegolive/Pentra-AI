"""Ffuf wrapper — directory and parameter fuzzing."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

from pentra_scope import ScopeEnforcer

from pentra_tools.base import AsyncToolWrapper, RateLimiter, ToolResult

log = logging.getLogger(__name__)

# ── Bundled wordlists — paths mirror the Dockerfile.worker install ─────────────
WORDLISTS: dict[str, str] = {
    "dirs_small": "/usr/share/wordlists/dirb/common.txt",
    "dirs_medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "params": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    "api": "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
}


@dataclass
class FfufResult:
    url: str
    input: str          # FUZZ value that triggered this result
    status: int
    length: int
    words: int
    lines: int
    content_type: str | None = None


class FfufWrapper(AsyncToolWrapper):
    """Directory and parameter fuzzing via ffuf.

    The ``target`` argument must contain ``FUZZ`` as the injection placeholder,
    e.g. ``https://target.com/FUZZ`` or ``https://target.com/search?q=FUZZ``.

    Parameters
    ----------
    scope_enforcer:
        Scope gate — the base URL is validated before fuzzing begins.
    wordlist:
        Key from :data:`WORDLISTS` dict, or an absolute path to a custom list.
    extensions:
        List of extensions to append to each wordlist entry (e.g. ``["php","html"]``).
    filter_status:
        Response status codes to *exclude* (e.g. ``[404, 400]``).
    match_status:
        Response status codes to *include* (e.g. ``[200, 301, 302, 403]``).
    """

    name = "ffuf"
    description = "Directory and parameter fuzzing via ffuf"
    timeout = 300
    rate_limiter = RateLimiter(max_calls=5, period=60)

    # Default: exclude 404 and 400
    DEFAULT_FILTER_STATUS = [404, 400]

    def __init__(
        self,
        scope_enforcer: ScopeEnforcer,
        wordlist: str = "dirs_small",
        extensions: list[str] | None = None,
        filter_status: list[int] | None = None,
        match_status: list[int] | None = None,
    ) -> None:
        super().__init__(scope_enforcer)
        self._wordlist_path = WORDLISTS.get(wordlist, wordlist)
        self._extensions = extensions or []
        self._filter_status = filter_status if filter_status is not None else self.DEFAULT_FILTER_STATUS
        self._match_status = match_status or []

    async def run(self, target: str, **kwargs: object) -> ToolResult:  # type: ignore[override]
        """Fuzz *target*.  ``target`` must contain ``FUZZ`` placeholder."""
        # 1. Scope check — strip placeholder and validate base URL
        base_url = target.replace("FUZZ", "").rstrip("/?")
        self.scope.validate_or_raise(base_url)

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        cmd = [
            "ffuf",
            "-u", target,
            "-w", self._wordlist_path,
            "-json",          # JSON output
            "-s",             # silent (no banner)
            "-of", "json",
            "-o", "/dev/stdout",
        ]
        if self._extensions:
            cmd.extend(["-e", ",".join(f".{e}" for e in self._extensions)])
        if self._filter_status:
            cmd.extend(["-fc", ",".join(str(s) for s in self._filter_status)])
        if self._match_status:
            cmd.extend(["-mc", ",".join(str(s) for s in self._match_status)])

        log.info("[ffuf] starting fuzz on %s", target)
        t0 = time.monotonic()
        stdout, stderr, returncode = await self._exec(cmd)
        duration = time.monotonic() - t0

        results = self._parse(stdout)
        log.info("[ffuf] found %d results for %s in %.1fs", len(results), target, duration)

        return ToolResult(
            tool=self.name,
            success=returncode == 0 or bool(results),
            data=results,
            raw=stdout,
            target=target,
            command=cmd,
            duration_seconds=duration,
            error=stderr if returncode != 0 and not results else None,
        )

    def _parse(self, raw: str) -> list[FfufResult]:
        """Parse ffuf JSON output (can be wrapped in {"results":[...]} or JSONL)."""
        results: list[FfufResult] = []

        # Try wrapped JSON first
        raw = raw.strip()
        try:
            outer = json.loads(raw)
            items = outer.get("results", [])
        except (json.JSONDecodeError, AttributeError):
            # Fall back to JSON-per-line
            items = []
            for line in raw.splitlines():
                line = line.strip()
                if line:
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        for obj in items:
            url = obj.get("url") or obj.get("input", {}).get("FUZZ", "")
            inp = obj.get("input", {}).get("FUZZ") or obj.get("input", "")
            if isinstance(inp, dict):
                inp = str(inp)
            results.append(
                FfufResult(
                    url=url,
                    input=str(inp),
                    status=int(obj.get("status", 0)),
                    length=int(obj.get("length", 0)),
                    words=int(obj.get("words", 0)),
                    lines=int(obj.get("lines", 0)),
                    content_type=obj.get("content-type"),
                )
            )
        return results
