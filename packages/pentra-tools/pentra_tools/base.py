"""Base classes for all Pentra tool wrappers.

Every tool wrapper MUST:
1. Accept a ScopeEnforcer in __init__
2. Call scope.validate_or_raise(target) as the very first line in run()
3. Return ToolResult
4. Never exceed its rate limit
"""

from __future__ import annotations

import asyncio
import random
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable

from pentra_scope import ScopeEnforcer


@dataclass
class ToolResult:
    """Structured output from every tool wrapper."""

    tool: str
    success: bool
    data: Any
    raw: str
    target: str
    command: list[str]
    duration_seconds: float
    error: str | None = None


class RateLimiter:
    """Token-bucket style rate limiter. Thread-safe with asyncio."""

    def __init__(self, max_calls: int, period: float) -> None:
        self.max_calls = max_calls
        self.period = period
        self._calls: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            # Purge timestamps older than the window
            while self._calls and self._calls[0] < now - self.period:
                self._calls.popleft()
            if len(self._calls) >= self.max_calls:
                sleep_for = self.period - (now - self._calls[0])
                await asyncio.sleep(max(sleep_for, 0))
            self._calls.append(time.monotonic())


class AsyncToolWrapper(ABC):
    """Abstract base for all async tool wrappers."""

    name: str = "base"
    description: str = ""
    timeout: int = 300
    rate_limiter: RateLimiter | None = None

    def __init__(
        self,
        scope_enforcer: ScopeEnforcer,
        *,
        opsec_mode: bool = False,
        request_jitter_ms: int = 0,
    ) -> None:
        self.scope = scope_enforcer
        self.opsec_mode = opsec_mode
        self.request_jitter_ms = request_jitter_ms

    async def _maybe_jitter(self) -> None:
        """Sleep a random amount (0 .. request_jitter_ms) when OPSEC mode is on."""
        if self.opsec_mode and self.request_jitter_ms > 0:
            delay = random.uniform(0, self.request_jitter_ms / 1000.0)
            await asyncio.sleep(delay)

    @abstractmethod
    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        """Execute the tool against target. Must call scope.validate_or_raise first."""

    async def _exec(
        self,
        cmd: list[str],
        *,
        timeout: int | None = None,
        on_line: Callable[[str], None] | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[str, str, int]:
        """Run a subprocess, optionally streaming each output line to on_line.

        Applies OPSEC jitter delay before spawning the process when enabled.
        """
        await self._maybe_jitter()
        t0 = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        stdout_lines: list[str] = []
        stderr_data = b""

        async def _read_stdout() -> None:
            assert proc.stdout is not None
            async for line in proc.stdout:
                decoded = line.decode(errors="replace").rstrip()
                stdout_lines.append(decoded)
                if on_line:
                    on_line(decoded)

        async def _read_stderr() -> None:
            nonlocal stderr_data
            assert proc.stderr is not None
            stderr_data = await proc.stderr.read()

        try:
            await asyncio.wait_for(
                asyncio.gather(_read_stdout(), _read_stderr()),
                timeout=timeout or self.timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return "\n".join(stdout_lines), "TIMEOUT", -1

        await proc.wait()
        return "\n".join(stdout_lines), stderr_data.decode(errors="replace"), proc.returncode or 0

    async def _timed_run(self, coro: Any) -> tuple[Any, float]:
        t0 = time.monotonic()
        result = await coro
        return result, time.monotonic() - t0
