"""Sqlmap wrapper — SQL injection detection and exploitation.

⚠️  DESTRUCTIVE TOOL — this wrapper MUST only be invoked after explicit
human approval via the LangGraph HITL interrupt().  The IS_DESTRUCTIVE flag
is checked by the agent before any invocation.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from uuid import uuid4

from pentra_scope import ScopeEnforcer

from pentra_tools.base import AsyncToolWrapper, RateLimiter, ToolResult

log = logging.getLogger(__name__)


@dataclass
class SqliFinding:
    url: str
    param: str
    injection_type: str        # e.g. "boolean-based blind", "time-based blind"
    dbms: str | None = None
    technique: str | None = None
    data: dict | None = None


class SqlmapWrapper(AsyncToolWrapper):
    """SQL injection detection via sqlmap.

    **⚠️ Destructive** — always requires human approval before execution.
    The agent checks :attr:`IS_DESTRUCTIVE` and interrupts via HITL before
    calling this wrapper.

    Default ``--level=1 --risk=1`` keeps the tool at its safest operating
    mode.  Increase only with explicit user approval.

    Parameters
    ----------
    scope_enforcer:
        Scope gate — validated before any network activity.
    level:
        Sqlmap level (1–5). Default 1 (safest).
    risk:
        Sqlmap risk (1–3). Default 1 (safest).
    technique:
        SQL injection techniques to test. Default ``"BEUST"`` (all).
    """

    name = "sqlmap"
    description = "SQL injection testing via sqlmap"
    timeout = 600
    rate_limiter = RateLimiter(max_calls=2, period=60)

    #: Flag checked by agent graph — prevents invocation without HITL approval.
    IS_DESTRUCTIVE: bool = True

    def __init__(
        self,
        scope_enforcer: ScopeEnforcer,
        level: int = 1,
        risk: int = 1,
        technique: str = "BEUST",
    ) -> None:
        super().__init__(scope_enforcer)
        self._level = max(1, min(level, 5))
        self._risk = max(1, min(risk, 3))
        self._technique = technique

    async def run(  # type: ignore[override]
        self,
        target: str,
        data: str | None = None,
        params: list[str] | None = None,
        **kwargs: object,
    ) -> ToolResult:
        """Run sqlmap against *target*.

        Parameters
        ----------
        target:
            URL to test (GET parameters will be tested automatically).
        data:
            POST body data (will also be tested for injection).
        params:
            Specific parameter names to test (skips others).
        """
        # 1. Scope check — ALWAYS first
        self.scope.validate_or_raise(target)

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        output_dir = f"/tmp/sqlmap_{uuid4().hex[:8]}"
        os.makedirs(output_dir, exist_ok=True)

        cmd = [
            "sqlmap",
            "-u", target,
            "--batch",                     # Non-interactive mode
            "--output-dir", output_dir,
            f"--level={self._level}",
            f"--risk={self._risk}",
            f"--technique={self._technique}",
            "--json-output",               # JSON output format
        ]
        if data:
            cmd.extend(["--data", data])
        if params:
            cmd.extend(["-p", ",".join(params)])

        log.info(
            "[sqlmap] starting scan on %s (level=%d risk=%d)",
            target, self._level, self._risk,
        )
        t0 = time.monotonic()
        stdout, stderr, returncode = await self._exec(cmd)
        duration = time.monotonic() - t0

        findings = self._parse(stdout, target)
        log.info("[sqlmap] found %d injection(s) on %s in %.1fs", len(findings), target, duration)

        # Clean up temp output dir
        try:
            import shutil
            shutil.rmtree(output_dir, ignore_errors=True)
        except Exception:  # noqa: BLE001
            pass

        return ToolResult(
            tool=self.name,
            success=returncode == 0,
            data=findings,
            raw=stdout,
            target=target,
            command=cmd,
            duration_seconds=duration,
            error=stderr if returncode != 0 else None,
        )

    def _parse(self, raw: str, target: str) -> list[SqliFinding]:
        results: list[SqliFinding] = []

        # Try JSON output first
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                data_section = obj.get("data", {})
                for param, info_list in data_section.items():
                    if not isinstance(info_list, list):
                        continue
                    for info in info_list:
                        results.append(
                            SqliFinding(
                                url=target,
                                param=param,
                                injection_type=info.get("type", "unknown"),
                                dbms=info.get("dbms"),
                                technique=info.get("title"),
                            )
                        )
            except (json.JSONDecodeError, KeyError):
                pass

        # Fallback: parse classic sqlmap text output
        if not results:
            # Look for lines like: "Parameter: id (GET)\n    Type: boolean-based blind"
            param_blocks = re.findall(
                r"Parameter:\s+(\S+)[^\n]*\n.*?Type:\s+(.+?)\n.*?(?:DBMS:\s+(.+?))?(?:\n|$)",
                raw,
                re.DOTALL | re.IGNORECASE,
            )
            for match in param_blocks:
                results.append(
                    SqliFinding(
                        url=target,
                        param=match[0].strip(),
                        injection_type=match[1].strip(),
                        dbms=match[2].strip() if match[2] else None,
                    )
                )
        return results
