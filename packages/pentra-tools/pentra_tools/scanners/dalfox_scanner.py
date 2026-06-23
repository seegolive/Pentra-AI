"""Dalfox batch scanner for reflected/blind XSS candidates."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(slots=True)
class XSSFinding:
    url: str
    param: str
    payload: str
    severity: str = "high"
    vuln_class: str = "xss"
    xss_type: str = "reflected"
    evidence: str = ""
    source: str = "dalfox"


class DalfoxScanner:
    """Async wrapper for dalfox's JSON output mode."""

    def is_available(self) -> bool:
        return shutil.which("dalfox") is not None

    async def scan(
        self,
        url: str,
        timeout: int = 120,
        blind_xss_url: str | None = None,
    ) -> list[XSSFinding]:
        if not self.is_available():
            log.info("[dalfox] Binary not found — skipping")
            return []

        outfile = ""
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
                outfile = handle.name

            cmd = [
                "dalfox",
                "url",
                url,
                "--silence",
                "--format",
                "json",
                "-o",
                outfile,
            ]
            if blind_xss_url:
                cmd.extend(["--blind", blind_xss_url])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                log.warning("[dalfox] Timeout for %s", url)
                return []

            findings = self._parse_output_file(outfile, fallback_url=url)
            if findings:
                log.info("[dalfox] %d XSS finding(s) for %s", len(findings), url)
            return findings
        except Exception as exc:
            log.warning("[dalfox] Error for %s: %s", url, exc)
            return []
        finally:
            if outfile and os.path.exists(outfile):
                os.unlink(outfile)

    async def scan_batch(self, urls: list[str], max_concurrent: int = 2) -> list[XSSFinding]:
        semaphore = asyncio.Semaphore(max_concurrent)

        async def scan_one(url: str) -> list[XSSFinding]:
            async with semaphore:
                return await self.scan(url)

        batches = await asyncio.gather(*(scan_one(url) for url in urls))
        return [finding for batch in batches for finding in batch]

    def _parse_output_file(self, path: str, fallback_url: str) -> list[XSSFinding]:
        if not os.path.exists(path):
            return []
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                raw = handle.read().strip()
            if not raw:
                return []
            data = json.loads(raw)
        except Exception:
            return []

        items = data if isinstance(data, list) else [data]
        findings: list[XSSFinding] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            findings.append(
                XSSFinding(
                    url=item.get("url") or fallback_url,
                    param=item.get("param") or "unknown",
                    payload=item.get("payload") or "",
                    xss_type=item.get("type") or item.get("inject_type") or "reflected",
                    evidence=item.get("evidence") or item.get("poc") or "",
                )
            )
        return findings
