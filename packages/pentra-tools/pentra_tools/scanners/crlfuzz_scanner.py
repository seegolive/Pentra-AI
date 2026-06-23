"""CRLFuzz wrapper for CRLF injection discovery."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(slots=True)
class CRLFFinding:
    url: str
    payload: str
    severity: str = "medium"
    vuln_class: str = "crlf_injection"
    evidence: str = ""
    source: str = "crlfuzz"


class CRLFuzzScanner:
    """Async wrapper for the crlfuzz binary."""

    def is_available(self) -> bool:
        return shutil.which("crlfuzz") is not None

    async def scan(self, url: str, timeout: int = 60) -> list[CRLFFinding]:
        if not self.is_available():
            log.info("[crlfuzz] Binary not found — skipping")
            return []

        outfile = ""
        try:
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as handle:
                outfile = handle.name

            proc = await asyncio.create_subprocess_exec(
                "crlfuzz",
                "-u",
                url,
                "-o",
                outfile,
                "-s",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                log.warning("[crlfuzz] Timeout for %s", url)
                return []

            findings: list[CRLFFinding] = []
            if os.path.exists(outfile):
                with open(outfile, encoding="utf-8", errors="ignore") as handle:
                    for line in handle:
                        payload = line.strip()
                        if payload.startswith("http"):
                            findings.append(
                                CRLFFinding(
                                    url=url,
                                    payload=payload,
                                    evidence=f"CRLF injection found: {payload}",
                                )
                            )
            if findings:
                log.info("[crlfuzz] %d CRLF finding(s) for %s", len(findings), url)
            return findings
        except Exception as exc:
            log.warning("[crlfuzz] Error for %s: %s", url, exc)
            return []
        finally:
            if outfile and os.path.exists(outfile):
                os.unlink(outfile)

    async def scan_batch(self, urls: list[str], max_concurrent: int = 3) -> list[CRLFFinding]:
        semaphore = asyncio.Semaphore(max_concurrent)

        async def scan_one(url: str) -> list[CRLFFinding]:
            async with semaphore:
                return await self.scan(url)

        batches = await asyncio.gather(*(scan_one(url) for url in urls))
        return [finding for batch in batches for finding in batch]
