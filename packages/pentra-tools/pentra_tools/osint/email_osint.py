"""Email OSINT helpers: enumeration and breach checks."""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from dataclasses import dataclass, field

import httpx

log = logging.getLogger(__name__)

HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
HUNTER_API_URL = "https://api.hunter.io/v2/domain-search"
HIBP_RATE_LIMIT_DELAY = 1.6


@dataclass(slots=True)
class BreachResult:
    email: str
    breached: bool
    breach_count: int = 0
    breaches: list[str] = field(default_factory=list)
    has_passwords: bool = False
    severity: str = "INFO"

    def __post_init__(self) -> None:
        if self.breached and self.has_passwords:
            self.severity = "CRITICAL"
        elif self.breached:
            self.severity = "MEDIUM"


@dataclass(slots=True)
class EmailOSINTResult:
    domain: str
    emails: list[str] = field(default_factory=list)
    breach_results: dict[str, BreachResult] = field(default_factory=dict)
    critical_emails: list[str] = field(default_factory=list)
    source: str = "unknown"
    error: str | None = None


class EmailOSINT:
    """Enumerate domain emails and optionally check public breach metadata."""

    async def run(
        self,
        domain: str,
        hunter_api_key: str | None = None,
        hibp_api_key: str | None = None,
        check_breaches: bool = True,
    ) -> EmailOSINTResult:
        emails = await self.enumerate_emails(domain, hunter_api_key=hunter_api_key)
        breach_results: dict[str, BreachResult] = {}
        if emails and check_breaches:
            breach_results = await self.check_breaches(emails, hibp_api_key=hibp_api_key)
        critical = [
            email for email, result in breach_results.items()
            if result.breached and result.has_passwords
        ]
        return EmailOSINTResult(
            domain=domain,
            emails=emails,
            breach_results=breach_results,
            critical_emails=sorted(critical),
            source="theharvester+hunter+hibp",
        )

    async def enumerate_emails(
        self,
        domain: str,
        hunter_api_key: str | None = None,
    ) -> list[str]:
        """Enumerate emails via theHarvester and hunter.io when available."""
        emails: set[str] = set()
        emails.update(await self._run_harvester(domain))
        if hunter_api_key:
            emails.update(await self._run_hunter(domain, hunter_api_key))
        result = sorted(email.lower() for email in emails)
        log.info("[email_osint] Found %d emails for %s", len(result), domain)
        return result

    async def check_breaches(
        self,
        emails: list[str],
        hibp_api_key: str | None = None,
        delay: float = HIBP_RATE_LIMIT_DELAY,
    ) -> dict[str, BreachResult]:
        """Check emails against HaveIBeenPwned; returns empty on API errors."""
        headers = {"User-Agent": "Pentra-AI-SecurityScanner"}
        if hibp_api_key:
            headers["hibp-api-key"] = hibp_api_key
        results: dict[str, BreachResult] = {}

        for email in emails:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(
                        HIBP_API_URL.format(email=email),
                        headers=headers,
                    )
                if response.status_code == 200:
                    breaches = response.json()
                    has_passwords = any(
                        "Passwords" in breach.get("DataClasses", [])
                        for breach in breaches
                    )
                    results[email] = BreachResult(
                        email=email,
                        breached=True,
                        breach_count=len(breaches),
                        breaches=[breach.get("Name", "") for breach in breaches],
                        has_passwords=has_passwords,
                    )
                elif response.status_code == 404:
                    results[email] = BreachResult(email=email, breached=False)
                elif response.status_code == 429:
                    log.warning("[hibp] Rate limited while checking %s", email)
                else:
                    log.debug("[hibp] Unexpected status %s for %s", response.status_code, email)
            except Exception as exc:
                log.warning("[hibp] Error checking %s: %s", email, exc)

            if delay > 0:
                await asyncio.sleep(delay)

        return results

    async def _run_harvester(self, domain: str) -> list[str]:
        """Run theHarvester if installed and parse emails from stdout."""
        if not shutil.which("theHarvester"):
            log.info("[email_osint] theHarvester not found — skipping")
            return []
        try:
            proc = await asyncio.create_subprocess_exec(
                "theHarvester",
                "-d",
                domain,
                "-b",
                "all",
                "-l",
                "50",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60.0)
            return self._extract_emails_from_text(stdout.decode(errors="ignore"), domain)
        except Exception as exc:
            log.warning("[harvester] Error: %s", exc)
            return []

    async def _run_hunter(self, domain: str, api_key: str) -> list[str]:
        """Query hunter.io domain search API."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    HUNTER_API_URL,
                    params={"domain": domain, "api_key": api_key},
                )
            if response.status_code != 200:
                return []
            data = response.json()
            return [
                item["value"].lower()
                for item in data.get("data", {}).get("emails", [])
                if isinstance(item, dict) and item.get("value")
            ]
        except Exception as exc:
            log.warning("[hunter.io] Error: %s", exc)
            return []

    def _extract_emails_from_text(self, text: str, domain: str) -> list[str]:
        """Extract domain email addresses from arbitrary text."""
        pattern = rf"[a-zA-Z0-9._%+\-]+@{re.escape(domain)}"
        return sorted(set(match.lower() for match in re.findall(pattern, text, re.IGNORECASE)))

    def generate_email_patterns(self, domain: str, first: str, last: str) -> list[str]:
        """Generate common corporate email patterns from a name."""
        first = first.lower()
        last = last.lower()
        patterns = {
            f"{first}.{last}@{domain}",
            f"{first}{last}@{domain}",
            f"{last}.{first}@{domain}",
            f"{first[0]}{last}@{domain}",
            f"{first}.{last[0]}@{domain}",
            f"{first}_{last}@{domain}",
            f"{last}@{domain}",
            f"{first}@{domain}",
        }
        return sorted(patterns)
