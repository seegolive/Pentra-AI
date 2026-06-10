"""Subdomain Takeover Detector — Task 20.2 (Sprint 20).

Detects dangling CNAME records pointing to third-party services
that are no longer claimed — allowing an attacker to take over the subdomain.

Based on:
  - can-i-take-over-xyz fingerprints (EdOverflow)
  - nuclei takeover templates
  - BadDNS methodology

Usage:
    from pentra_tools.recon.takeover_detector import detect_subdomain_takeovers

    findings = await detect_subdomain_takeovers(
        subdomains=["blog.target.com", "cdn.target.com"],
    )
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


# ── Fingerprint database ──────────────────────────────────────────────────────
# Source: can-i-take-over-xyz + nuclei takeover templates

TAKEOVER_FINGERPRINTS: dict[str, dict] = {
    "github_pages": {
        "cname_patterns": ["github.io", "github.com"],
        "fingerprint": "There isn't a GitHub Pages site here",
        "service": "GitHub Pages",
        "severity": "high",
    },
    "heroku": {
        "cname_patterns": ["herokuapp.com"],
        "fingerprint": "No such app",
        "service": "Heroku",
        "severity": "high",
    },
    "aws_s3": {
        "cname_patterns": ["s3.amazonaws.com", "s3-website"],
        "fingerprint": "NoSuchBucket",
        "service": "AWS S3",
        "severity": "high",
    },
    "netlify": {
        "cname_patterns": ["netlify.app", "netlify.com"],
        "fingerprint": "Not Found - Request ID",
        "service": "Netlify",
        "severity": "medium",
    },
    "vercel": {
        "cname_patterns": ["vercel.app", "now.sh"],
        "fingerprint": "The deployment you are trying to access does not exist",
        "service": "Vercel",
        "severity": "medium",
    },
    "azure": {
        "cname_patterns": ["azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"],
        "fingerprint": "404 Web Site not found",
        "service": "Azure App Service",
        "severity": "high",
    },
    "shopify": {
        "cname_patterns": ["myshopify.com"],
        "fingerprint": "Sorry, this shop is currently unavailable",
        "service": "Shopify",
        "severity": "medium",
    },
    "fastly": {
        "cname_patterns": ["fastly.net"],
        "fingerprint": "Fastly error: unknown domain",
        "service": "Fastly",
        "severity": "medium",
    },
    "pantheon": {
        "cname_patterns": ["pantheonsite.io"],
        "fingerprint": "The gods are wise, but do not know of the site",
        "service": "Pantheon",
        "severity": "medium",
    },
    "wordpress": {
        "cname_patterns": ["wordpress.com"],
        "fingerprint": "Do you want to register",
        "service": "WordPress.com",
        "severity": "medium",
    },
    "ghost": {
        "cname_patterns": ["ghost.io"],
        "fingerprint": "The thing you were looking for is no longer here",
        "service": "Ghost",
        "severity": "medium",
    },
    "bitbucket": {
        "cname_patterns": ["bitbucket.io"],
        "fingerprint": "Repository not found",
        "service": "Bitbucket",
        "severity": "medium",
    },
    "zendesk": {
        "cname_patterns": ["zendesk.com"],
        "fingerprint": "Help Center Closed",
        "service": "Zendesk",
        "severity": "medium",
    },
    "surge": {
        "cname_patterns": ["surge.sh"],
        "fingerprint": "project not found",
        "service": "Surge.sh",
        "severity": "medium",
    },
    "readthedocs": {
        "cname_patterns": ["readthedocs.io"],
        "fingerprint": "unknown to Read the Docs",
        "service": "ReadTheDocs",
        "severity": "medium",
    },
}


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class TakeoverFinding:
    """A confirmed or likely subdomain takeover."""
    subdomain: str
    cname_target: str
    service: str
    severity: str
    fingerprint: str
    confidence: str     # "certain" | "likely" | "possible"

    def to_finding(self) -> dict:
        return {
            "title": f"Subdomain Takeover — {self.subdomain} ({self.service})",
            "severity": self.severity,
            "vuln_class": "SUBDOMAIN_TAKEOVER",
            "target_url": f"https://{self.subdomain}",
            "description": (
                f"Subdomain '{self.subdomain}' has a dangling CNAME record pointing to "
                f"'{self.cname_target}' ({self.service}). "
                f"The resource at that service is no longer claimed. "
                f"An attacker can register this resource and serve malicious content "
                f"from your subdomain, enabling cookie theft, phishing, and CSP bypass."
            ),
            "request_raw": f"CNAME: {self.subdomain} → {self.cname_target}",
            "response_raw": (
                f"Fingerprint: '{self.fingerprint}' detected in response "
                f"(confidence: {self.confidence})"
            ),
            "source": "takeover_detector",
            "remediation": (
                f"Remove the dangling DNS CNAME record for '{self.subdomain}', "
                f"or immediately re-register the resource on {self.service}. "
                "Implement regular DNS audits to catch dangling records early."
            ),
        }


# ── DNS helpers ───────────────────────────────────────────────────────────────

async def check_dns_cname(domain: str) -> str | None:
    """Resolve CNAME record for domain. Return CNAME target or None.

    Requires dnspython (installed as dependency).
    """
    try:
        import dns.resolver
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: dns.resolver.resolve(domain, "CNAME"),
        )
        return str(result[0].target).rstrip(".")
    except Exception:
        return None


# ── Fingerprint checker ───────────────────────────────────────────────────────

async def check_takeover_fingerprint(
    subdomain: str,
    cname: str,
    client: httpx.AsyncClient,
) -> TakeoverFinding | None:
    """Check if subdomain is vulnerable to takeover based on CNAME + response fingerprint.

    Args:
        subdomain: The subdomain to test (e.g. "blog.target.com").
        cname:     Resolved CNAME target (e.g. "target-org.github.io").
        client:    Shared httpx client for HTTP probing.

    Returns:
        TakeoverFinding if vulnerable, None otherwise.
    """
    for service_name, config in TAKEOVER_FINGERPRINTS.items():
        # Check CNAME points to this service
        if not any(pattern in cname.lower() for pattern in config["cname_patterns"]):
            continue

        # Fetch subdomain and check for takeover fingerprint
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                resp = await client.get(url, timeout=8.0)
                body = resp.text.lower()

                if config["fingerprint"].lower() in body:
                    logger.info(
                        "[takeover] VULNERABLE: %s → %s (%s)",
                        subdomain, cname, config["service"],
                    )
                    return TakeoverFinding(
                        subdomain=subdomain,
                        cname_target=cname,
                        service=config["service"],
                        severity=config["severity"],
                        fingerprint=config["fingerprint"],
                        confidence="certain",
                    )
                break  # Got a response — stop trying http vs https

            except httpx.ConnectError:
                # NXDOMAIN or connection refused — possibly dangling
                # Only flag AWS S3 with high confidence on connection error
                if service_name == "aws_s3":
                    return TakeoverFinding(
                        subdomain=subdomain,
                        cname_target=cname,
                        service=config["service"],
                        severity=config["severity"],
                        fingerprint="NXDOMAIN/Connection refused",
                        confidence="likely",
                    )
                break
            except Exception:
                break

    return None


# ── Main entry point ──────────────────────────────────────────────────────────

async def detect_subdomain_takeovers(
    subdomains: list[str],
    scope_check_fn=None,
    proxy_url: str | None = None,
) -> list[dict]:
    """Run takeover detection for a list of subdomains.

    Resolves CNAME for each subdomain, then probes for service fingerprints
    that indicate a dangling / unclaimed resource.

    Args:
        subdomains:     List of subdomain strings (e.g. ["blog.target.com"]).
        scope_check_fn: Optional callable(url) -> bool scope enforcer.
        proxy_url:      Optional HTTP proxy URL.

    Returns:
        List of finding dicts in Pentra AI format.
    """
    try:
        import dns.resolver  # noqa: F401
    except ImportError:
        logger.warning("[takeover] dnspython not installed — skipping takeover detection. "
                       "Run: uv add dnspython")
        return []

    if not subdomains:
        return []

    proxy = proxy_url if proxy_url else None

    async with httpx.AsyncClient(
        verify=False,  # noqa: S501
        follow_redirects=False,
        timeout=10.0,
        **({"proxy": proxy} if proxy else {}),
    ) as client:
        tasks = [
            _check_single(sub, client, scope_check_fn)
            for sub in subdomains
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[dict] = []
    for result in results:
        if isinstance(result, TakeoverFinding):
            findings.append(result.to_finding())
        elif isinstance(result, Exception):
            logger.debug("[takeover] Check error: %s", result)

    if findings:
        logger.info("[takeover] %d subdomain takeover(s) detected", len(findings))
    else:
        logger.debug("[takeover] No subdomain takeovers detected (%d checked)", len(subdomains))

    return findings


async def _check_single(
    subdomain: str,
    client: httpx.AsyncClient,
    scope_check_fn=None,
) -> TakeoverFinding | None:
    """Check a single subdomain for takeover vulnerability."""
    if scope_check_fn and not scope_check_fn(f"http://{subdomain}"):
        return None

    cname = await check_dns_cname(subdomain)
    if not cname:
        return None

    return await check_takeover_fingerprint(subdomain, cname, client)
