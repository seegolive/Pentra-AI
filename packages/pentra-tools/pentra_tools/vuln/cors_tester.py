"""CORS Misconfiguration Tester — Task 19.3 (Sprint 19).

Detects CORS misconfigurations by injecting crafted Origin headers and
analyzing Access-Control-Allow-Origin + Access-Control-Allow-Credentials.

Common misconfigs:
  - Reflects arbitrary origin + allows credentials → account takeover
  - Null origin accepted → local file bypass
  - Suffix/prefix bypass (evil.target.com, target.com.evil.com)
  - HTTP downgrade (accepts http:// for https:// origin)
  - Wildcard (*) with credentials → browsers block but server misconfigured

Usage:
    from pentra_tools.vuln.cors_tester import test_cors

    findings = await test_cors("https://api.target.com/user/profile")
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

# Origin payloads: (origin_value, test_description)
CORS_ORIGIN_TESTS = [
    ("null", "Null origin bypass"),
    ("https://evil.com", "Generic evil origin"),
    ("https://target.com.evil.com", "Suffix bypass (reflected domain as prefix)"),
    ("https://evil.target.com", "Subdomain bypass"),
    ("https://notTarget.com", "Completely different domain"),
    ("http://target.com", "HTTP downgrade of HTTPS origin"),
]


async def check_cors(
    url: str,
    auth_headers: dict | None = None,
    proxy_url: str | None = None,
) -> list[dict]:
    """Test CORS misconfiguration on a single endpoint.

    Sends requests with crafted Origin headers and checks the
    Access-Control-Allow-Origin and Access-Control-Allow-Credentials headers.

    Args:
        url:         Target URL to test.
        auth_headers: Optional auth headers to include.
        proxy_url:   Optional HTTP proxy (e.g. Burp).

    Returns:
        List of finding dicts (empty if no misconfigurations found).
    """
    findings: list[dict] = []
    base_headers = dict(auth_headers or {})
    proxies = {"http://": proxy_url, "https://": proxy_url} if proxy_url else None

    async with httpx.AsyncClient(
        verify=False,  # noqa: S501
        timeout=8.0,
        follow_redirects=True,
        proxies=proxies,  # type: ignore[arg-type]
    ) as client:

        # Get baseline without Origin header (to compare ACAO)
        try:
            baseline = await client.get(url, headers=base_headers)
            baseline_acao = baseline.headers.get("Access-Control-Allow-Origin", "")
        except Exception:
            return []

        for origin, test_name in CORS_ORIGIN_TESTS:
            try:
                resp = await client.get(
                    url,
                    headers={**base_headers, "Origin": origin},
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                # Critical: reflects injected evil origin AND allows credentials
                if acao == origin and acac == "true":
                    findings.append({
                        "title": f"CORS Misconfiguration — {test_name}",
                        "severity": "high",
                        "vuln_class": "CORS_MISCONFIGURATION",
                        "target_url": url,
                        "description": (
                            f"Server reflects origin '{origin}' in ACAO header and sets "
                            f"Access-Control-Allow-Credentials: true. "
                            f"An attacker at {origin} can make authenticated cross-origin requests, "
                            "reading private API responses including session data and PII."
                        ),
                        "request_raw": f"GET {url}\nOrigin: {origin}",
                        "response_raw": (
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}"
                        ),
                        "source": "cors_tester",
                        "remediation": (
                            "Never reflect arbitrary origins. Maintain an explicit allowlist. "
                            "Never combine wildcard (*) with credentials=true. "
                            "Validate Origin against a strict allowlist before reflecting."
                        ),
                        "param_name": "Origin",
                        "param_location": "header",
                        "payload": origin,
                    })
                    logger.info("[cors] Misconfiguration confirmed: %s at %s", test_name, url)
                    break  # one confirmed finding per endpoint is enough

                # Medium: wildcard with credentials (browser blocks but misconfigured)
                elif acao == "*" and acac == "true":
                    findings.append({
                        "title": "CORS Wildcard with Credentials",
                        "severity": "medium",
                        "vuln_class": "CORS_MISCONFIGURATION",
                        "target_url": url,
                        "description": (
                            "Server responds with Access-Control-Allow-Origin: * and "
                            "Access-Control-Allow-Credentials: true. "
                            "Browsers block this combination, but it indicates CORS misconfiguration."
                        ),
                        "request_raw": f"GET {url}\nOrigin: {origin}",
                        "response_raw": f"ACAO: *\nACAC: true",
                        "source": "cors_tester",
                        "remediation": "Remove the wildcard origin and use an explicit allowlist.",
                    })
                    break

                # Info: ACAO changed from baseline — note but don't flag as vuln
                elif acao and acao != baseline_acao and acao != "*":
                    logger.debug("[cors] Origin reflection (no credentials): %s → ACAO=%s", origin, acao)

            except Exception as exc:
                logger.debug("[cors] Test failed for %s at %s: %s", test_name, url, exc)

    return findings


async def scan_cors_on_endpoints(
    endpoints: list[dict],
    auth_headers: dict | None = None,
    proxy_url: str | None = None,
    max_endpoints: int = 10,
) -> list[dict]:
    """Run CORS tests on multiple endpoints concurrently.

    Args:
        endpoints:     List of endpoint dicts (with 'url' key).
        auth_headers:  Optional auth headers.
        proxy_url:     Optional proxy URL.
        max_endpoints: Cap to avoid flooding.

    Returns:
        All CORS findings across all tested endpoints.
    """
    import asyncio

    live_urls = [ep.get("url", "") for ep in endpoints if ep.get("url")][:max_endpoints]
    if not live_urls:
        return []

    results = await asyncio.gather(
        *[check_cors(url, auth_headers=auth_headers, proxy_url=proxy_url) for url in live_urls],
        return_exceptions=True,
    )

    all_findings: list[dict] = []
    for result in results:
        if isinstance(result, list):
            all_findings.extend(result)

    if all_findings:
        logger.info("[cors] %d CORS findings across %d endpoints", len(all_findings), len(live_urls))

    return all_findings
