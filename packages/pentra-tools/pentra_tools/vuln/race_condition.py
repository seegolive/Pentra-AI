"""Race Condition Tester — Task 19.2 (Sprint 19).

Detect timing-based business logic flaws via concurrent HTTP requests.
Inspired by PortSwigger Research: Single-packet attack (HTTP/2).

Focus: endpoints that should only be processed once but accept multiple
concurrent requests (coupon redemption, payment, vote, transfer, etc.).

Usage:
    from pentra_tools.vuln.race_condition import identify_race_candidates, test_race_condition

    candidates = identify_race_candidates(endpoints)
    for candidate in candidates:
        result = await test_race_condition(candidate["url"], method="POST")
        if result and result.race_detected:
            print(f"Race condition: {result.evidence}")
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


# ── URL patterns prone to race conditions ─────────────────────────────────────

RACE_PRONE_PATTERNS = [
    r"/(redeem|apply|use|claim|voucher|coupon|promo|discount)",
    r"/(purchase|buy|order|checkout|payment|pay)",
    r"/(transfer|send|withdraw|deposit|refund)",
    r"/(vote|like|upvote|follow|subscribe|react)",
    r"/(register|signup|enroll|join)",
    r"/(verify|confirm|activate|approve|validate)",
    r"/(consume|spend|deduct|debit|credit)",
    r"/(reserve|book|lock|hold)",
]


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class RaceResult:
    """Result of a race condition test."""
    endpoint: str
    http_method: str
    concurrent_requests: int
    successful_responses: int
    unique_responses: int
    race_detected: bool
    evidence: str
    severity: str       # high/medium/info

    def to_finding(self) -> dict:
        if not self.race_detected:
            return {}
        return {
            "title": f"Race Condition — {self.endpoint}",
            "severity": self.severity,
            "vuln_class": "RACE_CONDITION",
            "target_url": self.endpoint,
            "description": (
                f"Race condition detected: {self.successful_responses}/{self.concurrent_requests} "
                f"concurrent requests succeeded simultaneously on an endpoint that should "
                "process only one at a time. An attacker can exploit this to double-spend, "
                "apply discounts multiple times, or bypass one-time-use restrictions."
            ),
            "request_raw": f"{self.http_method} {self.endpoint}",
            "response_raw": self.evidence,
            "source": "race_condition_tester",
            "remediation": (
                "Implement database-level locking (SELECT FOR UPDATE), idempotency keys, "
                "or atomic operations. Use Redis SETNX for distributed locking. "
                "Never rely on application-level checks without DB-level enforcement."
            ),
        }


# ── Candidate identification ──────────────────────────────────────────────────

def identify_race_candidates(endpoints: list[dict]) -> list[dict]:
    """Filter endpoints that are likely to have race condition vulnerabilities.

    Checks URL patterns and HTTP method (POST/PATCH/PUT only — GET is idempotent).

    Returns:
        Filtered endpoint list with added 'race_pattern' key.
    """
    candidates: list[dict] = []

    for ep in endpoints:
        url = ep.get("url", "")
        method = ep.get("method", "GET").upper()

        # Only test state-changing endpoints
        if method not in ("POST", "PATCH", "PUT"):
            continue

        for pattern in RACE_PRONE_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                candidates.append({**ep, "race_pattern": pattern})
                break

    logger.info(
        "[race_condition] %d/%d endpoints identified as race candidates",
        len(candidates), len(endpoints),
    )
    return candidates


# ── Race condition tester ─────────────────────────────────────────────────────

async def check_race_condition(
    url: str,
    method: str = "POST",
    body: dict | None = None,
    headers: dict | None = None,
    concurrency: int = 20,
    scope_check_fn=None,
    proxy_url: str | None = None,
) -> RaceResult | None:
    """Test race condition with simultaneous HTTP requests.

    Single-packet attack: all requests are sent in one burst via asyncio.gather
    to maximize the chance of hitting the server simultaneously.

    If an endpoint should accept only 1 request but multiple succeed → race condition.

    Args:
        url:             Target URL.
        method:          HTTP method (POST/GET etc.).
        body:            Optional request body dict.
        headers:         Optional extra headers (auth, content-type etc.).
        concurrency:     Number of simultaneous requests to send.
        scope_check_fn:  Optional callable(url) -> bool for scope enforcement.
        proxy_url:       Optional HTTP proxy URL.

    Returns:
        RaceResult, or None if out of scope.
    """
    if scope_check_fn and not scope_check_fn(url):
        return None

    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    proxy = proxy_url if proxy_url else None

    async def _single_request(client: httpx.AsyncClient) -> dict:
        t0 = time.monotonic()
        try:
            if method.upper() in ("POST", "PATCH", "PUT"):
                resp = await client.request(
                    method.upper(), url, json=body or {}, headers=req_headers, timeout=10.0
                )
            else:
                resp = await client.get(url, headers=req_headers, timeout=10.0)
            return {
                "status": resp.status_code,
                "body": resp.text[:200],
                "elapsed": time.monotonic() - t0,
            }
        except Exception as exc:
            return {"status": 0, "error": str(exc), "elapsed": 0.0}

    try:
        async with httpx.AsyncClient(
            verify=False,  # noqa: S501
            http2=True,    # HTTP/2 single-packet attack when supported
            follow_redirects=True,
            **({"proxy": proxy} if proxy else {}),
        ) as client:
            # Launch all concurrent — HTTP/2 allows single-packet attack
            tasks = [_single_request(client) for _ in range(concurrency)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as exc:
        logger.debug("[race_condition] Client setup failed: %s", exc)
        return None

    valid = [r for r in results if isinstance(r, dict) and r.get("status", 0) > 0]
    success_count = sum(1 for r in valid if r["status"] in (200, 201, 204))
    unique_bodies = len({r.get("body", "") for r in valid if r.get("body")})

    # Race condition: multiple requests succeeded when only 1 should
    race_detected = success_count > 1
    severity = "high" if success_count > 5 else "medium" if success_count > 1 else "info"

    result = RaceResult(
        endpoint=url,
        http_method=method.upper(),
        concurrent_requests=concurrency,
        successful_responses=success_count,
        unique_responses=unique_bodies,
        race_detected=race_detected,
        evidence=(
            f"{success_count}/{concurrency} requests succeeded simultaneously. "
            f"Expected: ≤1 success if endpoint has proper locking."
        ) if race_detected else f"No race condition: only {success_count}/{concurrency} succeeded",
        severity=severity,
    )

    if race_detected:
        logger.info(
            "[race_condition] DETECTED at %s — %d/%d succeeded",
            url, success_count, concurrency,
        )

    return result
