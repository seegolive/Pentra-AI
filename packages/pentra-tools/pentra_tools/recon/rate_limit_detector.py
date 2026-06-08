"""
RateLimitDetector — probe target sebelum fuzzing intensif.
Deteksi: HTTP 429, X-RateLimit-* headers, Retry-After, timing variance.
Output: RateLimitResult.safe_rps untuk di-pass ke ffuf, katana, nuclei.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class RateLimitResult:
    url: str
    is_rate_limited: bool           # HTTP 429 ditemukan
    has_ratelimit_headers: bool     # X-RateLimit-* atau RateLimit-* header
    has_retry_after: bool           # Retry-After header ada
    timing_variance: float          # max/min response time ratio (1.0 = no variance)
    recommended_delay_ms: int       # delay antar request yang disarankan (ms)
    safe_rps: int                   # safe requests per second untuk tools
    notes: list[str] = field(default_factory=list)  # human-readable observations


async def probe_rate_limit(
    url: str,
    probe_count: int = 6,
    probe_interval: float = 0.15,
    timeout: float = 10.0,
) -> RateLimitResult:
    """
    Probe URL dengan N requests cepat dan analisis response patterns.

    Args:
        url: Target URL untuk diprobe
        probe_count: Jumlah request probe (default 6)
        probe_interval: Interval antar probe dalam detik (default 150ms)
        timeout: HTTP timeout per request dalam detik

    Returns:
        RateLimitResult dengan rekomendasi safe_rps dan delay
    """
    responses: list[dict] = []
    notes: list[str] = []

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        for i in range(probe_count):
            start = time.monotonic()
            try:
                r = await client.get(url)
                elapsed = time.monotonic() - start
                responses.append({
                    "status": r.status_code,
                    "elapsed": elapsed,
                    "retry_after": r.headers.get("Retry-After"),
                    "x_ratelimit_remaining": r.headers.get("X-RateLimit-Remaining"),
                    "x_ratelimit_limit": r.headers.get("X-RateLimit-Limit"),
                    "ratelimit_remaining": r.headers.get("RateLimit-Remaining"),
                    "ratelimit_policy": r.headers.get("RateLimit-Policy"),
                })
            except httpx.TimeoutException:
                responses.append({"status": 0, "elapsed": timeout})
            except Exception as exc:
                responses.append({"status": 0, "elapsed": 0.0, "error": str(exc)})

            if i < probe_count - 1:
                await asyncio.sleep(probe_interval)

    # ── Analysis ──────────────────────────────────────────────────────────────

    statuses = [r["status"] for r in responses]
    elapsed_times = [r["elapsed"] for r in responses if r.get("elapsed", 0) > 0]

    # 1. Hard rate limiting (HTTP 429)
    is_rate_limited = 429 in statuses
    if is_rate_limited:
        first_429 = statuses.index(429)
        notes.append(f"HTTP 429 detected after {first_429 + 1} requests")

    # 2. Rate limit response headers
    has_ratelimit_headers = any(
        r.get("x_ratelimit_remaining") is not None
        or r.get("ratelimit_remaining") is not None
        for r in responses
    )
    if has_ratelimit_headers:
        for r in responses:
            limit = r.get("x_ratelimit_limit") or r.get("ratelimit_policy")
            if limit:
                notes.append(f"Rate limit header detected: limit={limit}")
                break
        else:
            notes.append("Rate limit headers detected (X-RateLimit-* or RateLimit-*)")

    # 3. Retry-After header
    has_retry_after = any(r.get("retry_after") for r in responses)
    if has_retry_after:
        retry_val = next(
            (r["retry_after"] for r in responses if r.get("retry_after")), None
        )
        notes.append(f"Retry-After header present: {retry_val}")

    # 4. Timing variance — sustained increase suggests throttling
    timing_variance = 1.0
    if len(elapsed_times) >= 3:
        min_t = min(elapsed_times)
        max_t = max(elapsed_times)
        timing_variance = max_t / max(min_t, 0.001)
        if timing_variance > 5.0:
            notes.append(
                f"High timing variance ({timing_variance:.1f}x) — "
                "possible server-side throttling"
            )

    # ── Recommendations ───────────────────────────────────────────────────────

    if is_rate_limited:
        recommended_delay_ms = 2000
        safe_rps = 1
        notes.append("Aggressive rate limiting detected — use very slow scan mode")
    elif has_ratelimit_headers:
        recommended_delay_ms = 500
        safe_rps = 3
        notes.append("Rate limit headers present — using conservative speed")
    elif timing_variance > 3.0:
        recommended_delay_ms = 300
        safe_rps = 5
        notes.append("Timing variance suggests throttling — using moderate speed")
    elif has_retry_after:
        recommended_delay_ms = 1000
        safe_rps = 2
        notes.append("Retry-After header present — using slow speed")
    else:
        recommended_delay_ms = 0
        safe_rps = 20
        notes.append("No rate limiting detected — normal speed")

    result = RateLimitResult(
        url=url,
        is_rate_limited=is_rate_limited,
        has_ratelimit_headers=has_ratelimit_headers,
        has_retry_after=has_retry_after,
        timing_variance=round(timing_variance, 2),
        recommended_delay_ms=recommended_delay_ms,
        safe_rps=safe_rps,
        notes=notes,
    )

    logger.info(
        "[rate_limit_detector] %s → rate_limited=%s headers=%s safe_rps=%d notes=%s",
        url,
        is_rate_limited,
        has_ratelimit_headers,
        safe_rps,
        notes,
    )

    return result
