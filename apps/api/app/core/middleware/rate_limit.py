"""Sliding-window rate limiting middleware using Redis.

Limits are applied per authenticated user (by JWT ``sub`` claim).
Unauthenticated requests are limited by IP address.

Default limits:
- 200 requests / minute per user (API endpoints)
- 10 requests / minute per user for payload generation (expensive LLM call)
- 5 requests / minute per user for KB inject endpoints
- 5 requests / minute per user for scan endpoints (subscan / start)

Configuration (via environment variables)::

    REDIS_URL=redis://localhost:6379/0
    RATE_LIMIT_DEFAULT=200          # requests per minute
    RATE_LIMIT_EXPENSIVE=10         # for /payloads/generate and /knowledge/inject/*
    RATE_LIMIT_SCAN=5               # for /engagements/*/subscan and /engagements/*/start
"""

from __future__ import annotations

import time
from typing import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Expensive endpoints get a tighter rate limit
_EXPENSIVE_PREFIXES = (
    "/api/v1/payloads/generate",
    "/api/v1/knowledge/inject/",
)
# Heavy scan endpoints: subscan triggers real tool execution; start launches the full agent
_SCAN_SUFFIXES = ("/subscan", "/start")
_WINDOW_SECONDS = 60


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter backed by Redis.

    Falls back gracefully if Redis is unavailable (logs warning, allows request).
    """

    def __init__(
        self,
        app,
        redis_url: str,
        default_limit: int = 200,
        expensive_limit: int = 10,
        scan_limit: int = 5,
    ) -> None:
        super().__init__(app)
        self._redis_url = redis_url
        self._default_limit = default_limit
        self._expensive_limit = expensive_limit
        self._scan_limit = scan_limit
        self._redis = None  # lazily initialised

    async def _get_redis(self):
        if self._redis is None:
            try:
                import redis.asyncio as aioredis
                self._redis = await aioredis.from_url(
                    self._redis_url, encoding="utf-8", decode_responses=True
                )
            except Exception:  # noqa: BLE001
                pass
        return self._redis

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip non-API routes and health check
        path = request.url.path
        if not path.startswith("/api/v1/"):
            return await call_next(request)

        # Identify caller: extract user_id from JWT or fall back to IP
        key_id = _extract_user_key(request)

        # Choose limit based on endpoint — most specific match wins
        if any(path.endswith(suffix) for suffix in _SCAN_SUFFIXES):
            limit = self._scan_limit
        elif any(path.startswith(prefix) for prefix in _EXPENSIVE_PREFIXES):
            limit = self._expensive_limit
        else:
            limit = self._default_limit

        redis = await self._get_redis()
        if redis is None:
            # Redis unavailable — allow the request, log once
            return await call_next(request)

        allowed, remaining, retry_after = await _sliding_window_check(
            redis, key_id, path, limit, _WINDOW_SECONDS
        )

        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Try again later.",
                    "retry_after": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + retry_after),
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        return response


def _extract_user_key(request: Request) -> str:
    """Return user_id from Bearer JWT, or client IP as fallback."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:]
        try:
            # Decode without verification just to extract sub (already verified by deps)
            import base64, json
            parts = token.split(".")
            if len(parts) >= 2:
                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(padded))
                sub = payload.get("sub", "")
                if sub:
                    return f"user:{sub}"
        except Exception:  # noqa: BLE001
            pass
    # Fallback: client IP
    forwarded = request.headers.get("x-forwarded-for", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    return f"ip:{ip}"


async def _sliding_window_check(
    redis,
    key_id: str,
    path: str,
    limit: int,
    window: int,
) -> tuple[bool, int, int]:
    """Sliding window rate limit check using Redis sorted set.

    Returns (allowed, remaining, retry_after_seconds).
    """
    now = time.time()
    window_start = now - window
    # Bucket key per user per endpoint class
    bucket = "all"
    if any(path.endswith(suffix) for suffix in _SCAN_SUFFIXES):
        bucket = "scan"
    else:
        for prefix in _EXPENSIVE_PREFIXES:
            if path.startswith(prefix):
                bucket = prefix.replace("/", "_")
                break
    redis_key = f"rl:{key_id}:{bucket}"

    try:
        pipe = redis.pipeline()
        # Remove old entries
        await pipe.zremrangebyscore(redis_key, 0, window_start)
        # Count current entries
        await pipe.zcard(redis_key)
        # Add this request
        await pipe.zadd(redis_key, {str(now): now})
        # Set TTL
        await pipe.expire(redis_key, window + 1)
        results = await pipe.execute()
        current_count = results[1]

        if current_count >= limit:
            return False, 0, window
        return True, limit - current_count - 1, 0
    except Exception:  # noqa: BLE001
        # Redis error — fail open
        return True, limit, 0
