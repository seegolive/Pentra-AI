"""Tests: rate limiting middleware — sliding window per user."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.core.middleware.rate_limit import (
    RateLimitMiddleware,
    _extract_user_key,
    _sliding_window_check,
)


# ── _extract_user_key ─────────────────────────────────────────────────────────

def _make_request(auth_header: str | None = None, client_ip: str = "127.0.0.1") -> MagicMock:
    req = MagicMock()
    req.headers = {}
    if auth_header:
        req.headers["authorization"] = auth_header
    req.client = MagicMock()
    req.client.host = client_ip
    return req


def _make_jwt_token(sub: str) -> str:
    """Create a minimal (unsigned) JWT token with given sub claim."""
    import base64, json
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload_data = json.dumps({"sub": sub}).encode()
    payload = base64.urlsafe_b64encode(payload_data).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesig"


def test_extract_key_from_valid_jwt():
    """Should extract user:<sub> from valid Bearer JWT."""
    user_id = str(uuid4())
    token = _make_jwt_token(user_id)
    req = _make_request(auth_header=f"Bearer {token}")
    key = _extract_user_key(req)
    assert key == f"user:{user_id}"


def test_extract_key_falls_back_to_ip_without_auth():
    """Without Authorization header, should use ip:<client_ip>."""
    req = _make_request(client_ip="192.168.1.100")
    key = _extract_user_key(req)
    assert key == "ip:192.168.1.100"


def test_extract_key_falls_back_to_ip_with_bad_token():
    """Malformed JWT should fall back to IP."""
    req = _make_request(auth_header="Bearer notavalidtoken", client_ip="10.0.0.1")
    key = _extract_user_key(req)
    assert key == "ip:10.0.0.1"


def test_extract_key_uses_x_forwarded_for():
    """X-Forwarded-For header should be used for IP when present."""
    req = _make_request(client_ip="10.0.0.1")
    req.headers["x-forwarded-for"] = "203.0.113.5, 10.0.0.1"
    key = _extract_user_key(req)
    assert key == "ip:203.0.113.5"


# ── _sliding_window_check ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sliding_window_allows_under_limit():
    """Requests under the limit should be allowed."""
    redis = MagicMock()
    pipe = AsyncMock()
    pipe.execute = AsyncMock(return_value=[None, 5, None, None])  # 5 existing requests
    redis.pipeline = MagicMock(return_value=pipe)

    allowed, remaining, retry_after = await _sliding_window_check(
        redis, "user:abc", "/api/v1/engagements", limit=10, window=60
    )

    assert allowed is True
    assert remaining == 4  # 10 - 5 - 1
    assert retry_after == 0


@pytest.mark.asyncio
async def test_sliding_window_blocks_at_limit():
    """At the limit, request should be blocked."""
    redis = MagicMock()
    pipe = AsyncMock()
    pipe.execute = AsyncMock(return_value=[None, 10, None, None])  # exactly at limit
    redis.pipeline = MagicMock(return_value=pipe)

    allowed, remaining, retry_after = await _sliding_window_check(
        redis, "user:abc", "/api/v1/engagements", limit=10, window=60
    )

    assert allowed is False
    assert remaining == 0
    assert retry_after == 60


@pytest.mark.asyncio
async def test_sliding_window_fails_open_on_redis_error():
    """If Redis raises an exception, request should be allowed (fail open)."""
    redis = MagicMock()
    pipe = AsyncMock()
    pipe.execute = AsyncMock(side_effect=Exception("Redis unavailable"))
    redis.pipeline = MagicMock(return_value=pipe)

    allowed, remaining, retry_after = await _sliding_window_check(
        redis, "user:abc", "/api/v1/engagements", limit=10, window=60
    )

    assert allowed is True


# ── Expensive endpoint limits ─────────────────────────────────────────────────

def test_expensive_endpoint_detection():
    """Payload and inject endpoints should be identified as expensive."""
    from app.core.middleware.rate_limit import _EXPENSIVE_PREFIXES

    assert "/api/v1/payloads/generate" in _EXPENSIVE_PREFIXES
    assert "/api/v1/knowledge/inject/" in _EXPENSIVE_PREFIXES


@pytest.mark.asyncio
async def test_expensive_endpoint_uses_lower_limit():
    """generate endpoint should use expensive_limit, not default_limit."""
    redis = MagicMock()
    pipe = AsyncMock()
    # 9 requests already — under expensive limit (10) but over default for test
    pipe.execute = AsyncMock(return_value=[None, 9, None, None])
    redis.pipeline = MagicMock(return_value=pipe)

    # Check with expensive limit = 10
    allowed, remaining, _ = await _sliding_window_check(
        redis, "user:abc", "/api/v1/payloads/generate", limit=10, window=60
    )
    assert allowed is True  # 9 < 10

    # Same request count but limit=5 (as if it were even tighter)
    pipe.execute = AsyncMock(return_value=[None, 5, None, None])
    allowed2, remaining2, _ = await _sliding_window_check(
        redis, "user:abc", "/api/v1/payloads/generate", limit=5, window=60
    )
    assert allowed2 is False  # 5 >= 5
