"""Tests for JWT Vulnerability Tester — Task 20.1."""

from __future__ import annotations

import base64
import json

import pytest

from pentra_tools.vuln.jwt_tester import (
    b64url_encode,
    decode_jwt,
    forge_none_algorithm,
    forge_role_escalation,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_fake_jwt(header: dict, payload: dict, sig: str = "fakesig") -> str:
    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64(header)}.{b64(payload)}.{sig}"


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_decode_valid_jwt():
    """decode_jwt should extract header and payload from a valid token."""
    token = make_fake_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "user1", "role": "user", "exp": 9999999999},
    )
    result = decode_jwt(token)
    assert result is not None
    header, payload, sig = result
    assert header["alg"] == "HS256"
    assert payload["sub"] == "user1"
    assert sig == "fakesig"


def test_decode_invalid_returns_none():
    """decode_jwt should return None for malformed tokens."""
    assert decode_jwt("not.a.valid.jwt.token") is None
    assert decode_jwt("onlytwoparts.here") is None
    assert decode_jwt("") is None


def test_forge_none_algorithm():
    """forge_none_algorithm should produce a JWT with alg=none and empty signature."""
    token = make_fake_jwt({"alg": "HS256"}, {"sub": "user", "role": "user"})
    forged = forge_none_algorithm(token, {"role": "admin"})

    parts = forged.split(".")
    assert len(parts) == 3

    # Header must have alg=none
    h = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    assert h["alg"] == "none"

    # Signature must be empty
    assert parts[2] == ""

    # Payload must have escalated role
    p = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert p["role"] == "admin"


def test_forge_role_escalation():
    """forge_role_escalation should inject admin claims with invalid signature."""
    token = make_fake_jwt({"alg": "HS256"}, {"sub": "user123", "role": "user"})
    forged = forge_role_escalation(token, role_field="role", admin_value="admin")

    parts = forged.split(".")
    assert len(parts) == 3

    # Payload should have escalated values
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert payload["role"] == "admin"
    assert payload["is_admin"] is True
    assert payload["admin"] is True

    # Signature must be intentionally invalid string
    assert parts[2] == "invalidsignature"


def test_none_alg_token_is_valid_structure():
    """forge_none_algorithm on RS256 token should produce correctly structured token."""
    token = make_fake_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "1", "exp": 9999999999, "iat": 1000000000},
    )
    none_tok = forge_none_algorithm(token)

    parts = none_tok.split(".")
    assert len(parts) == 3

    # Must decode without errors
    h = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    assert h["alg"] == "none"
    assert h["typ"] == "JWT"

    # Payload must preserve original fields
    p = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert p["sub"] == "1"
