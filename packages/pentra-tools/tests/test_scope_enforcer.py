"""Tests for ScopeEnforcer — the core security gate for all tool calls."""

import pytest
from pentra_scope import ScopeEnforcer, ScopeViolationError


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def enforcer() -> ScopeEnforcer:
    return ScopeEnforcer(
        in_scope=["target.com", "*.api.target.com", "10.0.0.0/8"],
        out_of_scope=["admin.target.com"],
    )


# ── Exact domain ───────────────────────────────────────────────────────────────

def test_exact_domain_in_scope(enforcer: ScopeEnforcer) -> None:
    enforcer.validate_or_raise("target.com")  # must not raise


def test_exact_domain_out_of_scope(enforcer: ScopeEnforcer) -> None:
    with pytest.raises(ScopeViolationError):
        enforcer.validate_or_raise("evil.com")


def test_explicit_exclusion_blocks(enforcer: ScopeEnforcer) -> None:
    """admin.target.com is a subdomain of target.com but explicitly excluded."""
    with pytest.raises(ScopeViolationError):
        enforcer.validate_or_raise("admin.target.com")


# ── Wildcard subdomain ─────────────────────────────────────────────────────────

def test_wildcard_subdomain_matches(enforcer: ScopeEnforcer) -> None:
    enforcer.validate_or_raise("v1.api.target.com")
    enforcer.validate_or_raise("v2.api.target.com")


def test_wildcard_parent_matches(enforcer: ScopeEnforcer) -> None:
    enforcer.validate_or_raise("api.target.com")


def test_wildcard_does_not_match_sibling(enforcer: ScopeEnforcer) -> None:
    # *.api.target.com should not match "other.target.com"
    with pytest.raises(ScopeViolationError):
        enforcer.validate_or_raise("other.target.com")


# ── URL stripping ─────────────────────────────────────────────────────────────

def test_url_scheme_stripped(enforcer: ScopeEnforcer) -> None:
    enforcer.validate_or_raise("https://target.com/login")


def test_url_port_stripped(enforcer: ScopeEnforcer) -> None:
    enforcer.validate_or_raise("target.com:443")


def test_url_path_stripped(enforcer: ScopeEnforcer) -> None:
    enforcer.validate_or_raise("target.com/api/v1/users")


# ── CIDR ───────────────────────────────────────────────────────────────────────

def test_ip_inside_cidr(enforcer: ScopeEnforcer) -> None:
    enforcer.validate_or_raise("10.10.20.30")


def test_ip_outside_cidr(enforcer: ScopeEnforcer) -> None:
    with pytest.raises(ScopeViolationError):
        enforcer.validate_or_raise("192.168.1.1")


# ── is_allowed convenience method ─────────────────────────────────────────────

def test_is_allowed_returns_bool(enforcer: ScopeEnforcer) -> None:
    assert enforcer.is_allowed("target.com") is True
    assert enforcer.is_allowed("evil.com") is False
    assert enforcer.is_allowed("admin.target.com") is False  # excluded
