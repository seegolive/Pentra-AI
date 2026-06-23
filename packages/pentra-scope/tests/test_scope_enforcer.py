"""Tests for ScopeEnforcer — the security-critical scope validator.

Every agent tool call goes through ScopeEnforcer before executing.
These tests cover all supported rule formats and edge cases.
"""

from __future__ import annotations

import pytest

from pentra_scope.errors import ScopeViolationError
from pentra_scope.validator import ScopeEnforcer


# ── Exact domain match ────────────────────────────────────────────────────────

def test_exact_domain_allowed():
    e = ScopeEnforcer(in_scope=["target.com"])
    assert e.is_allowed("target.com") is True


def test_exact_domain_blocked():
    e = ScopeEnforcer(in_scope=["target.com"])
    assert e.is_allowed("other.com") is False


def test_subdomain_of_exact_is_blocked():
    e = ScopeEnforcer(in_scope=["target.com"])
    assert e.is_allowed("sub.target.com") is False


# ── Wildcard subdomain ────────────────────────────────────────────────────────

def test_wildcard_matches_direct_subdomain():
    e = ScopeEnforcer(in_scope=["*.target.com"])
    assert e.is_allowed("api.target.com") is True


def test_wildcard_matches_deep_subdomain():
    e = ScopeEnforcer(in_scope=["*.target.com"])
    assert e.is_allowed("deep.api.target.com") is True


def test_wildcard_matches_apex_too():
    e = ScopeEnforcer(in_scope=["*.target.com"])
    assert e.is_allowed("target.com") is True


def test_wildcard_does_not_match_other_domain():
    e = ScopeEnforcer(in_scope=["*.target.com"])
    assert e.is_allowed("evil.com") is False


def test_wildcard_does_not_match_partial_suffix():
    e = ScopeEnforcer(in_scope=["*.target.com"])
    assert e.is_allowed("notarget.com") is False


# ── CIDR range ────────────────────────────────────────────────────────────────

def test_cidr_allows_host_inside_range():
    e = ScopeEnforcer(in_scope=["10.0.0.0/8"])
    assert e.is_allowed("10.0.1.50") is True


def test_cidr_blocks_host_outside_range():
    e = ScopeEnforcer(in_scope=["10.0.0.0/8"])
    assert e.is_allowed("192.168.1.1") is False


def test_cidr_allows_network_address():
    e = ScopeEnforcer(in_scope=["192.168.0.0/24"])
    assert e.is_allowed("192.168.0.254") is True


def test_exact_ip_allowed():
    e = ScopeEnforcer(in_scope=["203.0.113.5"])
    assert e.is_allowed("203.0.113.5") is True


def test_exact_ip_blocks_different():
    e = ScopeEnforcer(in_scope=["203.0.113.5"])
    assert e.is_allowed("203.0.113.6") is False


# ── URL stripping ─────────────────────────────────────────────────────────────

def test_url_with_scheme_is_stripped():
    e = ScopeEnforcer(in_scope=["target.com"])
    assert e.is_allowed("https://target.com/api/v1/users") is True


def test_url_with_path_is_stripped():
    e = ScopeEnforcer(in_scope=["target.com"])
    assert e.is_allowed("target.com/login?next=/admin") is True


def test_url_http_stripped():
    e = ScopeEnforcer(in_scope=["*.target.com"])
    assert e.is_allowed("http://api.target.com/search?q=test") is True


# ── Out-of-scope exclusions ───────────────────────────────────────────────────

def test_explicit_exclusion_blocks_subdomain():
    e = ScopeEnforcer(in_scope=["*.target.com"], out_of_scope=["admin.target.com"])
    assert e.is_allowed("admin.target.com") is False


def test_excluded_domain_still_blocks_even_if_in_scope():
    e = ScopeEnforcer(in_scope=["target.com"], out_of_scope=["target.com"])
    assert e.is_allowed("target.com") is False


def test_exclusion_only_blocks_specified_subdomain():
    e = ScopeEnforcer(in_scope=["*.target.com"], out_of_scope=["admin.target.com"])
    assert e.is_allowed("api.target.com") is True
    assert e.is_allowed("admin.target.com") is False


# ── validate_or_raise ─────────────────────────────────────────────────────────

def test_validate_or_raise_passes_for_in_scope():
    e = ScopeEnforcer(in_scope=["target.com"])
    e.validate_or_raise("target.com")  # should not raise


def test_validate_or_raise_raises_scope_violation():
    e = ScopeEnforcer(in_scope=["target.com"])
    with pytest.raises(ScopeViolationError):
        e.validate_or_raise("evil.com")


def test_scope_violation_error_has_target():
    e = ScopeEnforcer(in_scope=["target.com"])
    try:
        e.validate_or_raise("evil.com")
    except ScopeViolationError as exc:
        assert exc.target == "evil.com"
    else:
        pytest.fail("Expected ScopeViolationError")


def test_validate_or_raise_raises_for_excluded():
    e = ScopeEnforcer(in_scope=["*.target.com"], out_of_scope=["admin.target.com"])
    with pytest.raises(ScopeViolationError):
        e.validate_or_raise("admin.target.com")


# ── Case insensitivity ────────────────────────────────────────────────────────

def test_case_insensitive_domain():
    e = ScopeEnforcer(in_scope=["Target.COM"])
    assert e.is_allowed("target.com") is True
    assert e.is_allowed("TARGET.COM") is True


def test_case_insensitive_in_url():
    e = ScopeEnforcer(in_scope=["target.com"])
    assert e.is_allowed("HTTPS://TARGET.COM/api") is True


# ── Empty scope ───────────────────────────────────────────────────────────────

def test_empty_in_scope_blocks_everything():
    e = ScopeEnforcer(in_scope=[])
    assert e.is_allowed("target.com") is False
    assert e.is_allowed("10.0.0.1") is False


def test_empty_out_of_scope_allows_all_in_scope():
    e = ScopeEnforcer(in_scope=["target.com"], out_of_scope=[])
    assert e.is_allowed("target.com") is True


# ── Mixed scope ───────────────────────────────────────────────────────────────

def test_multiple_in_scope_rules():
    e = ScopeEnforcer(in_scope=["target.com", "*.api.target.com", "10.0.0.0/8"])
    assert e.is_allowed("target.com") is True
    assert e.is_allowed("v2.api.target.com") is True
    assert e.is_allowed("10.10.10.10") is True
    assert e.is_allowed("evil.com") is False


def test_url_path_with_scope_wildcard():
    e = ScopeEnforcer(in_scope=["*.target.com"])
    assert e.is_allowed("https://api.target.com/v1/users?id=1") is True


# ── Port handling ─────────────────────────────────────────────────────────────

def test_port_stripped_from_url_for_domain_match():
    e = ScopeEnforcer(in_scope=["target.com"])
    assert e.is_allowed("https://target.com:8443/api") is True


def test_port_qualified_rule_matches():
    e = ScopeEnforcer(in_scope=["localhost:9999"])
    assert e.is_allowed("http://localhost:9999/test") is True


def test_port_qualified_rule_does_not_match_different_port():
    e = ScopeEnforcer(in_scope=["localhost:9999"])
    assert e.is_allowed("http://localhost:8080/test") is False
