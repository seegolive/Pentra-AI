"""Tests for UserAgent rotation module."""
from __future__ import annotations
import pytest


def test_ua_list_has_15_or_more_entries():
    from pentra_tools.http.user_agent_rotator import UA_LIST
    assert len(UA_LIST) >= 15, f"UA_LIST has only {len(UA_LIST)} entries"


def test_get_random_ua_returns_string():
    from pentra_tools.http.user_agent_rotator import get_random_ua
    ua = get_random_ua()
    assert isinstance(ua, str)
    assert len(ua) > 20


def test_get_random_ua_varies():
    from pentra_tools.http.user_agent_rotator import get_random_ua
    results = {get_random_ua() for _ in range(50)}
    assert len(results) > 1, "get_random_ua always returns the same value"


def test_get_ua_for_waf_cloudflare_returns_string():
    from pentra_tools.http.user_agent_rotator import get_ua_for_waf
    ua = get_ua_for_waf("cloudflare")
    assert isinstance(ua, str)
    assert len(ua) > 20


def test_get_ua_for_waf_none_returns_string():
    from pentra_tools.http.user_agent_rotator import get_ua_for_waf
    ua = get_ua_for_waf(None)
    assert isinstance(ua, str)
    assert len(ua) > 20


def test_get_ua_for_waf_unknown_returns_string():
    from pentra_tools.http.user_agent_rotator import get_ua_for_waf
    ua = get_ua_for_waf("some_unknown_waf")
    assert isinstance(ua, str)
    assert len(ua) > 20


def test_all_uas_are_nonempty_strings():
    from pentra_tools.http.user_agent_rotator import UA_LIST
    for ua in UA_LIST:
        assert isinstance(ua, str)
        assert len(ua) > 20, f"UA too short: {ua!r}"
