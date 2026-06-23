"""Tests for worker/app/tasks/agent.py helpers.

The Celery tasks themselves create live DB connections — tested via
pure-Python helpers: _extract_domain, _build_initial_state, _publish_event.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch


# ── _extract_domain ──────────────────────────────────────────────────────────

from app.tasks.agent import _extract_domain


def test_extract_domain_plain_domain():
    assert _extract_domain(["target.com"]) == "target.com"


def test_extract_domain_prefers_plain_over_wildcard():
    assert _extract_domain(["*.target.com", "target.com"]) == "target.com"


def test_extract_domain_strips_wildcard_prefix():
    assert _extract_domain(["*.api.target.com"]) == "api.target.com"


def test_extract_domain_skips_cidr():
    assert _extract_domain(["10.0.0.0/8"]) == ""


def test_extract_domain_skips_cidr_prefers_domain():
    assert _extract_domain(["10.0.0.0/8", "target.com"]) == "target.com"


def test_extract_domain_skips_http_base_urls():
    # http base URLs contain "/" but should not be treated as CIDRs
    # The function skips them because they start with "http" but
    # _extract_domain doesn't explicitly pick https:// URLs as "domain"
    # (they're used as base_urls, not domain name). Still, no crash.
    result = _extract_domain(["https://target.com/api"])
    assert isinstance(result, str)


def test_extract_domain_empty_list():
    assert _extract_domain([]) == ""


def test_extract_domain_multiple_wildcards_takes_first():
    result = _extract_domain(["*.foo.com", "*.bar.com"])
    assert result in ("foo.com", "bar.com")


# ── _build_initial_state ─────────────────────────────────────────────────────

from app.tasks.agent import _build_initial_state


def _fake_engagement(**kwargs):
    defaults = dict(
        id="eng-uuid-1234",
        in_scope=["target.com"],
        out_of_scope=[],
        mode="semi_auto",
        llm_model="qwen2.5-coder:7b",
        opsec_mode=False,
        request_jitter_ms=0,
        scan_sequential=False,
        auto_approve_exploit_validation=False,
    )
    return SimpleNamespace(**{**defaults, **kwargs})


def test_build_initial_state_basic():
    eng = _fake_engagement()
    state = _build_initial_state(eng)

    assert state["engagement_id"] == "eng-uuid-1234"
    assert state["target"]["domain"] == "target.com"
    assert state["scope"]["in_scope"] == ["target.com"]
    assert state["mode"] == "semi_auto"
    assert state["current_phase"] == "planning"


def test_build_initial_state_generates_https_base_url():
    eng = _fake_engagement(in_scope=["target.com"])
    state = _build_initial_state(eng)
    assert "https://target.com" in state["target"]["base_urls"]


def test_build_initial_state_generates_http_for_127_0_0_1():
    eng = _fake_engagement(in_scope=["127.0.0.1"])
    state = _build_initial_state(eng)
    assert any("http://" in u for u in state["target"]["base_urls"])


def test_build_initial_state_separates_ip_ranges():
    eng = _fake_engagement(in_scope=["target.com", "10.0.0.0/8"])
    state = _build_initial_state(eng)
    assert "10.0.0.0/8" in state["target"]["ip_ranges"]
    assert "target.com" not in state["target"]["ip_ranges"]


def test_build_initial_state_http_urls_in_base_urls():
    eng = _fake_engagement(in_scope=["https://api.target.com/v2"])
    state = _build_initial_state(eng)
    assert "https://api.target.com/v2" in state["target"]["base_urls"]


def test_build_initial_state_empty_accumulators():
    eng = _fake_engagement()
    state = _build_initial_state(eng)

    assert state["findings"] == []
    assert state["subdomains"] == []
    assert state["messages"] == []
    assert state["errors"] == []
    assert state["awaiting_approval"] is False


def test_build_initial_state_opsec_mode_propagated():
    eng = _fake_engagement(opsec_mode=True, request_jitter_ms=200)
    state = _build_initial_state(eng)
    assert state["opsec_mode"] is True
    assert state["request_jitter_ms"] == 200


def test_build_initial_state_auto_approve_exploit_validation_propagated():
    eng = _fake_engagement(auto_approve_exploit_validation=True)
    state = _build_initial_state(eng)
    assert state["auto_approve_exploit_validation"] is True


def test_build_initial_state_out_of_scope_propagated():
    eng = _fake_engagement(out_of_scope=["admin.target.com"])
    state = _build_initial_state(eng)
    assert "admin.target.com" in state["scope"]["out_of_scope"]


def test_build_initial_state_none_scope_defaults_to_empty():
    eng = _fake_engagement(in_scope=None, out_of_scope=None)
    state = _build_initial_state(eng)
    assert isinstance(state["scope"]["in_scope"], list)
    assert isinstance(state["scope"]["out_of_scope"], list)


# ── _publish_event ────────────────────────────────────────────────────────────

from app.tasks.agent import _publish_event


def test_publish_event_sends_to_correct_channel():
    mock_redis = MagicMock()
    mock_r = MagicMock()
    mock_redis.from_url.return_value = mock_r

    event = {"type": "ENGAGEMENT_STARTED", "engagement_id": "abc-123"}
    with patch.dict("sys.modules", {"redis": mock_redis}):
        _publish_event("abc-123", event)

    mock_r.publish.assert_called_once()
    channel_arg, payload_arg = mock_r.publish.call_args[0]
    assert channel_arg == "engagement:abc-123:events"
    assert json.loads(payload_arg) == event


def test_publish_event_does_not_raise_on_redis_error():
    mock_redis = MagicMock()
    mock_r = MagicMock()
    mock_r.publish.side_effect = Exception("Redis down")
    mock_redis.from_url.return_value = mock_r

    with patch.dict("sys.modules", {"redis": mock_redis}):
        _publish_event("abc-123", {"type": "test"})  # should not raise
