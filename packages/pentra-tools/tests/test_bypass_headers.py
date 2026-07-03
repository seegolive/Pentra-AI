"""Tests for bypass header injection module."""
from __future__ import annotations


def test_build_bypass_headers_returns_dict():
    from pentra_tools.http.bypass_headers import build_bypass_headers
    headers = build_bypass_headers(None)
    assert isinstance(headers, dict)


def test_build_bypass_headers_has_xff():
    from pentra_tools.http.bypass_headers import build_bypass_headers
    headers = build_bypass_headers(None)
    assert "X-Forwarded-For" in headers


def test_build_bypass_headers_has_x_real_ip():
    from pentra_tools.http.bypass_headers import build_bypass_headers
    headers = build_bypass_headers(None)
    assert "X-Real-IP" in headers


def test_build_bypass_headers_has_true_client_ip():
    from pentra_tools.http.bypass_headers import build_bypass_headers
    headers = build_bypass_headers(None)
    assert "True-Client-IP" in headers


def test_spoof_ip_override():
    from pentra_tools.http.bypass_headers import build_bypass_headers
    headers = build_bypass_headers(None, spoof_ip="1.2.3.4")
    assert headers["X-Forwarded-For"] == "1.2.3.4"
    assert headers["X-Real-IP"] == "1.2.3.4"
    assert headers["True-Client-IP"] == "1.2.3.4"


def test_cloudflare_adds_cf_connecting_ip():
    from pentra_tools.http.bypass_headers import build_bypass_headers
    headers = build_bypass_headers("cloudflare", spoof_ip="10.0.0.1")
    assert "CF-Connecting-IP" in headers
    assert headers["CF-Connecting-IP"] == "10.0.0.1"


def test_akamai_adds_akamai_origin_hop():
    from pentra_tools.http.bypass_headers import build_bypass_headers
    headers = build_bypass_headers("akamai")
    assert "Akamai-Origin-Hop" in headers


def test_unknown_waf_returns_base_headers():
    from pentra_tools.http.bypass_headers import build_bypass_headers
    headers = build_bypass_headers("some_unknown_waf")
    assert "X-Forwarded-For" in headers
    assert "X-Real-IP" in headers


def test_spoof_ips_list_has_10_or_more():
    from pentra_tools.http.bypass_headers import SPOOF_IPS
    assert len(SPOOF_IPS) >= 10


def test_random_spoof_ip_used_when_none_given():
    from pentra_tools.http.bypass_headers import build_bypass_headers, SPOOF_IPS
    headers = build_bypass_headers(None)
    # The X-Forwarded-For value must be one of the SPOOF_IPS
    assert headers["X-Forwarded-For"] in SPOOF_IPS
