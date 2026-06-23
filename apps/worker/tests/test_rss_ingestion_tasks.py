"""Tests for worker/app/tasks/rss_ingestion.py helpers.

_guess_vuln_class and _stable_id are pure Python (no network, no DB).
"""

from __future__ import annotations

from app.tasks.rss_ingestion import _guess_vuln_class, _stable_id
from pentra_shared.types import VulnClass


# ── _guess_vuln_class ─────────────────────────────────────────────────────────

def test_guess_vuln_class_xss():
    assert _guess_vuln_class("XSS vulnerability in search field") == VulnClass.XSS_STORED


def test_guess_vuln_class_cross_site_scripting():
    assert _guess_vuln_class("Cross-site scripting via reflected input") == VulnClass.XSS_STORED


def test_guess_vuln_class_sqli():
    assert _guess_vuln_class("SQL injection via login form") == VulnClass.SQLI


def test_guess_vuln_class_sqli_abbreviation():
    assert _guess_vuln_class("SQLi found in order parameter") == VulnClass.SQLI


def test_guess_vuln_class_ssrf():
    assert _guess_vuln_class("Server-Side Request Forgery in webhook URL") == VulnClass.SSRF


def test_guess_vuln_class_ssrf_abbreviation():
    assert _guess_vuln_class("SSRF via import endpoint") == VulnClass.SSRF


def test_guess_vuln_class_idor():
    assert _guess_vuln_class("IDOR allows accessing other users' profiles") == VulnClass.IDOR


def test_guess_vuln_class_insecure_direct_object():
    assert _guess_vuln_class("Insecure Direct Object Reference in API") == VulnClass.IDOR


def test_guess_vuln_class_rce():
    assert _guess_vuln_class("RCE via deserialized Java object") == VulnClass.RCE


def test_guess_vuln_class_remote_code_execution():
    assert _guess_vuln_class("Remote code execution in file processor") == VulnClass.RCE


def test_guess_vuln_class_cmdi():
    assert _guess_vuln_class("Command injection in ping utility") == VulnClass.RCE


def test_guess_vuln_class_path_traversal():
    assert _guess_vuln_class("Path traversal allows reading /etc/passwd") == VulnClass.PATH_TRAVERSAL


def test_guess_vuln_class_lfi():
    assert _guess_vuln_class("LFI via include parameter") == VulnClass.PATH_TRAVERSAL


def test_guess_vuln_class_open_redirect():
    assert _guess_vuln_class("Open redirect to phishing site via next parameter") == VulnClass.OPEN_REDIRECT


def test_guess_vuln_class_xxe():
    assert _guess_vuln_class("XXE via SVG file upload") == VulnClass.XXE


def test_guess_vuln_class_xml_external_entity():
    assert _guess_vuln_class("XML external entity injection in SOAP parser") == VulnClass.XXE


def test_guess_vuln_class_deserialization():
    assert _guess_vuln_class("Insecure deserialization via pickle") == VulnClass.DESERIALIZATION


def test_guess_vuln_class_unknown_returns_other():
    assert _guess_vuln_class("Generic security misconfiguration") == VulnClass.OTHER


def test_guess_vuln_class_empty_string():
    assert _guess_vuln_class("") == VulnClass.OTHER


def test_guess_vuln_class_case_insensitive():
    assert _guess_vuln_class("SQL INJECTION IN USER TABLE") == VulnClass.SQLI
    assert _guess_vuln_class("xss via reflected parameter") == VulnClass.XSS_STORED


def test_guess_vuln_class_csrf():
    result = _guess_vuln_class("CSRF allows state-changing requests")
    assert result == VulnClass.AUTH_BYPASS


# ── _stable_id ────────────────────────────────────────────────────────────────

def test_stable_id_returns_32_hex_chars():
    result = _stable_id("portswigger", "https://portswigger.net/research/sqli")
    assert len(result) == 32
    assert all(c in "0123456789abcdef" for c in result)


def test_stable_id_deterministic():
    a = _stable_id("hackernews_security", "https://hn.com/item?id=123")
    b = _stable_id("hackernews_security", "https://hn.com/item?id=123")
    assert a == b


def test_stable_id_different_sources_differ():
    a = _stable_id("source_a", "https://example.com/article")
    b = _stable_id("source_b", "https://example.com/article")
    assert a != b


def test_stable_id_different_urls_differ():
    a = _stable_id("portswigger", "https://portswigger.net/research/sqli")
    b = _stable_id("portswigger", "https://portswigger.net/research/xss")
    assert a != b
