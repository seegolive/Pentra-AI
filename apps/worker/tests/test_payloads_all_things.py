"""Tests for worker/app/tasks/payloads_all_things.py helpers.

_match_vuln_class, _stable_id, _parse_sections, _extract_payloads are
all pure Python — no network, no DB.
"""

from __future__ import annotations

from app.tasks.payloads_all_things import (
    _extract_payloads,
    _match_vuln_class,
    _parse_sections,
    _stable_id,
)
from pentra_shared.types import VulnClass


# ── _match_vuln_class ─────────────────────────────────────────────────────────

def test_match_vuln_class_exact_xss():
    assert _match_vuln_class("XSS Injection") == VulnClass.XSS_STORED


def test_match_vuln_class_exact_sqli():
    assert _match_vuln_class("SQL Injection") == VulnClass.SQLI


def test_match_vuln_class_exact_ssrf():
    assert _match_vuln_class("SSRF injection") == VulnClass.SSRF


def test_match_vuln_class_exact_idor():
    assert _match_vuln_class("IDOR") == VulnClass.IDOR


def test_match_vuln_class_exact_csrf():
    assert _match_vuln_class("CSRF Injection") == VulnClass.AUTH_BYPASS


def test_match_vuln_class_exact_xxe():
    assert _match_vuln_class("XXE Injection") == VulnClass.XXE


def test_match_vuln_class_exact_ssti():
    assert _match_vuln_class("Server Side Template Injection") == VulnClass.SSTI


def test_match_vuln_class_exact_deserialization():
    assert _match_vuln_class("Insecure Deserialization") == VulnClass.DESERIALIZATION


def test_match_vuln_class_exact_rce():
    assert _match_vuln_class("Remote Code Execution") == VulnClass.RCE


def test_match_vuln_class_exact_path_traversal():
    assert _match_vuln_class("Path Traversal") == VulnClass.PATH_TRAVERSAL


def test_match_vuln_class_fuzzy_matches_sqli():
    result = _match_vuln_class("Advanced SQL Injection Techniques")
    assert result == VulnClass.SQLI


def test_match_vuln_class_unknown_returns_other():
    assert _match_vuln_class("Totally Unknown Category") == VulnClass.OTHER


# ── _stable_id ────────────────────────────────────────────────────────────────

def test_stable_id_returns_32_hex():
    result = _stable_id("SQL Injection", "Basic Auth Bypass")
    assert len(result) == 32
    assert all(c in "0123456789abcdef" for c in result)


def test_stable_id_deterministic():
    a = _stable_id("XSS Injection", "Stored XSS")
    b = _stable_id("XSS Injection", "Stored XSS")
    assert a == b


def test_stable_id_different_folder_differs():
    a = _stable_id("XSS Injection", "Payload List")
    b = _stable_id("SQL Injection", "Payload List")
    assert a != b


def test_stable_id_different_section_differs():
    a = _stable_id("XSS Injection", "Stored XSS")
    b = _stable_id("XSS Injection", "DOM XSS")
    assert a != b


# ── _parse_sections ───────────────────────────────────────────────────────────

_SAMPLE_MD = """
## Stored XSS

Some introductory text about stored XSS.

```html
<script>alert(1)</script>
```

## Reflected XSS

Quick payload:

- `"><script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`

### DOM XSS

Subheading content.
```javascript
location.hash = "#<img src=x onerror=alert(1)>"
```
"""


def test_parse_sections_returns_list():
    sections = _parse_sections(_SAMPLE_MD)
    assert isinstance(sections, list)
    assert len(sections) >= 2


def test_parse_sections_captures_h2_headings():
    sections = _parse_sections(_SAMPLE_MD)
    headings = [s["heading"] for s in sections]
    assert "Stored XSS" in headings
    assert "Reflected XSS" in headings


def test_parse_sections_captures_h3_headings():
    sections = _parse_sections(_SAMPLE_MD)
    headings = [s["heading"] for s in sections]
    assert "DOM XSS" in headings


def test_parse_sections_body_is_non_empty():
    sections = _parse_sections(_SAMPLE_MD)
    for s in sections:
        assert s["body"]  # no empty bodies


def test_parse_sections_empty_markdown():
    assert _parse_sections("") == []


def test_parse_sections_no_headings():
    assert _parse_sections("Just some plain text without headings.") == []


def test_parse_sections_heading_without_body_excluded():
    md = "## Empty Section\n\n## Has Body\n\nsome content here"
    sections = _parse_sections(md)
    headings = [s["heading"] for s in sections]
    assert "Has Body" in headings
    # "Empty Section" has no body — should be excluded
    assert "Empty Section" not in headings


# ── _extract_payloads ─────────────────────────────────────────────────────────

def test_extract_payloads_from_code_block():
    body = "```\n' OR 1=1--\n' OR 'a'='a\n```"
    payloads = _extract_payloads(body)
    assert "' OR 1=1--" in payloads
    assert "' OR 'a'='a" in payloads


def test_extract_payloads_from_bullet_list():
    body = "- `<script>alert(1)</script>`\n- `<img src=x onerror=alert(1)>`"
    payloads = _extract_payloads(body)
    assert len(payloads) >= 2
    assert any("alert(1)" in p for p in payloads)


def test_extract_payloads_code_block_language_hint_ignored():
    body = "```bash\necho hello\ncat /etc/passwd\n```"
    payloads = _extract_payloads(body)
    assert "echo hello" in payloads or "cat /etc/passwd" in payloads


def test_extract_payloads_caps_at_50():
    lines = "\n".join(f"- payload{i}" for i in range(100))
    body = lines
    payloads = _extract_payloads(body)
    assert len(payloads) <= 50


def test_extract_payloads_empty_body():
    assert _extract_payloads("") == []


def test_extract_payloads_plain_text_no_code():
    body = "This section has no payloads, just description text."
    payloads = _extract_payloads(body)
    assert payloads == []


def test_extract_payloads_skips_short_bullet_items():
    body = "- `x`\n- valid payload here"
    payloads = _extract_payloads(body)
    # items shorter than 4 chars should be skipped
    assert all(len(p) > 3 for p in payloads)


def test_extract_payloads_skips_markdown_links_in_bullets():
    body = "- [OWASP link](https://owasp.org)\n- actual payload value"
    payloads = _extract_payloads(body)
    # Bullet items starting with "[" should be skipped
    assert not any(p.startswith("[") for p in payloads)
