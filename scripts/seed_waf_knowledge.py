#!/usr/bin/env python3
"""Seed WAF bypass technique records into the Pentra AI knowledge base.

Usage:
    python scripts/seed_waf_knowledge.py

Environment variables:
    PENTRA_API_URL     API base URL (default: http://localhost:8001)
    PENTRA_ADMIN_TOKEN JWT access token for admin authentication

The script injects WAF bypass records via POST /api/v1/knowledge/inject.
Already-existing records (same title) are silently skipped (409 is treated as OK).
"""
from __future__ import annotations
import os
import sys

try:
    import httpx
except ImportError:
    print("httpx not installed. Run: pip install httpx", file=sys.stderr)
    sys.exit(1)

API_URL = os.environ.get("PENTRA_API_URL", "http://localhost:8001").rstrip("/")
TOKEN = os.environ.get("PENTRA_ADMIN_TOKEN", "")
INJECT_URL = f"{API_URL}/api/v1/knowledge/inject"

WAF_BYPASS_RECORDS: list[dict] = [
    {
        "title": "Cloudflare WAF Bypass: Unicode Fullwidth Characters",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "Cloudflare WAF can be bypassed by replacing ASCII apostrophe (') with "
            "Unicode fullwidth apostrophe (＇, U+FF07) in SQL injection payloads. "
            "Similarly, fullwidth parentheses (（）) bypass function-call pattern detection. "
            "Example: SELECT＊FROM＇users＇ passes Cloudflare but executes on the DB."
        ),
        "key_insight": "Unicode lookalike characters bypass Cloudflare's ASCII-based pattern matching while remaining valid SQL on most databases.",
        "technique": "Unicode fullwidth character substitution in SQL injection and XSS payloads",
        "tech_stack": [],
        "tags": ["waf_bypass", "cloudflare", "sqli", "unicode"],
    },
    {
        "title": "Cloudflare WAF Bypass: Carriage Return Space Substitution",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "Replacing spaces in SQL payloads with carriage return (\\r, 0x0D) can bypass "
            "Cloudflare WAF space-based tokenization. Example: UNION\\rSELECT\\r1,2,3 "
            "is treated as whitespace by MySQL/PostgreSQL but Cloudflare's tokenizer misses it."
        ),
        "key_insight": "Cloudflare tokenizes on space (0x20) but \\r is valid SQL whitespace on MySQL/MSSQL.",
        "technique": "Carriage return (\\r) as whitespace substitute in SQL payloads",
        "tech_stack": ["mysql", "mssql"],
        "tags": ["waf_bypass", "cloudflare", "sqli", "whitespace"],
    },
    {
        "title": "Akamai WAF Bypass: Logical Operator Symbol Substitution",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "Akamai Kona WAF detects the keywords AND and OR but not their symbolic equivalents. "
            "Replacing AND with && and OR with || bypasses the keyword filter. "
            "Example: 1 && 1=1 instead of 1 AND 1=1."
        ),
        "key_insight": "Akamai's rule set focuses on SQL keyword strings, not semantic equivalents in operator form.",
        "technique": "Replace AND/OR keywords with &&/|| operators",
        "tech_stack": ["mysql", "postgresql"],
        "tags": ["waf_bypass", "akamai", "sqli", "operator"],
    },
    {
        "title": "Akamai WAF Bypass: Tab and Newline as Whitespace",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "Akamai Kona normalizes spaces but not tab (\\t, 0x09) or newline (\\n, 0x0A). "
            "UNION\\tSELECT\\t1 and UNION\\nSELECT\\n1 bypass space-based detection "
            "while being valid on all major databases."
        ),
        "key_insight": "Akamai's space normalization does not cover all SQL whitespace characters (\\t, \\n, \\r\\n).",
        "technique": "Tab (\\t) or newline (\\n) as whitespace in SQL payloads",
        "tech_stack": ["mysql", "postgresql", "mssql"],
        "tags": ["waf_bypass", "akamai", "sqli", "whitespace"],
    },
    {
        "title": "ModSecurity Bypass: HTTP Parameter Pollution",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "ModSecurity inspects the first occurrence of a parameter by default. "
            "Sending id=SAFE&id=MALICIOUS causes ModSecurity to inspect only 'SAFE' "
            "while the backend processes 'MALICIOUS' (depends on last-wins vs first-wins semantics). "
            "Works best against PHP (last-wins) and ASP.NET."
        ),
        "key_insight": "ModSecurity's default ARGS collection checks the combined value or first occurrence, enabling HPP splitting.",
        "technique": "HTTP Parameter Pollution — duplicate parameter with benign first value and malicious second",
        "tech_stack": ["php", "aspnet"],
        "tags": ["waf_bypass", "modsecurity", "hpp", "sqli"],
    },
    {
        "title": "ModSecurity Bypass: Null Byte Injection",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "A null byte (%00) terminates string inspection in some ModSecurity regex engines "
            "compiled against older PCRE versions. Inserting %00 mid-payload causes the WAF "
            "to see only the prefix: SELEC%00T is inspected as SELEC but executes as SELECT "
            "on MySQL when URL-decoded. Test carefully — modern ModSecurity versions patch this."
        ),
        "key_insight": "Older ModSecurity + PCRE combinations stop regex matching at null byte while the backend decodes and executes the full payload.",
        "technique": "Null byte (%00) mid-payload to truncate WAF regex inspection",
        "tech_stack": ["mysql"],
        "tags": ["waf_bypass", "modsecurity", "null_byte", "sqli"],
    },
    {
        "title": "Imperva Incapsula Bypass: Scientific Notation for Integer Literals",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "Imperva Incapsula's numeric pattern detection misses scientific notation. "
            "Replacing integer literals with scientific notation (e.g., 1 → 1e0, 0 → 0e0) "
            "bypasses numeric-based injection patterns. Example: 1=1e0 is TRUE in MySQL/PostgreSQL."
        ),
        "key_insight": "Imperva pattern matching works on fixed numeric patterns but not scientific notation equivalents.",
        "technique": "Scientific notation substitution for integer literals (1e0, 0e0)",
        "tech_stack": ["mysql", "postgresql"],
        "tags": ["waf_bypass", "imperva", "sqli", "numeric"],
    },
    {
        "title": "F5 BIG-IP ASM Bypass: Unicode Escape Sequences",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "F5 BIG-IP ASM normalizes standard URL encoding (%27 for apostrophe) but not "
            "Unicode escape sequences (%u0027). Encoding the apostrophe as %u0027 bypasses "
            "the WAF while IIS and some Python frameworks decode it correctly."
        ),
        "key_insight": "F5 BIG-IP ASM's Unicode normalization is incomplete — %uXXXX sequences bypass detection that catches %XX.",
        "technique": "%uXXXX Unicode escape encoding for special characters",
        "tech_stack": ["iis", "aspnet"],
        "tags": ["waf_bypass", "f5_bigip", "sqli", "unicode"],
    },
    {
        "title": "Generic WAF Bypass: X-Forwarded-For Header Spoofing",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "Many WAFs apply relaxed rules to requests from trusted IP ranges (127.0.0.1, "
            "10.0.0.0/8, 192.168.0.0/16). By adding X-Forwarded-For: 127.0.0.1 or "
            "X-Real-IP: 10.0.0.1 headers, the WAF may bypass rate limiting and some "
            "injection rules. Combine with X-Originating-IP, True-Client-IP for coverage. "
            "Effectiveness depends on WAF trusting the header — test with probe first."
        ),
        "key_insight": "WAFs that trust X-Forwarded-For without validation can be tricked into applying internal-IP rule profiles to attacker traffic.",
        "technique": "X-Forwarded-For header injection with private/loopback IP addresses",
        "tech_stack": [],
        "tags": ["waf_bypass", "generic", "header_injection", "ip_spoofing"],
    },
    {
        "title": "Generic WAF Bypass: Double URL Encoding",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "WAFs that decode URL encoding once before inspection miss double-encoded payloads. "
            "Single-encode ' → %27; double-encode %27 → %2527. The WAF sees %2527 (no match), "
            "the backend decodes twice and gets '. Works against older Apache/IIS + WAF combos "
            "that do not normalize twice before inspection."
        ),
        "key_insight": "Double URL encoding exploits single-pass URL decoding in WAF normalization, while the app server decodes twice.",
        "technique": "Double URL encoding (%2527 for apostrophe, %253C for <)",
        "tech_stack": ["apache", "iis"],
        "tags": ["waf_bypass", "generic", "url_encoding", "sqli", "xss"],
    },
    {
        "title": "AWS WAF Bypass: SQL Comment Block Fragmentation",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "AWS WAF Managed Rules match complete SQL injection signatures. Fragmenting tokens "
            "with MySQL inline comment blocks (/***/) defeats sequential token matching: "
            "UNION/**/SELECT/**/1 or SEL/**/ECT/**/1,2. The comment is stripped by MySQL "
            "but the WAF sees no 'UNION SELECT' substring."
        ),
        "key_insight": "AWS WAF string-matching rules work on substrings; comment injection splits the matched token across word boundaries.",
        "technique": "MySQL inline comment (/**/) injection to fragment SQL keywords",
        "tech_stack": ["mysql"],
        "tags": ["waf_bypass", "aws_waf", "sqli", "comment_injection"],
    },
    {
        "title": "Azure Front Door WAF Bypass: Case Variation",
        "vuln_class": "WAF Bypass",
        "severity": "info",
        "source": "waf_bypass_seed",
        "raw_text": (
            "Azure Front Door WAF (OWASP CRS based) uses case-insensitive matching for "
            "many rules, but mixed-case tricks can cause false negatives in custom rules "
            "and paranoia level 1. SeLeCt, uNiOn, aNd bypass custom case-sensitive rules. "
            "Always test — CRS paranoia level 2+ is case-insensitive."
        ),
        "key_insight": "Custom Azure WAF rules are often case-sensitive by default; alternating case breaks static keyword matching.",
        "technique": "Mixed-case SQL keywords (SeLeCt, uNiOn sElEcT)",
        "tech_stack": ["mssql", "mysql"],
        "tags": ["waf_bypass", "azure_frontdoor", "sqli", "case_variation"],
    },
]


def main() -> int:
    if not TOKEN:
        print("ERROR: PENTRA_ADMIN_TOKEN is not set.", file=sys.stderr)
        print("Get a token via: POST /api/v1/auth/login", file=sys.stderr)
        return 1

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
    }

    injected = 0
    skipped = 0
    failed = 0

    with httpx.Client(base_url=API_URL, headers=headers, timeout=30.0) as client:
        for record in WAF_BYPASS_RECORDS:
            resp = client.post("/api/v1/knowledge/inject", json=record)
            if resp.status_code in (200, 201):
                print(f"  [OK]      {record['title'][:70]}")
                injected += 1
            elif resp.status_code == 409:
                print(f"  [SKIP]    {record['title'][:70]} (already exists)")
                skipped += 1
            else:
                print(f"  [FAIL]    {record['title'][:70]} → HTTP {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
                failed += 1

    print(f"\nDone: {injected} injected, {skipped} skipped, {failed} failed.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
