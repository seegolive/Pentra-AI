"""
WAFProfiler — detect dan profile WAF pada target URL.
Terinspirasi dari Pentest Agent Suite waf-profiler + reNgine waf_detection.
"""

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
    "cloudflare":      ["cf-ray", "__cfduid", "cloudflare"],
    "akamai":          ["akamai", "x-check-cacheable", "x-cache-remote"],
    "imperva":         ["x-iinfo", "incap_ses", "visid_incap"],
    "f5_bigip":        ["bigipserver", "ts"],
    "barracuda":       ["bnsec", "barracuda_"],
    "sucuri":          ["x-sucuri", "sucuri-cache"],
    "modsecurity":     ["mod_security", "modsecurity", "noyb"],
    "aws_waf":         ["x-amzn-requestid", "awswaf"],
    "azure_frontdoor": ["x-azure-ref", "x-ms-ref"],
    "fortiweb":        ["fortiwafsid", "cookiesession"],
}

BYPASS_STRATEGIES: dict[str, list[str]] = {
    "cloudflare":      ["unicode_bypass", "case_variation", "comment_injection", "chunked_encoding"],
    "modsecurity":     ["http_param_pollution", "null_byte", "comment_bypass", "url_double_encode"],
    "akamai":          ["case_variation", "unicode_bypass", "header_injection"],
    "imperva":         ["url_encoding", "html_entity", "case_variation"],
    "generic":         ["url_double_encode", "html_entity_encode", "hex_encode", "case_variation"],
}


async def profile_waf(
    url: str,
    timeout: float = 8.0,
) -> WAFProfile:
    """
    Detect dan profile WAF pada target URL.
    Kirim 3 probe requests (normal + xss + sqli) dan analisis responses.
    """
    try:
        from pentra_tools.http.user_agent_rotator import get_random_ua as _get_ua
        _probe_ua = _get_ua()
    except Exception:
        _probe_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": _probe_ua},
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
        url, detected_waf or "none", is_blocked, bypass[:2],
    )

    return profile
