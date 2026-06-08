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
