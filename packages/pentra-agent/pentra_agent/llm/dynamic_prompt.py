"""
Dynamic prompt generator — system prompt yang berubah sesuai target context.
Terinspirasi dari ARTEMIS dynamic prompt generation.
Bukan static "You are a pentester" — berubah berdasarkan tech stack dan findings.
"""

from __future__ import annotations

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

_DEVELOPER_PSYCHOLOGY = """
## Developer Psychology — Where Bugs Hide
1. v2 API endpoints are often added quickly, missing auth checks that v1 has
2. Integer ID parameters assume users won't guess other IDs (IDOR)
3. Admin functionality at /admin/, /api/admin/ often has weaker auth
4. New features copy old code — check for deprecated auth patterns
5. Error messages in production often reveal stack traces or config
6. File serving endpoints (/view?file=, /load?path=) often lack path validation"""


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
    sections: list[str] = []

    # Base role
    sections.append(
        "You are a senior penetration tester conducting web application security testing. "
        "Think step by step. Prioritize findings by real, demonstrable impact."
    )

    # Tech-specific context
    tech_lower_str = " ".join(t.lower() for t in tech_stack)
    tech_sections: list[str] = []
    for tech_key, context in TECH_CONTEXTS.items():
        if tech_key in tech_lower_str:
            tech_sections.append(context)

    if tech_sections:
        sections.append("\n## Target Tech Stack Context\n" + "\n\n".join(tech_sections))
    else:
        sections.append("\n## Target\nGeneric web application. Test common vuln classes.")

    # Prior findings context
    if prior_findings:
        high_impact = [
            f for f in prior_findings
            if f.get("severity") in ("critical", "high")
        ]
        if high_impact:
            finding_lines = "\n".join(
                f"- [{f.get('severity', '').upper()}] {f.get('title', '')} at {f.get('target_url', '')}"
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

    # Learning context from KB / past engagements
    if engagement_learnings:
        effective = [
            lr for lr in engagement_learnings
            if lr.get("effective_tools") or lr.get("high_value_endpoints")
        ]
        if effective:
            learning_lines: list[str] = []
            for lr in effective[:2]:
                if lr.get("high_value_endpoints"):
                    eps = [ep.get("pattern", "") for ep in lr["high_value_endpoints"][:3]]
                    learning_lines.append(f"High-value endpoint patterns: {', '.join(eps)}")
            if learning_lines:
                sections.append(
                    "\n## Historical Learning (from similar past engagements)\n"
                    + "\n".join(learning_lines)
                )

    # Developer psychology heuristics
    sections.append(_DEVELOPER_PSYCHOLOGY)

    return "\n".join(sections)
