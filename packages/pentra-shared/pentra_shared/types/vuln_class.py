from enum import Enum


class VulnClass(str, Enum):
    """Vulnerability class taxonomy for Pentra AI knowledge engine and findings.

    Categories:
    - Access Control: IDOR, BOLA, BFLA, privilege escalation
    - Injection: SQLi, XSS variants, XXE, SSTI, CMDi
    - Auth: authentication and session flaws
    - Server-side: SSRF, path traversal, RCE, deserialization
    - Business Logic: race conditions, mass assignment, workflow bypass
    - Info Disclosure: key leaks, PII, debug info
    - Infrastructure: subdomain takeover, cache poisoning, cloud misconfig
    - GraphQL: introspection, query abuse
    - Cryptography: weak algorithms, oracle attacks
    """

    # ── Access Control ──────────────────────────────────────────────────
    IDOR = "idor"
    BOLA = "bola"
    BFLA = "bfla"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # ── Injection ────────────────────────────────────────────────────────
    SQLI = "sqli"
    XSS_STORED = "xss_stored"
    XSS_REFLECTED = "xss_reflected"
    XSS_DOM = "xss_dom"
    MXSS = "mxss"
    XXE = "xxe"
    SSTI = "ssti"
    CMDI = "cmdi"

    # ── Auth ─────────────────────────────────────────────────────────────
    AUTH_BYPASS = "auth_bypass"
    SESSION = "session"
    OAUTH_MISCONFIG = "oauth_misconfig"
    JWT_ISSUES = "jwt_issues"

    # ── Server-side ──────────────────────────────────────────────────────
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    RCE = "rce"
    DESERIALIZATION = "deserialization"

    # ── Business Logic ───────────────────────────────────────────────────
    RACE_CONDITION = "race_condition"
    MASS_ASSIGNMENT = "mass_assignment"
    PARAM_POLLUTION = "param_pollution"
    WORKFLOW_BYPASS = "workflow_bypass"

    # ── Info Disclosure ──────────────────────────────────────────────────
    API_KEY_LEAK = "api_key_leak"
    PII_EXPOSURE = "pii_exposure"
    DEBUG_INFO = "debug_info"
    SOURCE_CODE = "source_code"

    # ── Infrastructure ───────────────────────────────────────────────────
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    CACHE_POISONING = "cache_poisoning"
    CLOUD_MISCONFIG = "cloud_misconfig"
    CORS = "cors"

    # ── GraphQL ──────────────────────────────────────────────────────────
    INTROSPECTION = "introspection"
    QUERY_DEPTH = "query_depth"
    BATCH_ABUSE = "batch_abuse"
    FIELD_SUGGESTION = "field_suggestion"

    # ── Availability ─────────────────────────────────────────────────────
    DOS = "dos"
    OPEN_REDIRECT = "open_redirect"

    # ── Memory Safety ────────────────────────────────────────────────────
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"

    # ── Cryptography ─────────────────────────────────────────────────────
    WEAK_ALGO = "weak_algo"
    PADDING_ORACLE = "padding_oracle"
    TIMING_ATTACK = "timing_attack"

    # ── Catch-all ─────────────────────────────────────────────────────────
    OTHER = "other"


# Parent category mapping — useful for grouping/filtering
VULN_CLASS_CATEGORIES: dict[str, list[VulnClass]] = {
    "ACCESS_CONTROL": [
        VulnClass.IDOR,
        VulnClass.BOLA,
        VulnClass.BFLA,
        VulnClass.PRIVILEGE_ESCALATION,
    ],
    "INJECTION": [
        VulnClass.SQLI,
        VulnClass.XSS_STORED,
        VulnClass.XSS_REFLECTED,
        VulnClass.XSS_DOM,
        VulnClass.MXSS,
        VulnClass.XXE,
        VulnClass.SSTI,
        VulnClass.CMDI,
    ],
    "AUTH": [
        VulnClass.AUTH_BYPASS,
        VulnClass.SESSION,
        VulnClass.OAUTH_MISCONFIG,
        VulnClass.JWT_ISSUES,
    ],
    "SERVER_SIDE": [
        VulnClass.SSRF,
        VulnClass.PATH_TRAVERSAL,
        VulnClass.RCE,
        VulnClass.DESERIALIZATION,
    ],
    "BUSINESS_LOGIC": [
        VulnClass.RACE_CONDITION,
        VulnClass.MASS_ASSIGNMENT,
        VulnClass.PARAM_POLLUTION,
        VulnClass.WORKFLOW_BYPASS,
    ],
    "INFO_DISCLOSURE": [
        VulnClass.API_KEY_LEAK,
        VulnClass.PII_EXPOSURE,
        VulnClass.DEBUG_INFO,
        VulnClass.SOURCE_CODE,
    ],
    "INFRASTRUCTURE": [
        VulnClass.SUBDOMAIN_TAKEOVER,
        VulnClass.CACHE_POISONING,
        VulnClass.CLOUD_MISCONFIG,
        VulnClass.CORS,
    ],
    "GRAPHQL": [
        VulnClass.INTROSPECTION,
        VulnClass.QUERY_DEPTH,
        VulnClass.BATCH_ABUSE,
        VulnClass.FIELD_SUGGESTION,
    ],
    "CRYPTOGRAPHY": [
        VulnClass.WEAK_ALGO,
        VulnClass.PADDING_ORACLE,
        VulnClass.TIMING_ATTACK,
    ],
    "AVAILABILITY": [
        VulnClass.DOS,
        VulnClass.OPEN_REDIRECT,
    ],
    "MEMORY_SAFETY": [
        VulnClass.BUFFER_OVERFLOW,
        VulnClass.USE_AFTER_FREE,
        VulnClass.INTEGER_OVERFLOW,
    ],
}


def get_category(vuln_class: VulnClass) -> str | None:
    """Return the parent category name for a given VulnClass."""
    for category, members in VULN_CLASS_CATEGORIES.items():
        if vuln_class in members:
            return category
    return None
