"""CVSS v3.1 auto-calculator based on vuln_class and context.

Produces a deterministic (score, vector_string) pair for common web
vulnerability classes found in bug-bounty and pentest engagements.

Lookup key: (normalised_vuln_class, auth_required, network_accessible)

Usage::

    from pentra_shared.utils.cvss import calculate_cvss, normalise_vuln_class

    score, vector = calculate_cvss("SQL_INJECTION", auth_required=False)
    # → (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    score, vector = calculate_cvss("xss", auth_required=False)
    # → (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
"""

from __future__ import annotations

import re

# ── CVSS v3.1 base score table ────────────────────────────────────────────────
# Key:   (vuln_class: str, auth_required: bool, network_accessible: bool)
# Value: (base_score: float, vector_string: str)
#
# All vectors use Network attack vector (AV:N) because we only run against
# web applications.  auth_required maps to PR:L (Low privilege) when True,
# PR:N (None) when False.
#
# Sources: NVD CVSS calculator, OWASP Testing Guide, real H1/Bugcrowd reports.

CVSS_BASE_SCORES: dict[tuple[str, bool, bool], tuple[float, str]] = {
    # ── SQL Injection ────────────────────────────────────────────────────────
    ("SQL_INJECTION", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("SQL_INJECTION", True,  True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),

    # ── Cross-Site Scripting (Reflected / Stored) ───────────────────────────
    # Reflected (UI:R required — victim must click)
    ("XSS", False, True): (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("XSS", True,  True): (5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
    # Stored XSS scores slightly higher (no additional user interaction required beyond visit)
    ("STORED_XSS", False, True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"),
    ("STORED_XSS", True,  True): (8.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"),

    # ── Insecure Direct Object Reference ────────────────────────────────────
    ("IDOR", False, True): (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("IDOR", True,  True): (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),

    # ── Server-Side Request Forgery ──────────────────────────────────────────
    ("SSRF", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("SSRF", True,  True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),

    # ── Path / Directory Traversal ───────────────────────────────────────────
    ("PATH_TRAVERSAL", False, True): (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("PATH_TRAVERSAL", True,  True): (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),

    # ── Command Injection / Remote Code Execution ────────────────────────────
    ("COMMAND_INJECTION", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("COMMAND_INJECTION", True,  True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    ("RCE", False, True): (10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    ("RCE", True,  True): (9.9,  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"),

    # ── Server-Side Template Injection ───────────────────────────────────────
    ("SSTI", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("SSTI", True,  True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),

    # ── Open Redirect ────────────────────────────────────────────────────────
    ("OPEN_REDIRECT", False, True): (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("OPEN_REDIRECT", True,  True): (5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),

    # ── XML External Entity ──────────────────────────────────────────────────
    ("XXE", False, True): (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("XXE", True,  True): (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),

    # ── Cross-Site Request Forgery ────────────────────────────────────────────
    ("CSRF", False, True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),
    ("CSRF", True,  True): (8.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H"),

    # ── Broken Authentication / Account Takeover ─────────────────────────────
    ("BROKEN_AUTH", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("BROKEN_AUTH", True,  True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    ("ACCOUNT_TAKEOVER", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("ACCOUNT_TAKEOVER", True,  True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),

    # ── Mass Assignment ───────────────────────────────────────────────────────
    ("MASS_ASSIGNMENT", False, True): (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("MASS_ASSIGNMENT", True,  True): (7.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),

    # ── Insecure Deserialization ──────────────────────────────────────────────
    ("INSECURE_DESERIALIZATION", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("INSECURE_DESERIALIZATION", True,  True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),

    # ── Security Misconfiguration / Information Disclosure ───────────────────
    ("INFORMATION_DISCLOSURE", False, True): (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("INFORMATION_DISCLOSURE", True,  True): (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    ("MISCONFIGURATION", False, True):       (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),

    # ── Business Logic ────────────────────────────────────────────────────────
    ("BUSINESS_LOGIC", False, True): (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("BUSINESS_LOGIC", True,  True): (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),

    # ── Race Condition ────────────────────────────────────────────────────────
    ("RACE_CONDITION", False, True): (8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("RACE_CONDITION", True,  True): (7.5, "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"),

    # ── OAuth / JWT misconfig ─────────────────────────────────────────────────
    ("OAUTH_MISCONFIGURATION", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("JWT_VULNERABILITY",      False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),

    # ── Host Header Injection ─────────────────────────────────────────────────
    ("HOST_HEADER_INJECTION", False, True): (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
}

# Default when no specific entry is found (medium / generic web vuln)
_DEFAULT_SCORE = 5.0
_DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"

# ── Normalisation map — aliases → canonical key ──────────────────────────────
_ALIASES: dict[str, str] = {
    # SQL Injection variants
    "sqli": "SQL_INJECTION",
    "sql injection": "SQL_INJECTION",
    "sql_injection": "SQL_INJECTION",
    "blind sqli": "SQL_INJECTION",
    "blind sql injection": "SQL_INJECTION",
    "error-based sqli": "SQL_INJECTION",
    "time-based sqli": "SQL_INJECTION",
    "second-order sqli": "SQL_INJECTION",

    # XSS variants
    "xss": "XSS",
    "cross-site scripting": "XSS",
    "cross_site_scripting": "XSS",
    "reflected xss": "XSS",
    "reflected_xss": "XSS",
    "stored xss": "STORED_XSS",
    "stored_xss": "STORED_XSS",
    "dom xss": "XSS",
    "dom-based xss": "XSS",

    # SSRF
    "ssrf": "SSRF",
    "server-side request forgery": "SSRF",

    # Path traversal
    "path traversal": "PATH_TRAVERSAL",
    "directory traversal": "PATH_TRAVERSAL",
    "lfi": "PATH_TRAVERSAL",
    "local file inclusion": "PATH_TRAVERSAL",
    "rfi": "PATH_TRAVERSAL",

    # Command/code injection
    "rce": "RCE",
    "remote code execution": "RCE",
    "command injection": "COMMAND_INJECTION",
    "os command injection": "COMMAND_INJECTION",

    # SSTI
    "ssti": "SSTI",
    "server-side template injection": "SSTI",
    "template injection": "SSTI",

    # Open redirect
    "open redirect": "OPEN_REDIRECT",
    "url redirect": "OPEN_REDIRECT",

    # IDOR
    "idor": "IDOR",
    "insecure direct object reference": "IDOR",

    # CSRF
    "csrf": "CSRF",
    "cross-site request forgery": "CSRF",

    # XXE
    "xxe": "XXE",
    "xml external entity": "XXE",

    # Broken auth
    "broken authentication": "BROKEN_AUTH",
    "broken auth": "BROKEN_AUTH",
    "account takeover": "ACCOUNT_TAKEOVER",
    "ato": "ACCOUNT_TAKEOVER",

    # Mass assignment
    "mass assignment": "MASS_ASSIGNMENT",
    "parameter pollution": "MASS_ASSIGNMENT",

    # Info disclosure
    "information disclosure": "INFORMATION_DISCLOSURE",
    "info disclosure": "INFORMATION_DISCLOSURE",
    "sensitive data exposure": "INFORMATION_DISCLOSURE",

    # Misc
    "insecure deserialization": "INSECURE_DESERIALIZATION",
    "deserialization": "INSECURE_DESERIALIZATION",
    "race condition": "RACE_CONDITION",
    "business logic": "BUSINESS_LOGIC",
    "oauth misconfiguration": "OAUTH_MISCONFIGURATION",
    "jwt": "JWT_VULNERABILITY",
    "jwt vulnerability": "JWT_VULNERABILITY",
    "host header injection": "HOST_HEADER_INJECTION",
    "misconfiguration": "MISCONFIGURATION",
    "security misconfiguration": "MISCONFIGURATION",
}


def normalise_vuln_class(vuln_class: str) -> str:
    """Return the canonical ALL_CAPS key for a vuln class name.

    Handles spaces, dashes, mixed case, and common abbreviations.
    Returns the input upper-cased if no alias matches (so the lookup
    will fall through to the default score).

    Examples::

        normalise_vuln_class("SQL Injection")  → "SQL_INJECTION"
        normalise_vuln_class("xss")            → "XSS"
        normalise_vuln_class("reflected xss")  → "XSS"
        normalise_vuln_class("MyCustomVuln")   → "MYCUSTOMVULN"  # default fallback
    """
    if not vuln_class:
        return "UNKNOWN"
    cleaned = re.sub(r"[\s\-]+", " ", vuln_class.strip()).lower()
    canonical = _ALIASES.get(cleaned)
    if canonical:
        return canonical
    # Last resort: uppercase + underscores
    return re.sub(r"\s+", "_", cleaned).upper()


def calculate_cvss(
    vuln_class: str,
    auth_required: bool = False,
    network_accessible: bool = True,
) -> tuple[float, str]:
    """Return (base_score, vector_string) for a given vulnerability context.

    Args:
        vuln_class: Raw vuln class string from agent (e.g. "SQL Injection",
            "xss", "SSRF", "SQL_INJECTION").  Normalised internally.
        auth_required: True if the endpoint requires authentication
            (maps to PR:L in CVSS).  Defaults to False (PR:N = worst case).
        network_accessible: Always True for web apps — reserved for future
            local/adjacent attack vectors.

    Returns:
        (score, vector) — e.g. (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    """
    key = (normalise_vuln_class(vuln_class), auth_required, network_accessible)
    return CVSS_BASE_SCORES.get(key, (_DEFAULT_SCORE, _DEFAULT_VECTOR))
