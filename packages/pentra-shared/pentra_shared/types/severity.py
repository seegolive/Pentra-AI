from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity levels aligned with CVSS and HackerOne conventions."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self] < _SEVERITY_ORDER[other]

    def __le__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self] <= _SEVERITY_ORDER[other]

    def __gt__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self] > _SEVERITY_ORDER[other]

    def __ge__(self, other: "Severity") -> bool:
        return _SEVERITY_ORDER[self] >= _SEVERITY_ORDER[other]


# Higher value = higher severity — used for ordering/filtering
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Approximate CVSS score ranges per severity band
SEVERITY_CVSS_RANGES: dict[Severity, tuple[float, float]] = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH: (7.0, 8.9),
    Severity.MEDIUM: (4.0, 6.9),
    Severity.LOW: (0.1, 3.9),
    Severity.INFO: (0.0, 0.0),
}


def severity_from_cvss(score: float) -> Severity:
    """Derive a Severity from a CVSS score."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


# Canonical mapping — all known raw variants → lowercase standard.
# Covers: uppercase/mixed-case LLM output, nuclei suffixes, Burp confidence
# qualifiers, CVSS label variants, and None/empty fallback.
_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "information": "info",
    "informational": "info",
    "none": "info",
    "unknown": "medium",
    # Nuclei / scanner suffix variants
    "critical_severity": "critical",
    "high_severity": "high",
    "medium_severity": "medium",
    "low_severity": "low",
    "info_severity": "info",
    # Burp confidence-qualified variants
    "high_certain": "high",
    "high_firm": "high",
    "medium_certain": "medium",
    "medium_firm": "medium",
    "low_certain": "low",
    "low_firm": "low",
    # CVSS-level numeric descriptors sometimes emitted by LLMs
    "critical (9.0-10.0)": "critical",
    "high (7.0-8.9)": "high",
    "medium (4.0-6.9)": "medium",
    "low (0.1-3.9)": "low",
}


def normalize_severity(raw: "str | None", *, default: str = "medium") -> str:
    """Normalize any severity string variant to lowercase standard.

    Handles uppercase, mixed-case, vendor-specific suffixes (nuclei, Burp),
    and None/empty values.

    Args:
        raw:     Raw severity string from LLM, scanner, or user input.
        default: Fallback value for unrecognized inputs. Defaults to 'medium'.

    Returns:
        One of: 'critical', 'high', 'medium', 'low', 'info'.
    """
    if not raw:
        return default
    # Direct lookup (covers exact lowercase and most variants)
    normalized = _SEVERITY_MAP.get(raw)
    if normalized:
        return normalized
    # Case-fold lookup for uppercase/mixed-case LLM output
    lower = raw.lower().strip()
    normalized = _SEVERITY_MAP.get(lower)
    if normalized:
        return normalized
    # Strip common vendor suffixes and retry
    stripped = lower.replace("_severity", "").replace("severity_", "").strip()
    return _SEVERITY_MAP.get(stripped, default)
