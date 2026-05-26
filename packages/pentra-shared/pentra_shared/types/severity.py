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
