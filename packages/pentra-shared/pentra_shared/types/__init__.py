"""Shared type exports for Pentra AI.

Import everything from this package rather than from sub-modules to keep
consumer code stable as the internal structure evolves.

Example::

    from pentra_shared.types import (
        VulnClass,
        Severity,
        KnowledgeRecord,
        Finding,
        FindingCreate,
        Engagement,
        EngagementCreate,
        Scope,
    )
"""

from pentra_shared.types.engagement import (
    Engagement,
    EngagementCreate,
    EngagementMode,
    EngagementResponse,
    EngagementStatus,
    EngagementUpdate,
    Scope,
)
from pentra_shared.types.finding import (
    Finding,
    FindingCreate,
    FindingStatus,
    FindingUpdate,
)
from pentra_shared.types.knowledge import (
    KnowledgeRecord,
    KnowledgeSource,
    PlatformType,
)
from pentra_shared.types.severity import (
    Severity,
    SEVERITY_CVSS_RANGES,
    normalize_severity,
    severity_from_cvss,
)
from pentra_shared.types.vuln_class import (
    VulnClass,
    VULN_CLASS_CATEGORIES,
    get_category,
)

__all__ = [
    # Enums
    "VulnClass",
    "Severity",
    # Taxonomy helpers
    "VULN_CLASS_CATEGORIES",
    "SEVERITY_CVSS_RANGES",
    "get_category",
    "severity_from_cvss",
    # Type aliases
    "KnowledgeSource",
    "PlatformType",
    "EngagementMode",
    "EngagementStatus",
    "FindingStatus",
    # Models
    "Scope",
    "KnowledgeRecord",
    "Finding",
    "FindingCreate",
    "FindingUpdate",
    "Engagement",
    "EngagementCreate",
    "EngagementUpdate",
    "EngagementResponse",
]
