"""Pydantic schemas for the Knowledge Engine REST API.

These are the request/response types for the FastAPI router.
They are distinct from the canonical ``KnowledgeRecord`` in pentra-shared so
the API can evolve (add pagination wrappers, hide internal fields, etc.)
without breaking the shared contract used by other packages.
"""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from pentra_shared.types import KnowledgeRecord, KnowledgeSource, Severity, VulnClass


# ── Request schemas ───────────────────────────────────────────────────────────

class SearchRequest(BaseModel):
    """Query parameters for GET /knowledge/search (also usable as POST body)."""

    model_config = ConfigDict(from_attributes=True)

    q: str = Field(
        min_length=1,
        max_length=1000,
        description="Natural-language search query",
    )
    vuln_class: list[VulnClass] | None = Field(
        default=None,
        description="Filter by vulnerability class (multi-value OR)",
    )
    severity: list[Severity] | None = Field(
        default=None,
        description="Filter by severity (multi-value OR)",
    )
    tech_stack: list[str] | None = Field(
        default=None,
        description="Filter by tech stack entries (multi-value OR, case-insensitive)",
    )
    source: list[KnowledgeSource] | None = Field(
        default=None,
        description="Filter by source system",
    )
    top_k: int = Field(
        default=8,
        ge=1,
        le=50,
        description="Maximum number of results to return",
    )


class KnowledgeInjectRequest(BaseModel):
    """Manual knowledge injection — POST /knowledge/inject."""

    model_config = ConfigDict(from_attributes=True)

    source: KnowledgeSource
    source_id: str = Field(max_length=200)
    source_url: str | None = None
    title: str = Field(max_length=500)
    vuln_class: VulnClass
    vuln_subclass: str = Field(default="")
    severity: Severity
    program: str = Field(max_length=200)
    tech_stack: list[str] = Field(default_factory=list)
    platform_type: list[str] = Field(default_factory=list)
    endpoint_pattern: str = Field(default="")
    http_method: list[str] = Field(default_factory=list)
    auth_required: bool = True
    attack_technique: str
    attack_steps: list[str] = Field(default_factory=list)
    payload_pattern: str | None = None
    indicators: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    what_tools_missed: str | None = None
    chained_with: list[str] = Field(default_factory=list)
    impact: str = Field(default="")
    impact_category: list[str] = Field(default_factory=list)
    bounty_usd: int | None = None
    key_insight: str
    unique_factor: str = Field(default="")
    pentra_tags: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    cve_id: str | None = None


class KnowledgeRawInjectRequest(BaseModel):
    """Raw text injection — POST /knowledge/inject/raw.

    Accepts a free-form vulnerability description (writeup, report paste, etc.).
    LLM extraction populates all intelligence fields automatically.
    """

    model_config = ConfigDict(from_attributes=True)

    title: str = Field(max_length=500, description="Short descriptive title")
    raw_text: str = Field(
        max_length=10000,
        description="Full vulnerability description, PoC, writeup text, etc.",
    )
    source: KnowledgeSource | None = Field(default=None)
    source_id: str | None = Field(
        default=None,
        max_length=200,
        description="Stable unique identifier (auto-generated if omitted)",
    )
    source_url: str | None = None
    program: str | None = Field(default=None, max_length=200)
    severity: Severity | None = None
    vuln_class: VulnClass | None = None
    bounty_usd: int | None = None


# ── Response schemas ──────────────────────────────────────────────────────────

class KnowledgeSummary(BaseModel):
    """Lightweight record representation for list / search results.

    Omits heavy embedding vectors to keep payloads small.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    vuln_class: VulnClass
    severity: Severity
    program: str
    tech_stack: list[str]
    key_insight: str
    bounty_usd: int | None
    source: KnowledgeSource
    source_url: str | None

    @classmethod
    def from_record(cls, record: KnowledgeRecord) -> "KnowledgeSummary":
        return cls(
            id=record.id,
            title=record.title,
            vuln_class=record.vuln_class,
            severity=record.severity,
            program=record.program,
            tech_stack=record.tech_stack,
            key_insight=record.key_insight,
            bounty_usd=record.bounty_usd,
            source=record.source,
            source_url=record.source_url,
        )


class SearchResponse(BaseModel):
    """Wrapper for search results with pagination metadata."""

    results: list[KnowledgeSummary]
    total: int
    query: str


class KnowledgeInjectResponse(BaseModel):
    """Response after a successful manual injection."""

    id: UUID
    status: str = "queued"
    message: str = "Record saved. Embedding will be computed asynchronously."
