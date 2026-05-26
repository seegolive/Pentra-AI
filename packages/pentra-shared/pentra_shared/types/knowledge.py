from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from pentra_shared.types.severity import Severity
from pentra_shared.types.vuln_class import VulnClass

KnowledgeSource = Literal[
    "hackerone",
    "bugcrowd",
    "intigriti",
    "writeup",
    "pentra_finding",
    "custom",
]

PlatformType = Literal["web", "api", "mobile", "cloud", "network", "iot"]


class KnowledgeRecord(BaseModel):
    """A single knowledge record ingested from a real-world bug bounty disclosure
    or security writeup.

    Stored in both PostgreSQL (metadata + full text) and Qdrant (embeddings).
    """

    model_config = ConfigDict(from_attributes=True)

    # ── Identity ─────────────────────────────────────────────────────────
    id: UUID
    source: KnowledgeSource
    source_id: str = Field(description="Original ID in the source system (e.g., H1 report ID)")
    source_url: str | None = Field(default=None, description="Public URL of the original disclosure")
    ingested_at: datetime
    updated_at: datetime

    # ── Vulnerability Classification ─────────────────────────────────────
    title: str = Field(max_length=500)
    vuln_class: VulnClass
    vuln_subclass: str = Field(
        description="More specific classification string (e.g., 'stored_xss_via_filename')"
    )
    severity: Severity
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = Field(default=None, description="CVSS vector string")
    cve_id: str | None = Field(default=None, description="CVE identifier if correlated")

    # ── Target Context ────────────────────────────────────────────────────
    program: str = Field(description="Bug bounty program name (e.g., 'shopify', 'gitlab')")
    tech_stack: list[str] = Field(
        default_factory=list,
        description="Technologies involved (e.g., ['Ruby on Rails', 'PostgreSQL'])",
    )
    platform_type: list[PlatformType] = Field(
        default_factory=list,
        description="Target platform categories",
    )
    endpoint_pattern: str = Field(
        description="Generalised endpoint pattern (e.g., '/api/v{n}/users/{id}/*')"
    )
    http_method: list[str] = Field(
        default_factory=list,
        description="HTTP methods involved (e.g., ['GET', 'POST'])",
    )
    auth_required: bool = Field(description="Whether a valid session is needed to reproduce")

    # ── Attack Intelligence ───────────────────────────────────────────────
    attack_technique: str = Field(
        description="Human-readable summary of how the vulnerability is exploited"
    )
    attack_steps: list[str] = Field(
        default_factory=list,
        description="Step-by-step reproduction instructions",
    )
    payload_pattern: str | None = Field(
        default=None,
        description="Representative payload or payload template",
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Observable signals that suggest this vulnerability may be present",
    )
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Conditions that must be true for this bug to exist",
    )
    what_tools_missed: str | None = Field(
        default=None,
        description="Why automated scanners failed to detect this vulnerability",
    )

    # ── Chain & Impact ────────────────────────────────────────────────────
    chained_with: list[str] = Field(
        default_factory=list,
        description="Vulnerability classes this is commonly chained with",
    )
    impact: str = Field(description="Impact description of a successful exploit")
    impact_category: list[str] = Field(
        default_factory=list,
        description="Impact categories (e.g., ['account_takeover', 'data_exfil'])",
    )
    bounty_usd: int | None = Field(default=None, ge=0, description="Bounty paid in USD")

    # ── Learning ──────────────────────────────────────────────────────────
    key_insight: str = Field(
        description="The 'aha moment' — 1–3 sentences capturing the core learning"
    )
    unique_factor: str = Field(
        description="What made this non-obvious to find"
    )
    pentra_tags: list[str] = Field(
        default_factory=list,
        description="Internal taxonomy tags for retrieval tuning",
    )

    # ── Quality Scoring ───────────────────────────────────────────────────
    quality_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Completeness score (0.0–1.0) — used to boost retrieval rank",
    )

    # ── Embedding (BGE-M3) ────────────────────────────────────────────────
    embedding_dense: list[float] = Field(
        default_factory=list,
        description="Dense vector (1024-dim from BGE-M3)",
    )
    embedding_sparse: dict[str, float] = Field(
        default_factory=dict,
        description="Sparse vector weights for lexical search (SPLADE-style)",
    )
    embedding_model: str = Field(default="bge-m3")
    embedding_version: int = Field(default=1)

    def calculate_quality_score(self) -> float:
        """Compute a completeness score from 0.0 to 1.0.

        Higher-quality records (more fields populated, higher bounty) are
        surfaced first in search results via a quality boost multiplier.
        """
        score = 0.0
        if self.key_insight:
            score += 0.20
        if self.attack_technique:
            score += 0.20
        if self.indicators:
            score += 0.15
        if self.attack_steps:
            score += 0.15
        if self.what_tools_missed:
            score += 0.10
        if self.tech_stack:
            score += 0.10
        if self.bounty_usd and self.bounty_usd > 0:
            if self.bounty_usd >= 5000:
                score += 0.10
            else:
                score += 0.05
        if self.chained_with:
            score += 0.05
        if self.cvss_score:
            score += 0.05
        return round(min(score, 1.0), 4)
