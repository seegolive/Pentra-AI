from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from pentra_shared.types.severity import Severity
from pentra_shared.types.vuln_class import VulnClass

FindingStatus = Literal[
    "new",
    "confirmed",
    "false_positive",
    "duplicate",
    "reported",
]


class Finding(BaseModel):
    """A security finding discovered during an engagement.

    Created by the agent or manually by the operator. Each finding is linked to
    the engagement, categorised by vulnerability class and severity, and stores
    raw HTTP evidence for report generation.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID

    # ── Classification ────────────────────────────────────────────────────
    title: str = Field(max_length=500)
    vuln_class: VulnClass
    severity: Severity
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)

    # ── Target ────────────────────────────────────────────────────────────
    target_url: str = Field(description="Affected URL")
    http_method: str = Field(description="HTTP method (GET, POST, …)")

    # ── Evidence ──────────────────────────────────────────────────────────
    request_raw: str = Field(description="Raw HTTP request that triggered the vulnerability")
    response_raw: str = Field(description="Raw HTTP response showing the vulnerability")
    screenshot_path: str | None = Field(
        default=None,
        description="MinIO path to screenshot evidence",
    )
    reproduction_steps: list[str] = Field(
        default_factory=list,
        description="Ordered reproduction instructions",
    )

    # ── Knowledge References ──────────────────────────────────────────────
    knowledge_refs: list[UUID] = Field(
        default_factory=list,
        description="IDs of KnowledgeRecords that informed this finding",
    )

    # ── Lifecycle ─────────────────────────────────────────────────────────
    status: FindingStatus = Field(default="new")
    discovered_by: str = Field(
        description="Agent node name (e.g., 'vuln_hunt_node') or 'manual'"
    )
    discovered_at: datetime


class FindingCreate(BaseModel):
    """Schema for creating a new Finding (agent or API input)."""

    model_config = ConfigDict(from_attributes=True)

    engagement_id: UUID
    title: str = Field(max_length=500)
    vuln_class: VulnClass
    severity: Severity
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    target_url: str
    http_method: str
    request_raw: str
    response_raw: str
    screenshot_path: str | None = None
    reproduction_steps: list[str] = Field(default_factory=list)
    knowledge_refs: list[UUID] = Field(default_factory=list)
    discovered_by: str


class FindingUpdate(BaseModel):
    """Schema for patching an existing Finding (status transitions, screenshots)."""

    model_config = ConfigDict(from_attributes=True)

    status: FindingStatus | None = None
    screenshot_path: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    knowledge_refs: list[UUID] | None = None
