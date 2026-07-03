"""Pydantic schemas for Workspace and Engagement API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# ── Workspace ─────────────────────────────────────────────────────────────────

class WorkspaceCreate(BaseModel):
    name: str = Field(max_length=200)
    description: str | None = Field(default=None, max_length=2000)


class WorkspaceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None
    owner_id: UUID | None
    created_at: datetime
    updated_at: datetime


# ── Engagement ────────────────────────────────────────────────────────────────

class EngagementCreate(BaseModel):
    workspace_id: UUID
    name: str = Field(max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    mode: Literal["semi_auto", "agentic"] = "semi_auto"
    in_scope: list[str] = Field(min_length=1)
    out_of_scope: list[str] = Field(default_factory=list)
    llm_model: str = Field(default="qwen2.5:32b")
    scan_preset: str = Field(default="fast")
    opsec_mode: bool = False
    request_jitter_ms: int = Field(default=0, ge=0, le=30_000)
    scan_sequential: bool = False
    auto_approve_exploit_validation: bool = False
    tool_config: dict = Field(default_factory=dict)


class EngagementResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workspace_id: UUID
    name: str
    description: str | None
    mode: str
    status: str
    in_scope: list[str]
    out_of_scope: list[str]
    llm_model: str
    scan_preset: str
    langgraph_thread_id: str
    opsec_mode: bool
    request_jitter_ms: int
    scan_sequential: bool
    auto_approve_exploit_validation: bool
    created_by: UUID
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    tool_config: dict = Field(default_factory=dict)


# ── HITL ──────────────────────────────────────────────────────────────────────

class HitlDecision(BaseModel):
    action: Literal["approve", "skip", "modify"]
    modified_data: dict | None = None


# ── Recon Surface ─────────────────────────────────────────────────────────────

class SubdomainInfo(BaseModel):
    host: str
    ip: str | None = None
    source: str = ""
    is_alive: bool = False
    status_code: int | None = None
    tech_stack: list[str] = Field(default_factory=list)
    findings_count: int = 0
    interest_score: int = 0
    is_interesting: bool = False


class PortInfo(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str | None = None
    state: str = "open"


class EndpointInfo(BaseModel):
    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    source: str = ""


class ReconStateResponse(BaseModel):
    subdomains: list[SubdomainInfo] = Field(default_factory=list)
    open_ports: list[PortInfo] = Field(default_factory=list)
    endpoints: list[EndpointInfo] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)
    osint_summary: dict = Field(default_factory=dict)
    total_subdomains: int = 0
    alive_count: int = 0
    total_ports: int = 0
    total_endpoints: int = 0


# ── Finding ───────────────────────────────────────────────────────────────────

class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID
    title: str
    vuln_class: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None = None
    target_url: str
    http_method: str
    status: str
    discovered_by: str
    discovered_at: datetime
    description: str | None = None
    impact: str | None = None
    remediation: str | None = None
    request_raw: str = ""
    response_raw: str = ""
    reproduction_steps: list = Field(default_factory=list)
    cve_ids: list[str] = []
    cve_data: dict | None = None
    chains: list | None = None


class FindingWithEngagementResponse(FindingResponse):
    engagement_name: str


class PaginatedFindingsResponse(BaseModel):
    results: list[FindingWithEngagementResponse]
    total: int
    page: int
    page_size: int


# ── Export / Import ───────────────────────────────────────────────────────────

class FindingExport(BaseModel):
    """Single finding inside an engagement export bundle."""
    title: str
    vuln_class: str
    severity: str
    cvss_score: float | None = None
    target_url: str
    http_method: str = "GET"
    request_raw: str = ""
    response_raw: str = ""
    reproduction_steps: list = Field(default_factory=list)
    status: str = "new"
    discovered_by: str = "manual"
    description: str | None = None
    cve_ids: list[str] = Field(default_factory=list)


class EngagementExportBundle(BaseModel):
    """Full export bundle for an engagement (JSON download)."""
    export_version: str = "1"
    exported_at: datetime
    engagement: EngagementResponse
    findings: list[FindingExport]


class EngagementImportRequest(BaseModel):
    """Body for POST /workspaces/{id}/engagements/import."""
    bundle: EngagementExportBundle
    new_name: str | None = Field(default=None, max_length=200, description="Override engagement name on import")


# ── Knowledge inject ──────────────────────────────────────────────────────────

class KnowledgeInjectRequest(BaseModel):
    """Body for POST /findings/{id}/submit-to-knowledge."""
    key_insight: str = Field(default="", max_length=1000)
    technique: str = Field(default="", max_length=500)
    tags: list[str] = Field(default_factory=list)


# ── Finding Patch ─────────────────────────────────────────────────────────────

class FindingPatch(BaseModel):
    """Body for PATCH /findings/{id} — partial update."""
    status: Optional[Literal["open", "confirmed", "false_positive", "wont_fix", "resolved"]] = None


class KnowledgeInjectResponse(BaseModel):
    knowledge_record_id: str
    message: str


# ── KB Manual Inject ──────────────────────────────────────────────────────────

class KBManualInjectRequest(BaseModel):
    """Body for POST /knowledge/inject — manual KB record creation."""
    title: str = Field(max_length=500)
    vuln_class: str
    severity: str = "info"
    source: str = Field(default="manual", max_length=50)
    raw_text: str = Field(max_length=20000)
    key_insight: str = Field(default="", max_length=1000)
    technique: str = Field(default="", max_length=500)
    tech_stack: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    url: str | None = None


class KBUrlInjectRequest(BaseModel):
    """Body for POST /knowledge/inject/url."""
    url: str = Field(max_length=2000)
    vuln_class: str | None = None
    tags: list[str] = Field(default_factory=list)


# ── Payload Generator ─────────────────────────────────────────────────────────

class PayloadGenerateAPIRequest(BaseModel):
    """Body for POST /payloads/generate."""
    target_url: str
    parameter_name: str
    parameter_value: str = ""
    parameter_position: str = "query"
    http_method: str = "GET"
    vuln_class: str
    tech_stack: list[str] = Field(default_factory=list)
    additional_context: str = ""
    count: int = Field(default=10, ge=1, le=50)


class PayloadItem(BaseModel):
    value: str
    rationale: str
    severity_hint: str = "medium"
    requires_encoding: bool = False


class PayloadGenerateAPIResponse(BaseModel):
    payloads: list[PayloadItem]
    knowledge_used: int
    model_used: str


# ── Monitoring ────────────────────────────────────────────────────────────────

class MonitoringAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID
    alert_type: str
    detail: dict
    is_read: bool
    created_at: datetime


class ReconSnapshotResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID
    snapshot_at: datetime
    subdomains: list[SubdomainInfo]
    open_ports: dict
    endpoints: list
    tech_stack: list
    raw_summary: str | None

    @classmethod
    def from_orm_safe(cls, obj: Any) -> "ReconSnapshotResponse":
        """Coerce legacy string[] subdomains to SubdomainInfo on read."""
        subs = []
        for s in (obj.subdomains or []):
            if isinstance(s, dict):
                subs.append(SubdomainInfo(**{k: v for k, v in s.items() if k in SubdomainInfo.model_fields}))
            else:
                subs.append(SubdomainInfo(host=str(s)))
        return cls(
            id=obj.id,
            engagement_id=obj.engagement_id,
            snapshot_at=obj.snapshot_at,
            subdomains=subs,
            open_ports=obj.open_ports or {},
            endpoints=obj.endpoints or [],
            tech_stack=obj.tech_stack or [],
            raw_summary=obj.raw_summary,
        )


class SnapshotDiffResponse(BaseModel):
    snapshot_a_id: UUID
    snapshot_b_id: UUID
    snapshot_a_at: datetime
    snapshot_b_at: datetime
    new_subdomains: list[str]
    removed_subdomains: list[str]
    new_ports: dict   # host -> [port, ...]
    new_endpoints: list[str]
    new_tech: list[str]


class SubscanRequest(BaseModel):
    target_urls: list[str] = Field(..., min_length=1, max_length=50)
