"""ORM models: User, Workspace, Engagement, Finding, AuditLog."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class UserORM(Base):
    """A local operator account."""

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        nullable=False, server_default=func.now(), onupdate=func.now()
    )


class WorkspaceORM(Base):
    """A workspace groups engagements (e.g. per client or personal projects)."""

    __tablename__ = "workspaces"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        nullable=False, server_default=func.now(), onupdate=func.now()
    )

    engagements: Mapped[list["EngagementORM"]] = relationship(back_populates="workspace")


class EngagementORM(Base):
    """A single pentest / bug-bounty session against a target."""

    __tablename__ = "engagements"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    workspace_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    mode: Mapped[str] = mapped_column(String(20), nullable=False, default="semi_auto")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="planning")

    opsec_mode: Mapped[bool] = mapped_column(nullable=False, default=False, comment="Enable OPSEC jitter between tool calls")
    request_jitter_ms: Mapped[int] = mapped_column(nullable=False, default=0, comment="Max random delay (ms) added before each tool request")

    in_scope: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    out_of_scope: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    llm_model: Mapped[str] = mapped_column(String(100), nullable=False, default="qwen2.5:32b")
    langgraph_thread_id: Mapped[str] = mapped_column(String(100), nullable=False)

    created_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        nullable=False, server_default=func.now(), onupdate=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    monitoring_enabled: Mapped[bool] = mapped_column(nullable=False, default=False, comment="Whether continuous monitoring is enabled for this engagement")
    monitoring_interval_hours: Mapped[int] = mapped_column(nullable=False, default=24, comment="How often to run recon snapshot (hours)")

    workspace: Mapped["WorkspaceORM"] = relationship(back_populates="engagements")
    findings: Mapped[list["FindingORM"]] = relationship(back_populates="engagement")
    audit_logs: Mapped[list["AuditLogORM"]] = relationship(back_populates="engagement")


class FindingORM(Base):
    """A security finding discovered during an engagement."""

    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    engagement_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    vuln_class: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True, comment="CVSS v3.1 vector string, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    http_method: Mapped[str] = mapped_column(String(10), nullable=False, default="GET")

    request_raw: Mapped[str] = mapped_column(Text, nullable=False, default="")
    response_raw: Mapped[str] = mapped_column(Text, nullable=False, default="")
    screenshot_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    reproduction_steps: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    knowledge_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    status: Mapped[str] = mapped_column(String(30), nullable=False, default="new")
    discovered_by: Mapped[str] = mapped_column(String(100), nullable=False, default="manual")
    discovered_at: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── CVE Correlation (Task 5.2) ─────────────────────────────────────────
    cve_ids: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list,
        comment="List of correlated CVE IDs, e.g. ['CVE-2024-1234']",
    )
    cve_data: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True,
        comment="Enriched CVE detail from NVD (first/most severe match)",
    )
    chains: Mapped[list | None] = mapped_column(
        JSONB, nullable=True,
        comment="Attack chains this finding participates in, set by VulnerabilityCorrelator",
    )

    engagement: Mapped["EngagementORM"] = relationship(back_populates="findings")


class AuditLogORM(Base):
    """Append-only audit trail — every agent action writes one row."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    engagement_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actor: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())

    engagement: Mapped["EngagementORM"] = relationship(back_populates="audit_logs")


class ReconSnapshotORM(Base):
    """Periodic recon snapshot for delta detection / continuous monitoring."""

    __tablename__ = "recon_snapshots"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    engagement_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    snapshot_at: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())
    # Stores serialised recon data: subdomains, open ports, endpoints, tech stack
    subdomains: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    open_ports: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    endpoints: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    tech_stack: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    raw_summary: Mapped[str | None] = mapped_column(Text, nullable=True)


class EngagementLearningORM(Base):
    """Learning record persisted after each engagement completes.

    Queried by plan_node before generating a new plan so the LLM can
    benefit from prior experience on targets with similar tech stacks.
    """

    __tablename__ = "engagement_learnings"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    engagement_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Target context
    tech_stack: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    target_pattern: Mapped[str] = mapped_column(
        String(200), nullable=False, default="",
        comment="Human-readable pattern, e.g. 'ASP.NET + IIS + MSSQL'",
    )

    # What worked
    effective_tools: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list,
        comment='e.g. [{"tool": "nuclei", "tags": ["sqli"], "findings": 3}]',
    )
    effective_techniques: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list,
        comment='e.g. [{"technique": "HTTPS→HTTP fallback", "impact": "unblocked 30 findings"}]',
    )

    # What didn't work
    failed_tools: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    failed_techniques: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # High-value endpoints discovered
    high_value_endpoints: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list,
        comment='e.g. [{"pattern": "/products?cat=", "vuln": "SQLi", "confirmed": true}]',
    )

    # Metrics
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    engagement_duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())


class MonitoringAlertORM(Base):
    """A change detected between two recon snapshots."""

    __tablename__ = "monitoring_alerts"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    engagement_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    alert_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # new_subdomain | new_port | new_endpoint | removed_subdomain
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())


class AgentEventORM(Base):
    """Persisted WebSocket event for engagement live feed — Task 19.4.

    Allows frontend to reload event history after page refresh or server restart.
    Max retention enforced by cleanup task: 7 days or 1000 events per engagement.
    LLM_STREAM tokens are excluded (too voluminous) — only structural events.
    """

    __tablename__ = "agent_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    engagement_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    node: Mapped[str | None] = mapped_column(String(100), nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        nullable=False, server_default=func.now(), index=True
    )
