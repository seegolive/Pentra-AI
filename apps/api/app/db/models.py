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
