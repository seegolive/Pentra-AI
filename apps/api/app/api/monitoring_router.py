"""Monitoring API endpoints.

Route summary:
  GET   /api/v1/engagements/{id}/monitoring/alerts
  PATCH /api/v1/engagements/{id}/monitoring/alerts/{alert_id}/read
  GET   /api/v1/engagements/{id}/monitoring/snapshots
  GET   /api/v1/engagements/{id}/monitoring/snapshots/diff
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    MonitoringAlertResponse,
    ReconSnapshotResponse,
    SnapshotDiffResponse,
)
from app.core.deps import get_current_user
from app.db.base import get_db
from app.db.models import EngagementORM, MonitoringAlertORM, ReconSnapshotORM, UserORM

router = APIRouter(prefix="/api/v1", tags=["monitoring"])


async def _get_engagement_or_404(
    engagement_id: UUID,
    db: AsyncSession,
    current_user: UserORM,
) -> EngagementORM:
    result = await db.execute(
        select(EngagementORM).where(EngagementORM.id == engagement_id)
    )
    engagement = result.scalar_one_or_none()
    if engagement is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement


@router.get(
    "/engagements/{engagement_id}/monitoring/alerts",
    response_model=list[MonitoringAlertResponse],
    summary="List monitoring alerts",
    description="List security monitoring alerts for an engagement. Filter by is_read status or alert_type.",
)
async def list_monitoring_alerts(
    engagement_id: UUID,
    is_read: bool | None = Query(default=None),
    alert_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> list[MonitoringAlertResponse]:
    """List monitoring alerts for an engagement, optionally filtered."""
    await _get_engagement_or_404(engagement_id, db, current_user)

    stmt = (
        select(MonitoringAlertORM)
        .where(MonitoringAlertORM.engagement_id == engagement_id)
        .order_by(MonitoringAlertORM.created_at.desc())
        .limit(limit)
    )
    if is_read is not None:
        stmt = stmt.where(MonitoringAlertORM.is_read == is_read)
    if alert_type is not None:
        stmt = stmt.where(MonitoringAlertORM.alert_type == alert_type)

    result = await db.execute(stmt)
    alerts = result.scalars().all()
    return [MonitoringAlertResponse.model_validate(a) for a in alerts]


@router.patch(
    "/engagements/{engagement_id}/monitoring/alerts/{alert_id}/read",
    response_model=MonitoringAlertResponse,
    summary="Mark alert as read",
    description="Mark a single monitoring alert as read.",
)
async def mark_alert_read(
    engagement_id: UUID,
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> MonitoringAlertResponse:
    """Mark a single monitoring alert as read."""
    await _get_engagement_or_404(engagement_id, db, current_user)

    result = await db.execute(
        select(MonitoringAlertORM).where(
            MonitoringAlertORM.id == alert_id,
            MonitoringAlertORM.engagement_id == engagement_id,
        )
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_read = True  # type: ignore[assignment]
    await db.commit()
    await db.refresh(alert)
    return MonitoringAlertResponse.model_validate(alert)


@router.post(
    "/engagements/{engagement_id}/monitoring/alerts/read-all",
    response_model=dict,
    summary="Mark all alerts read",
    description="Mark all unread monitoring alerts for an engagement as read in one call.",
)
async def mark_all_alerts_read(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> dict:
    """Mark all unread alerts for an engagement as read."""
    await _get_engagement_or_404(engagement_id, db, current_user)

    await db.execute(
        update(MonitoringAlertORM)
        .where(
            MonitoringAlertORM.engagement_id == engagement_id,
            MonitoringAlertORM.is_read.is_(False),
        )
        .values(is_read=True)
    )
    await db.commit()
    return {"status": "ok"}


@router.get(
    "/engagements/{engagement_id}/monitoring/snapshots",
    response_model=list[ReconSnapshotResponse],
    summary="List recon snapshots",
    description="Return recon snapshots for an engagement, newest first. Used to track attack surface changes over time.",
)
async def list_recon_snapshots(
    engagement_id: UUID,
    limit: int = Query(default=10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> list[ReconSnapshotResponse]:
    """List recon snapshots for an engagement (newest first)."""
    await _get_engagement_or_404(engagement_id, db, current_user)

    result = await db.execute(
        select(ReconSnapshotORM)
        .where(ReconSnapshotORM.engagement_id == engagement_id)
        .order_by(ReconSnapshotORM.snapshot_at.desc())
        .limit(limit)
    )
    snapshots = result.scalars().all()
    return [ReconSnapshotResponse.model_validate(s) for s in snapshots]


@router.get(
    "/engagements/{engagement_id}/monitoring/snapshots/diff",
    response_model=SnapshotDiffResponse,
    summary="Diff two snapshots",
    description="Compute the delta (new/removed hosts, ports, endpoints) between two recon snapshots.",
)
async def get_snapshot_diff(
    engagement_id: UUID,
    snapshot_a: UUID = Query(..., description="Older snapshot ID"),
    snapshot_b: UUID = Query(..., description="Newer snapshot ID"),
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> SnapshotDiffResponse:
    """Compute delta between two recon snapshots."""
    await _get_engagement_or_404(engagement_id, db, current_user)

    result_a = await db.execute(
        select(ReconSnapshotORM).where(
            ReconSnapshotORM.id == snapshot_a,
            ReconSnapshotORM.engagement_id == engagement_id,
        )
    )
    snap_a = result_a.scalar_one_or_none()
    if snap_a is None:
        raise HTTPException(status_code=404, detail="Snapshot A not found")

    result_b = await db.execute(
        select(ReconSnapshotORM).where(
            ReconSnapshotORM.id == snapshot_b,
            ReconSnapshotORM.engagement_id == engagement_id,
        )
    )
    snap_b = result_b.scalar_one_or_none()
    if snap_b is None:
        raise HTTPException(status_code=404, detail="Snapshot B not found")

    # Compute diffs
    subs_a: set[str] = {s if isinstance(s, str) else str(s) for s in (snap_a.subdomains or [])}
    subs_b: set[str] = {s if isinstance(s, str) else str(s) for s in (snap_b.subdomains or [])}
    new_subdomains = sorted(subs_b - subs_a)
    removed_subdomains = sorted(subs_a - subs_b)

    ports_a: dict = snap_a.open_ports or {}
    ports_b: dict = snap_b.open_ports or {}
    new_ports: dict = {}
    for host, ports in ports_b.items():
        old_ports = set(ports_a.get(host, []))
        added = [p for p in ports if p not in old_ports]
        if added:
            new_ports[host] = added

    eps_a: set[str] = {e if isinstance(e, str) else str(e) for e in (snap_a.endpoints or [])}
    eps_b: set[str] = {e if isinstance(e, str) else str(e) for e in (snap_b.endpoints or [])}
    new_endpoints = sorted(eps_b - eps_a)

    tech_a: set[str] = {t if isinstance(t, str) else str(t) for t in (snap_a.tech_stack or [])}
    tech_b: set[str] = {t if isinstance(t, str) else str(t) for t in (snap_b.tech_stack or [])}
    new_tech = sorted(tech_b - tech_a)

    return SnapshotDiffResponse(
        snapshot_a_id=snap_a.id,
        snapshot_b_id=snap_b.id,
        snapshot_a_at=snap_a.snapshot_at,
        snapshot_b_at=snap_b.snapshot_at,
        new_subdomains=new_subdomains,
        removed_subdomains=removed_subdomains,
        new_ports=new_ports,
        new_endpoints=new_endpoints,
        new_tech=new_tech,
    )


# ── Monitoring schedule ───────────────────────────────────────────────────────

class MonitoringScheduleRequest(BaseModel):
    enabled: bool = True
    interval_hours: int = 24


@router.get(
    "/engagements/{engagement_id}/monitoring/schedule",
    summary="Get monitoring schedule",
    description="Return the current monitoring schedule settings for an engagement.",
)
async def get_monitoring_schedule(
    engagement_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> dict:
    """Return saved monitoring schedule for an engagement."""
    eng = await _get_engagement_or_404(engagement_id, db, current_user)
    return {
        "enabled": eng.monitoring_enabled,
        "interval_hours": eng.monitoring_interval_hours,
    }


@router.post(
    "/engagements/{engagement_id}/monitoring/schedule",
    summary="Set monitoring schedule",
    description="Enable or disable continuous monitoring schedule for an engagement.",
)
async def set_monitoring_schedule(
    engagement_id: UUID,
    body: MonitoringScheduleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserORM = Depends(get_current_user),
) -> dict:
    """Persist monitoring schedule for an engagement."""
    eng = await _get_engagement_or_404(engagement_id, db, current_user)
    eng.monitoring_enabled = body.enabled
    eng.monitoring_interval_hours = body.interval_hours
    await db.commit()
    return {
        "updated": True,
        "enabled": eng.monitoring_enabled,
        "interval_hours": eng.monitoring_interval_hours,
    }
