"""Tests for /monitoring/* endpoints (Sprint 35).

Covers list_monitoring_alerts, mark_alert_read, mark_all_alerts_read,
list_recon_snapshots, get_snapshot_diff, get_monitoring_schedule,
set_monitoring_schedule — all via mocked DB sessions (no live DB).
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.api.monitoring_router import (
    get_monitoring_schedule,
    get_snapshot_diff,
    list_monitoring_alerts,
    list_recon_snapshots,
    mark_alert_read,
    mark_all_alerts_read,
    set_monitoring_schedule,
    MonitoringScheduleRequest,
)
from app.db.models import EngagementORM, MonitoringAlertORM, ReconSnapshotORM, UserORM


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_user() -> UserORM:
    u = UserORM()
    u.id = uuid4()
    u.username = "tester"
    u.email = "tester@test.com"
    u.hashed_password = "x"
    u.is_active = True
    u.is_admin = False
    return u


def _make_engagement(user_id=None) -> EngagementORM:
    e = EngagementORM()
    e.id = uuid4()
    e.workspace_id = uuid4()
    e.name = "Monitoring Test Engagement"
    e.description = None
    e.mode = "semi_auto"
    e.status = "running"
    e.in_scope = ["target.com"]
    e.out_of_scope = []
    e.llm_model = "qwen2.5-coder:32b"
    e.langgraph_thread_id = str(uuid4())
    e.opsec_mode = False
    e.request_jitter_ms = 0
    e.created_by = user_id or uuid4()
    e.created_at = datetime.now(timezone.utc)
    e.updated_at = datetime.now(timezone.utc)
    e.started_at = None
    e.completed_at = None
    e.monitoring_enabled = False
    e.monitoring_interval_hours = 24
    return e


def _make_alert(engagement_id=None, alert_type="new_subdomain", is_read=False) -> MonitoringAlertORM:
    a = MonitoringAlertORM()
    a.id = uuid4()
    a.engagement_id = engagement_id or uuid4()
    a.alert_type = alert_type
    a.detail = {"host": "new.target.com"}
    a.is_read = is_read
    a.notified = False
    a.created_at = datetime.now(timezone.utc)
    return a


def _make_snapshot(engagement_id=None, **kwargs) -> ReconSnapshotORM:
    s = ReconSnapshotORM()
    s.id = uuid4()
    s.engagement_id = engagement_id or uuid4()
    s.snapshot_at = datetime.now(timezone.utc)
    s.subdomains = kwargs.get("subdomains", ["api.target.com", "www.target.com"])
    s.open_ports = kwargs.get("open_ports", {"api.target.com": [80, 443]})
    s.endpoints = kwargs.get("endpoints", ["/api/v1", "/login"])
    s.tech_stack = kwargs.get("tech_stack", ["nginx", "react"])
    s.raw_summary = kwargs.get("raw_summary", None)
    return s


def _db_returning(eng, *rows_per_execute):
    """
    DB mock where execute() returns different MagicMocks per call.
    First call is engagement lookup (scalar_one_or_none → eng).
    Subsequent calls return scalars().all() → rows.
    """
    db = AsyncMock()

    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng

    side_effects = [eng_result]
    for rows in rows_per_execute:
        r = MagicMock()
        r.scalar_one_or_none.return_value = rows[0] if len(rows) == 1 else None
        r.scalars.return_value.all.return_value = rows
        side_effects.append(r)

    db.execute.side_effect = side_effects
    return db


# ── list_monitoring_alerts ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_alerts_returns_all():
    user = _make_user()
    eng = _make_engagement(user.id)
    alerts = [_make_alert(eng.id), _make_alert(eng.id, alert_type="new_port")]
    db = _db_returning(eng, alerts)

    result = await list_monitoring_alerts(
        engagement_id=eng.id, is_read=None, alert_type=None, limit=50,
        db=db, current_user=user,
    )

    assert len(result) == 2


@pytest.mark.asyncio
async def test_list_alerts_returns_empty():
    user = _make_user()
    eng = _make_engagement(user.id)
    db = _db_returning(eng, [])

    result = await list_monitoring_alerts(
        engagement_id=eng.id, is_read=None, alert_type=None, limit=50,
        db=db, current_user=user,
    )

    assert result == []


@pytest.mark.asyncio
async def test_list_alerts_404_if_no_engagement():
    from fastapi import HTTPException
    user = _make_user()
    db = AsyncMock()
    no_eng = MagicMock()
    no_eng.scalar_one_or_none.return_value = None
    db.execute.return_value = no_eng

    with pytest.raises(HTTPException) as exc_info:
        await list_monitoring_alerts(
            engagement_id=uuid4(), is_read=None, alert_type=None, limit=50,
            db=db, current_user=user,
        )
    assert exc_info.value.status_code == 404


# ── mark_alert_read ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mark_alert_read_sets_is_read():
    user = _make_user()
    eng = _make_engagement(user.id)
    alert = _make_alert(eng.id, is_read=False)

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng
    alert_result = MagicMock()
    alert_result.scalar_one_or_none.return_value = alert
    db.execute.side_effect = [eng_result, alert_result]
    db.refresh = AsyncMock(return_value=None)

    result = await mark_alert_read(
        engagement_id=eng.id, alert_id=alert.id, db=db, current_user=user,
    )

    assert alert.is_read is True
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_mark_alert_read_404_if_alert_missing():
    from fastapi import HTTPException
    user = _make_user()
    eng = _make_engagement(user.id)

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng
    alert_result = MagicMock()
    alert_result.scalar_one_or_none.return_value = None
    db.execute.side_effect = [eng_result, alert_result]

    with pytest.raises(HTTPException) as exc_info:
        await mark_alert_read(
            engagement_id=eng.id, alert_id=uuid4(), db=db, current_user=user,
        )
    assert exc_info.value.status_code == 404


# ── mark_all_alerts_read ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mark_all_alerts_read_returns_ok():
    user = _make_user()
    eng = _make_engagement(user.id)

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng
    db.execute.side_effect = [eng_result, MagicMock()]  # 2nd call is the UPDATE

    result = await mark_all_alerts_read(engagement_id=eng.id, db=db, current_user=user)

    assert result == {"status": "ok"}
    db.commit.assert_called_once()


# ── list_recon_snapshots ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_snapshots_returns_results():
    user = _make_user()
    eng = _make_engagement(user.id)
    snaps = [_make_snapshot(eng.id), _make_snapshot(eng.id)]
    db = _db_returning(eng, snaps)

    result = await list_recon_snapshots(
        engagement_id=eng.id, limit=10, db=db, current_user=user,
    )

    assert len(result) == 2


@pytest.mark.asyncio
async def test_list_snapshots_empty():
    user = _make_user()
    eng = _make_engagement(user.id)
    db = _db_returning(eng, [])

    result = await list_recon_snapshots(
        engagement_id=eng.id, limit=10, db=db, current_user=user,
    )
    assert result == []


# ── get_snapshot_diff ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_snapshot_diff_detects_new_subdomain():
    user = _make_user()
    eng = _make_engagement(user.id)

    snap_a = _make_snapshot(eng.id, subdomains=["www.target.com"], open_ports={}, endpoints=[], tech_stack=[])
    snap_b = _make_snapshot(eng.id, subdomains=["www.target.com", "new.target.com"], open_ports={}, endpoints=[], tech_stack=[])

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng
    snap_a_result = MagicMock()
    snap_a_result.scalar_one_or_none.return_value = snap_a
    snap_b_result = MagicMock()
    snap_b_result.scalar_one_or_none.return_value = snap_b
    db.execute.side_effect = [eng_result, snap_a_result, snap_b_result]

    result = await get_snapshot_diff(
        engagement_id=eng.id,
        snapshot_a=snap_a.id,
        snapshot_b=snap_b.id,
        db=db,
        current_user=user,
    )

    assert "new.target.com" in result.new_subdomains
    assert result.removed_subdomains == []


@pytest.mark.asyncio
async def test_snapshot_diff_detects_removed_subdomain():
    user = _make_user()
    eng = _make_engagement(user.id)

    snap_a = _make_snapshot(eng.id, subdomains=["www.target.com", "old.target.com"], open_ports={}, endpoints=[], tech_stack=[])
    snap_b = _make_snapshot(eng.id, subdomains=["www.target.com"], open_ports={}, endpoints=[], tech_stack=[])

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng
    snap_a_result = MagicMock()
    snap_a_result.scalar_one_or_none.return_value = snap_a
    snap_b_result = MagicMock()
    snap_b_result.scalar_one_or_none.return_value = snap_b
    db.execute.side_effect = [eng_result, snap_a_result, snap_b_result]

    result = await get_snapshot_diff(
        engagement_id=eng.id,
        snapshot_a=snap_a.id,
        snapshot_b=snap_b.id,
        db=db,
        current_user=user,
    )

    assert "old.target.com" in result.removed_subdomains
    assert result.new_subdomains == []


@pytest.mark.asyncio
async def test_snapshot_diff_detects_new_port():
    user = _make_user()
    eng = _make_engagement(user.id)

    snap_a = _make_snapshot(eng.id, subdomains=[], open_ports={"api.target.com": [443]}, endpoints=[], tech_stack=[])
    snap_b = _make_snapshot(eng.id, subdomains=[], open_ports={"api.target.com": [443, 8080]}, endpoints=[], tech_stack=[])

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng
    snap_a_result = MagicMock()
    snap_a_result.scalar_one_or_none.return_value = snap_a
    snap_b_result = MagicMock()
    snap_b_result.scalar_one_or_none.return_value = snap_b
    db.execute.side_effect = [eng_result, snap_a_result, snap_b_result]

    result = await get_snapshot_diff(
        engagement_id=eng.id,
        snapshot_a=snap_a.id,
        snapshot_b=snap_b.id,
        db=db,
        current_user=user,
    )

    assert "api.target.com" in result.new_ports
    assert 8080 in result.new_ports["api.target.com"]


@pytest.mark.asyncio
async def test_snapshot_diff_404_if_snapshot_a_missing():
    from fastapi import HTTPException
    user = _make_user()
    eng = _make_engagement(user.id)

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng
    snap_a_result = MagicMock()
    snap_a_result.scalar_one_or_none.return_value = None
    db.execute.side_effect = [eng_result, snap_a_result]

    with pytest.raises(HTTPException) as exc_info:
        await get_snapshot_diff(
            engagement_id=eng.id,
            snapshot_a=uuid4(),
            snapshot_b=uuid4(),
            db=db,
            current_user=user,
        )
    assert exc_info.value.status_code == 404


# ── get_monitoring_schedule ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_monitoring_schedule_returns_defaults():
    user = _make_user()
    eng = _make_engagement(user.id)  # monitoring_enabled=False, interval=24

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng
    db.execute.return_value = eng_result

    result = await get_monitoring_schedule(engagement_id=eng.id, db=db, current_user=user)

    assert result["enabled"] is False
    assert result["interval_hours"] == 24


@pytest.mark.asyncio
async def test_get_monitoring_schedule_returns_custom():
    user = _make_user()
    eng = _make_engagement(user.id)
    eng.monitoring_enabled = True
    eng.monitoring_interval_hours = 48

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng
    db.execute.return_value = eng_result

    result = await get_monitoring_schedule(engagement_id=eng.id, db=db, current_user=user)

    assert result["enabled"] is True
    assert result["interval_hours"] == 48


# ── set_monitoring_schedule ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_set_monitoring_schedule_persists():
    user = _make_user()
    eng = _make_engagement(user.id)

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng
    db.execute.return_value = eng_result

    body = MonitoringScheduleRequest(enabled=True, interval_hours=6)
    result = await set_monitoring_schedule(
        engagement_id=eng.id, body=body, db=db, current_user=user
    )

    assert result["updated"] is True
    assert eng.monitoring_enabled is True
    assert eng.monitoring_interval_hours == 6
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_set_monitoring_schedule_disable():
    user = _make_user()
    eng = _make_engagement(user.id)
    eng.monitoring_enabled = True

    db = AsyncMock()
    eng_result = MagicMock()
    eng_result.scalar_one_or_none.return_value = eng
    db.execute.return_value = eng_result

    body = MonitoringScheduleRequest(enabled=False, interval_hours=24)
    result = await set_monitoring_schedule(
        engagement_id=eng.id, body=body, db=db, current_user=user
    )

    assert result["enabled"] is False
    assert eng.monitoring_enabled is False
