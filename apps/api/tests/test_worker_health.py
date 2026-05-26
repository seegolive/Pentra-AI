"""Tests for worker health endpoint (Sprint 6.1).

Tests cover the helper functions and response schema validation
without requiring a live Celery/Redis connection.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from app.api.worker_health_router import (
    ActiveTask,
    WorkerHealthResponse,
    WorkerStats,
    _parse_active_task,
    _parse_worker,
    _safe_inspect,
)
from app.db.models import UserORM


# ── Helper factories ──────────────────────────────────────────────────────────

def _make_admin_user() -> UserORM:
    u = UserORM()
    u.id = uuid4()
    u.username = "admin"
    u.email = "admin@pentra.test"
    u.hashed_password = "hashed"
    u.is_active = True
    u.is_admin = True
    return u


def _stat_payload(pid: int = 1234, concurrency: int = 4, queues: list[str] | None = None) -> dict:
    queues = queues or ["default"]
    return {
        "pid": pid,
        "pool": {
            "max-concurrency": concurrency,
            "implementation": "billiard.pool.Pool",
            "processes": list(range(1000, 1000 + concurrency)),
        },
        "consumer": {
            "queues": [{"name": q} for q in queues],
        },
        "total": {"total": 42},
    }


def _active_task_payload(task_id: str = "abc-123") -> dict:
    return {
        "id": task_id,
        "name": "app.tasks.run_nuclei",
        "time_start": 1717171717.0,
        "kwargs": {"target": "target.com"},
    }


# ── _parse_worker ─────────────────────────────────────────────────────────────

def test_parse_worker_extracts_hostname():
    stat = _stat_payload()
    result = _parse_worker("celery@worker1", stat, [], [])
    assert result.hostname == "celery@worker1"
    assert result.status == "online"


def test_parse_worker_extracts_pid():
    stat = _stat_payload(pid=9999)
    result = _parse_worker("celery@worker1", stat, [], [])
    assert result.pid == 9999


def test_parse_worker_extracts_concurrency():
    stat = _stat_payload(concurrency=8)
    result = _parse_worker("celery@worker1", stat, [], [])
    assert result.concurrency == 8


def test_parse_worker_extracts_queues():
    stat = _stat_payload(queues=["default", "knowledge"])
    result = _parse_worker("celery@worker1", stat, [], [])
    assert "default" in result.queues
    assert "knowledge" in result.queues


def test_parse_worker_counts_active_tasks():
    stat = _stat_payload()
    active = [_active_task_payload("t1"), _active_task_payload("t2")]
    result = _parse_worker("celery@worker1", stat, active, [])
    assert result.active_tasks == 2


def test_parse_worker_counts_reserved_tasks():
    stat = _stat_payload()
    reserved = [_active_task_payload("r1")]
    result = _parse_worker("celery@worker1", stat, [], reserved)
    assert result.reserved_tasks == 1


# ── _parse_active_task ────────────────────────────────────────────────────────

def test_parse_active_task_extracts_id_and_name():
    payload = _active_task_payload("task-xyz")
    result = _parse_active_task(payload, "celery@worker1")
    assert result.id == "task-xyz"
    assert result.name == "app.tasks.run_nuclei"


def test_parse_active_task_extracts_worker():
    payload = _active_task_payload()
    result = _parse_active_task(payload, "celery@worker2")
    assert result.worker == "celery@worker2"


def test_parse_active_task_converts_timestamp():
    payload = _active_task_payload()
    result = _parse_active_task(payload, "celery@worker1")
    # started_at should be an ISO 8601 string
    assert result.started_at is not None
    assert "T" in result.started_at  # ISO 8601 format contains T separator


def test_parse_active_task_handles_missing_time_start():
    payload = {"id": "t1", "name": "some.task", "kwargs": {}}
    result = _parse_active_task(payload, "celery@worker1")
    assert result.started_at is None


# ── _safe_inspect ─────────────────────────────────────────────────────────────

def test_safe_inspect_returns_empty_on_exception():
    """If Celery/Redis is unreachable, _safe_inspect returns empty dicts."""
    with patch("app.api.worker_health_router._get_celery", side_effect=Exception("Redis down")):
        stats, active, reserved = _safe_inspect(timeout=0.1)
    assert stats == {}
    assert active == {}
    assert reserved == {}


def test_safe_inspect_returns_data_when_workers_online():
    """_safe_inspect returns inspect data from all connected workers."""
    mock_app = MagicMock()
    mock_inspect = MagicMock()
    mock_inspect.stats.return_value = {"celery@worker1": _stat_payload()}
    mock_inspect.active.return_value = {"celery@worker1": []}
    mock_inspect.reserved.return_value = {"celery@worker1": []}
    mock_app.control.inspect.return_value = mock_inspect

    with patch("app.api.worker_health_router._get_celery", return_value=mock_app):
        stats, active, reserved = _safe_inspect(timeout=1.0)

    assert "celery@worker1" in stats
    assert "celery@worker1" in active
    assert "celery@worker1" in reserved


def test_safe_inspect_handles_none_stats():
    """_safe_inspect handles None returns from inspect (no workers)."""
    mock_app = MagicMock()
    mock_inspect = MagicMock()
    mock_inspect.stats.return_value = None
    mock_inspect.active.return_value = None
    mock_inspect.reserved.return_value = None
    mock_app.control.inspect.return_value = mock_inspect

    with patch("app.api.worker_health_router._get_celery", return_value=mock_app):
        stats, active, reserved = _safe_inspect(timeout=1.0)

    assert stats == {}
    assert active == {}
    assert reserved == {}


# ── WorkerHealthResponse schema ────────────────────────────────────────────────

def test_worker_health_response_healthy_true_when_workers_present():
    resp = WorkerHealthResponse(
        healthy=True,
        workers=[
            WorkerStats(
                hostname="celery@worker1",
                status="online",
                pid=1234,
                concurrency=4,
                queues=["default"],
                active_tasks=0,
                reserved_tasks=0,
            )
        ],
        active_tasks=[],
        scheduled_tasks=0,
        checked_at=datetime.now(timezone.utc).isoformat(),
    )
    assert resp.healthy is True
    assert len(resp.workers) == 1
    assert resp.workers[0].hostname == "celery@worker1"


def test_worker_health_response_healthy_false_when_no_workers():
    resp = WorkerHealthResponse(
        healthy=False,
        workers=[],
        active_tasks=[],
        scheduled_tasks=0,
        checked_at=datetime.now(timezone.utc).isoformat(),
    )
    assert resp.healthy is False
    assert resp.workers == []


def test_worker_health_response_includes_active_tasks():
    task = ActiveTask(
        id="t1",
        name="app.tasks.run_subfinder",
        worker="celery@worker1",
        started_at="2024-06-01T10:00:00+00:00",
        kwargs={"domain": "target.com"},
    )
    resp = WorkerHealthResponse(
        healthy=True,
        workers=[],
        active_tasks=[task],
        scheduled_tasks=2,
        checked_at=datetime.now(timezone.utc).isoformat(),
    )
    assert len(resp.active_tasks) == 1
    assert resp.active_tasks[0].id == "t1"
    assert resp.scheduled_tasks == 2


# ── Full handler logic test ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_worker_health_returns_healthy_when_workers_online():
    """Handler returns healthy=True and populates workers list."""
    from app.api.worker_health_router import get_worker_health

    mock_stats = {"celery@worker1": _stat_payload()}
    mock_active = {"celery@worker1": [_active_task_payload()]}
    mock_reserved = {"celery@worker1": []}

    admin = _make_admin_user()

    with patch(
        "app.api.worker_health_router._safe_inspect",
        return_value=(mock_stats, mock_active, mock_reserved),
    ):
        result = await get_worker_health(current_user=admin)

    assert result.healthy is True
    assert len(result.workers) == 1
    assert result.workers[0].hostname == "celery@worker1"
    assert len(result.active_tasks) == 1
    assert result.active_tasks[0].name == "app.tasks.run_nuclei"


@pytest.mark.asyncio
async def test_get_worker_health_returns_unhealthy_when_no_workers():
    """Handler returns healthy=False and empty workers list when no workers respond."""
    from app.api.worker_health_router import get_worker_health

    admin = _make_admin_user()

    with patch(
        "app.api.worker_health_router._safe_inspect",
        return_value=({}, {}, {}),
    ):
        result = await get_worker_health(current_user=admin)

    assert result.healthy is False
    assert result.workers == []
    assert result.active_tasks == []
    assert result.scheduled_tasks == 0


@pytest.mark.asyncio
async def test_get_worker_health_scheduled_tasks_count():
    """Handler sums reserved tasks from all workers for scheduled_tasks field."""
    from app.api.worker_health_router import get_worker_health

    admin = _make_admin_user()

    mock_stats = {
        "celery@worker1": _stat_payload(),
        "celery@worker2": _stat_payload(),
    }
    mock_active = {"celery@worker1": [], "celery@worker2": []}
    mock_reserved = {
        "celery@worker1": [_active_task_payload("r1"), _active_task_payload("r2")],
        "celery@worker2": [_active_task_payload("r3")],
    }

    with patch(
        "app.api.worker_health_router._safe_inspect",
        return_value=(mock_stats, mock_active, mock_reserved),
    ):
        result = await get_worker_health(current_user=admin)

    assert result.scheduled_tasks == 3  # 2 + 1


@pytest.mark.asyncio
async def test_get_worker_health_checked_at_is_iso_format():
    """checked_at field should be a valid ISO 8601 timestamp."""
    from app.api.worker_health_router import get_worker_health

    admin = _make_admin_user()

    with patch(
        "app.api.worker_health_router._safe_inspect",
        return_value=({}, {}, {}),
    ):
        result = await get_worker_health(current_user=admin)

    # Should not raise
    dt = datetime.fromisoformat(result.checked_at)
    assert dt.tzinfo is not None  # timezone-aware
