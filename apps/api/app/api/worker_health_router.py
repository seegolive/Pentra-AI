"""Worker health monitoring — GET /api/v1/admin/worker/health

Returns live status of the Celery worker pool via Redis inspect.
Admin-only endpoint.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.deps import get_current_admin
from app.db.models import UserORM
from app.worker_client import _get_celery

router = APIRouter(prefix="/api/v1/admin/worker", tags=["admin-worker"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class WorkerStats(BaseModel):
    hostname: str
    status: str                         # "online" | "offline"
    pid: int | None = None
    concurrency: int | None = None
    queues: list[str] = []
    active_tasks: int = 0
    reserved_tasks: int = 0
    total_tasks_executed: int | None = None
    pool: str | None = None


class ActiveTask(BaseModel):
    id: str
    name: str
    worker: str
    started_at: str | None = None
    kwargs: dict = {}


class WorkerHealthResponse(BaseModel):
    healthy: bool
    workers: list[WorkerStats]
    active_tasks: list[ActiveTask]
    scheduled_tasks: int
    checked_at: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_inspect(timeout: float = 3.0) -> tuple[dict, dict, dict]:
    """
    Run Celery inspect commands against all connected workers.
    Returns (stats, active, reserved) dicts keyed by worker hostname.
    Falls back to empty dicts if the broker is unreachable.
    """
    try:
        app = _get_celery()
        i = app.control.inspect(timeout=timeout)
        stats = i.stats() or {}
        active = i.active() or {}
        reserved = i.reserved() or {}
        return stats, active, reserved
    except Exception:  # noqa: BLE001
        return {}, {}, {}


def _parse_worker(
    hostname: str,
    stat: dict[str, Any],
    active: list[dict],
    reserved: list[dict],
) -> WorkerStats:
    pool = stat.get("pool", {})
    queues = [q.get("name", "") for q in stat.get("consumer", {}).get("queues", [])]
    return WorkerStats(
        hostname=hostname,
        status="online",
        pid=stat.get("pid"),
        concurrency=pool.get("max-concurrency") or pool.get("processes") and len(pool.get("processes", [])),
        queues=queues,
        active_tasks=len(active),
        reserved_tasks=len(reserved),
        total_tasks_executed=stat.get("total", {}).get("total") if isinstance(stat.get("total"), dict) else None,
        pool=pool.get("implementation", "").split(".")[-1] or None,
    )


def _parse_active_task(task: dict[str, Any], worker: str) -> ActiveTask:
    return ActiveTask(
        id=task.get("id", ""),
        name=task.get("name", ""),
        worker=worker,
        started_at=task.get("time_start") and datetime.fromtimestamp(
            task["time_start"], tz=timezone.utc
        ).isoformat(),
        kwargs=task.get("kwargs") or {},
    )


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("/health", response_model=WorkerHealthResponse, summary="Worker health", description="Return health status of background workers, Celery beat, and scheduled task queue depth.")
async def get_worker_health(
    current_user: UserORM = Depends(get_current_admin),
) -> WorkerHealthResponse:
    """
    Return live health status of all connected Celery workers.

    - Uses Celery broadcast inspect with a 3s timeout.
    - If no workers respond, `healthy=False` with empty workers list.
    """
    stats, active_map, reserved_map = _safe_inspect(timeout=3.0)

    workers: list[WorkerStats] = []
    all_active_tasks: list[ActiveTask] = []

    for hostname, stat in stats.items():
        active = active_map.get(hostname, [])
        reserved = reserved_map.get(hostname, [])
        workers.append(_parse_worker(hostname, stat, active, reserved))
        for task in active:
            all_active_tasks.append(_parse_active_task(task, hostname))

    total_scheduled = sum(len(v) for v in reserved_map.values())

    return WorkerHealthResponse(
        healthy=len(workers) > 0,
        workers=workers,
        active_tasks=all_active_tasks,
        scheduled_tasks=total_scheduled,
        checked_at=datetime.now(timezone.utc).isoformat(),
    )
