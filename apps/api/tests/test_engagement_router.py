"""Tests for engagement CRUD and control handlers."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.router import (
    create_engagement,
    get_engagement,
    list_engagements,
    run_subscan,
    start_engagement,
    stop_engagement,
    update_engagement_mode,
)
from app.api.schemas import EngagementCreate, SubscanRequest
from app.db.models import EngagementORM, UserORM, WorkspaceORM


def _make_user(is_admin: bool = False) -> UserORM:
    user = UserORM()
    user.id = uuid4()
    user.username = f"user_{user.id.hex[:6]}"
    user.email = f"{user.username}@test.local"
    user.hashed_password = "hashed"
    user.is_active = True
    user.is_admin = is_admin
    return user


def _make_workspace(owner_id) -> WorkspaceORM:
    now = datetime.now(timezone.utc)
    ws = WorkspaceORM()
    ws.id = uuid4()
    ws.name = "Client Workspace"
    ws.description = None
    ws.owner_id = owner_id
    ws.created_at = now
    ws.updated_at = now
    return ws


def _make_engagement(workspace_id, user_id, status: str = "planning") -> EngagementORM:
    now = datetime.now(timezone.utc)
    eng = EngagementORM()
    eng.id = uuid4()
    eng.workspace_id = workspace_id
    eng.name = "Acme Scan"
    eng.description = "API scope"
    eng.mode = "semi_auto"
    eng.status = status
    eng.in_scope = ["acme.test"]
    eng.out_of_scope = []
    eng.llm_model = "qwen2.5-coder:7b"
    eng.langgraph_thread_id = str(eng.id)
    eng.opsec_mode = False
    eng.request_jitter_ms = 0
    eng.created_by = user_id
    eng.created_at = now
    eng.updated_at = now
    eng.started_at = None
    eng.completed_at = None
    return eng


def _engagement_create(workspace_id) -> EngagementCreate:
    return EngagementCreate(
        workspace_id=workspace_id,
        name="Acme Scan",
        description="API scope",
        mode="semi_auto",
        in_scope=["acme.test"],
        out_of_scope=["admin.acme.test"],
        llm_model="qwen2.5-coder:7b",
        opsec_mode=True,
        request_jitter_ms=250,
    )


def _db_with_scalars(items: list[object]) -> AsyncMock:
    db = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    db.execute.return_value = result
    return db


@pytest.mark.asyncio
async def test_create_engagement_persists_thread_id_equal_engagement_id():
    user = _make_user()
    ws = _make_workspace(user.id)
    db = AsyncMock()
    db.add = MagicMock()
    db.get = AsyncMock(return_value=ws)

    async def refresh_side_effect(eng: EngagementORM) -> None:
        now = datetime.now(timezone.utc)
        eng.status = "planning"
        eng.created_at = now
        eng.updated_at = now
        eng.started_at = None
        eng.completed_at = None

    db.refresh = AsyncMock(side_effect=refresh_side_effect)

    result = await create_engagement(
        data=_engagement_create(ws.id),
        db=db,
        current_user=user,
    )

    db.add.assert_called_once()
    created = db.add.call_args.args[0]
    assert created.workspace_id == ws.id
    assert created.created_by == user.id
    assert created.langgraph_thread_id == str(created.id)
    assert created.in_scope == ["acme.test"]
    assert result.langgraph_thread_id == str(result.id)
    assert result.opsec_mode is True


@pytest.mark.asyncio
async def test_create_engagement_returns_404_for_missing_workspace():
    user = _make_user()
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)

    with pytest.raises(HTTPException) as exc_info:
        await create_engagement(
            data=_engagement_create(uuid4()),
            db=db,
            current_user=user,
        )

    assert exc_info.value.status_code == 404
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_list_engagements_returns_responses():
    user = _make_user()
    ws = _make_workspace(user.id)
    eng = _make_engagement(ws.id, user.id, status="active")
    db = _db_with_scalars([eng])

    result = await list_engagements(
        workspace_id=ws.id,
        limit=5,
        db=db,
        current_user=user,
    )

    assert len(result) == 1
    assert result[0].id == eng.id
    assert result[0].status == "active"
    db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_get_engagement_returns_404_when_missing():
    user = _make_user()
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)

    with pytest.raises(HTTPException) as exc_info:
        await get_engagement(engagement_id=uuid4(), db=db, current_user=user)

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_start_engagement_rejects_non_planning_status():
    user = _make_user()
    eng = _make_engagement(uuid4(), user.id, status="active")
    db = AsyncMock()
    db.get = AsyncMock(return_value=eng)

    with pytest.raises(HTTPException) as exc_info:
        await start_engagement(engagement_id=eng.id, db=db, current_user=user)

    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_start_engagement_marks_active_and_launches_task():
    user = _make_user()
    eng = _make_engagement(uuid4(), user.id, status="planning")
    db = AsyncMock()
    db.add = MagicMock()
    db.get = AsyncMock(return_value=eng)
    fake_task = MagicMock()
    fake_task.add_done_callback = MagicMock()

    with patch("app.api.router._run_agent", new=AsyncMock()), patch(
        "app.api.router.asyncio.create_task", return_value=fake_task
    ) as create_task:
        result = await start_engagement(engagement_id=eng.id, db=db, current_user=user)

    assert result == {"status": "started", "engagement_id": str(eng.id)}
    assert eng.status == "active"
    assert eng.started_at is not None
    assert db.commit.call_count == 2
    create_task.assert_called_once()
    fake_task.add_done_callback.assert_called_once()


@pytest.mark.asyncio
async def test_update_engagement_mode_validates_mode():
    user = _make_user()
    db = AsyncMock()

    with pytest.raises(HTTPException) as exc_info:
        await update_engagement_mode(
            engagement_id=uuid4(),
            body={"mode": "manual"},
            db=db,
            current_user=user,
        )

    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_stop_engagement_denies_non_owner():
    owner = _make_user()
    other = _make_user()
    eng = _make_engagement(uuid4(), owner.id, status="active")
    db = AsyncMock()
    db.get = AsyncMock(return_value=eng)

    with pytest.raises(HTTPException) as exc_info:
        await stop_engagement(engagement_id=eng.id, db=db, current_user=other)

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_stop_engagement_returns_existing_status_for_completed():
    user = _make_user()
    eng = _make_engagement(uuid4(), user.id, status="completed")
    db = AsyncMock()
    db.get = AsyncMock(return_value=eng)

    result = await stop_engagement(engagement_id=eng.id, db=db, current_user=user)

    assert result == {"status": "completed", "message": "Engagement already finished"}
    db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_stop_engagement_cancels_active_task_and_broadcasts():
    user = _make_user()
    eng = _make_engagement(uuid4(), user.id, status="active")
    db = AsyncMock()
    db.add = MagicMock()
    db.get = AsyncMock(return_value=eng)
    fake_task = MagicMock()
    fake_task.done.return_value = False
    broadcast_calls = []

    async def fake_broadcast(engagement_id: str, payload: dict) -> None:
        broadcast_calls.append((engagement_id, payload))

    with patch.dict("app.api.router._active_tasks", {str(eng.id): fake_task}, clear=True), patch(
        "app.api.router.ws_manager.broadcast", new=fake_broadcast
    ):
        result = await stop_engagement(engagement_id=eng.id, db=db, current_user=user)

    assert result["status"] == "cancelled"
    assert eng.status == "cancelled"
    fake_task.cancel.assert_called_once()
    assert len(broadcast_calls) == 1
    assert broadcast_calls[0][0] == str(eng.id)
    assert broadcast_calls[0][1]["type"] == "agent_cancelled"
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_run_subscan_queues_worker_task_and_audit_log():
    user = _make_user()
    eng = _make_engagement(uuid4(), user.id, status="active")
    db = AsyncMock()
    db.add = MagicMock()
    db.get = AsyncMock(return_value=eng)

    send_task = MagicMock(return_value="task-123")
    worker_client = SimpleNamespace(send_task=send_task)
    with patch.dict("sys.modules", {"app.worker_client": worker_client}):
        result = await run_subscan(
            engagement_id=eng.id,
            body=SubscanRequest(target_urls=["https://acme.test/login"]),
            db=db,
            current_user=user,
        )

    assert result == {"task_id": "task-123", "status": "queued"}
    send_task.assert_called_once_with(
        "app.tasks.agent.run_subscan",
        kwargs={
            "engagement_id": str(eng.id),
            "target_urls": ["https://acme.test/login"],
        },
    )
    db.add.assert_called_once()
    db.commit.assert_called_once()
