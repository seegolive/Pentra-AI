"""Tests for workspace CRUD handlers.

These call the FastAPI handler functions directly with mocked DB sessions,
matching the existing API test style in this repository.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.router import create_workspace, get_workspace, list_workspaces
from app.api.schemas import WorkspaceCreate
from app.db.models import UserORM, WorkspaceORM


def _make_user(is_admin: bool = False) -> UserORM:
    user = UserORM()
    user.id = uuid4()
    user.username = f"user_{user.id.hex[:6]}"
    user.email = f"{user.username}@test.local"
    user.hashed_password = "hashed"
    user.is_active = True
    user.is_admin = is_admin
    return user


def _make_workspace(owner_id, name: str = "Acme") -> WorkspaceORM:
    now = datetime.now(timezone.utc)
    ws = WorkspaceORM()
    ws.id = uuid4()
    ws.name = name
    ws.description = "Security work"
    ws.owner_id = owner_id
    ws.created_at = now
    ws.updated_at = now
    return ws


def _db_with_scalars(items: list[object]) -> AsyncMock:
    db = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    db.execute.return_value = result
    return db


@pytest.mark.asyncio
async def test_create_workspace_sets_owner_and_persists():
    user = _make_user()
    db = AsyncMock()
    db.add = MagicMock()

    async def refresh_side_effect(ws: WorkspaceORM) -> None:
        now = datetime.now(timezone.utc)
        ws.id = uuid4()
        ws.created_at = now
        ws.updated_at = now

    db.refresh = AsyncMock(side_effect=refresh_side_effect)

    result = await create_workspace(
        data=WorkspaceCreate(name="Client A", description="External test"),
        db=db,
        current_user=user,
    )

    db.add.assert_called_once()
    created = db.add.call_args.args[0]
    assert created.name == "Client A"
    assert created.description == "External test"
    assert created.owner_id == user.id
    db.commit.assert_called_once()
    assert result.name == "Client A"
    assert result.owner_id == user.id


@pytest.mark.asyncio
async def test_list_workspaces_returns_model_responses():
    user = _make_user()
    ws = _make_workspace(user.id, name="Owned Workspace")
    db = _db_with_scalars([ws])

    result = await list_workspaces(db=db, current_user=user)

    assert len(result) == 1
    assert result[0].id == ws.id
    assert result[0].name == "Owned Workspace"
    db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_get_workspace_returns_owned_workspace():
    user = _make_user()
    ws = _make_workspace(user.id)
    db = AsyncMock()
    db.get = AsyncMock(return_value=ws)

    result = await get_workspace(workspace_id=ws.id, db=db, current_user=user)

    assert result.id == ws.id
    assert result.owner_id == user.id


@pytest.mark.asyncio
async def test_get_workspace_returns_404_when_missing():
    user = _make_user()
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)

    with pytest.raises(HTTPException) as exc_info:
        await get_workspace(workspace_id=uuid4(), db=db, current_user=user)

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_get_workspace_denies_non_owner():
    owner = _make_user()
    other = _make_user()
    ws = _make_workspace(owner.id)
    db = AsyncMock()
    db.get = AsyncMock(return_value=ws)

    with pytest.raises(HTTPException) as exc_info:
        await get_workspace(workspace_id=ws.id, db=db, current_user=other)

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_get_workspace_allows_admin_for_any_owner():
    owner = _make_user()
    admin = _make_user(is_admin=True)
    ws = _make_workspace(owner.id)
    db = AsyncMock()
    db.get = AsyncMock(return_value=ws)

    result = await get_workspace(workspace_id=ws.id, db=db, current_user=admin)

    assert result.id == ws.id
    assert result.owner_id == owner.id
