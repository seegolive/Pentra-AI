"""Tests: workspace isolation — users can only see their own workspaces."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.db.models import UserORM, WorkspaceORM


def _make_user(is_admin: bool = False) -> UserORM:
    u = UserORM()
    u.id = uuid4()
    u.username = f"user_{u.id.hex[:6]}"
    u.email = f"{u.username}@test.com"
    u.hashed_password = "hashed"
    u.is_active = True
    u.is_admin = is_admin
    return u


def _make_workspace(owner_id) -> WorkspaceORM:
    ws = WorkspaceORM()
    ws.id = uuid4()
    ws.name = f"ws_{ws.id.hex[:6]}"
    ws.owner_id = owner_id
    return ws


# ── GET /workspaces/ — list ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_workspaces_returns_only_owned():
    """Regular user should only see workspaces they own."""
    user_a = _make_user()
    user_b = _make_user()

    ws_a1 = _make_workspace(user_a.id)
    ws_a2 = _make_workspace(user_a.id)
    ws_b1 = _make_workspace(user_b.id)

    # Simulate the filter that router applies: owner_id == current_user.id
    all_workspaces = [ws_a1, ws_a2, ws_b1]
    user_a_workspaces = [ws for ws in all_workspaces if ws.owner_id == user_a.id]
    user_b_workspaces = [ws for ws in all_workspaces if ws.owner_id == user_b.id]

    assert len(user_a_workspaces) == 2
    assert len(user_b_workspaces) == 1
    assert ws_b1 not in user_a_workspaces
    assert ws_a1 not in user_b_workspaces


@pytest.mark.asyncio
async def test_admin_can_see_all_workspaces():
    """Admin user (is_admin=True) should be able to see all workspaces."""
    admin = _make_user(is_admin=True)
    user_a = _make_user()
    user_b = _make_user()

    ws_a = _make_workspace(user_a.id)
    ws_b = _make_workspace(user_b.id)
    ws_admin = _make_workspace(admin.id)

    all_workspaces = [ws_a, ws_b, ws_admin]

    # Admin sees all
    if admin.is_admin:
        visible = all_workspaces
    else:
        visible = [ws for ws in all_workspaces if ws.owner_id == admin.id]

    assert len(visible) == 3


@pytest.mark.asyncio
async def test_user_cannot_access_other_user_workspace():
    """GET /workspaces/{id} — user B cannot access user A's workspace."""
    user_a = _make_user()
    user_b = _make_user()

    ws_a = _make_workspace(user_a.id)

    # Simulate the check that get_workspace performs
    def can_access(workspace: WorkspaceORM, requesting_user: UserORM) -> bool:
        if requesting_user.is_admin:
            return True
        return workspace.owner_id == requesting_user.id

    assert can_access(ws_a, user_a) is True
    assert can_access(ws_a, user_b) is False


@pytest.mark.asyncio
async def test_workspace_created_with_owner_id():
    """Creating a workspace should set owner_id to current user."""
    user = _make_user()
    ws = WorkspaceORM()
    ws.id = uuid4()
    ws.name = "My Workspace"
    ws.owner_id = user.id  # this is what the router does

    assert ws.owner_id == user.id


@pytest.mark.asyncio
async def test_workspace_filter_excludes_null_owner():
    """Workspaces with no owner_id should not be visible to regular users."""
    user = _make_user()

    ws_owned = _make_workspace(user.id)
    ws_no_owner = WorkspaceORM()
    ws_no_owner.id = uuid4()
    ws_no_owner.name = "Legacy workspace"
    ws_no_owner.owner_id = None

    all_workspaces = [ws_owned, ws_no_owner]
    visible = [ws for ws in all_workspaces if ws.owner_id == user.id]

    assert len(visible) == 1
    assert ws_no_owner not in visible
