"""Tests for /api/v1/setup/* endpoints (Sprint 36).

Covers get_setup_status and initialize_platform without live DB or Ollama,
using mocked sessions and patched external calls.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.api.setup_router import (
    SetupInitRequest,
    SetupAdminConfig,
    get_setup_status,
    initialize_platform,
)
from app.db.models import UserORM


# ── Helpers ───────────────────────────────────────────────────────────────────

def _db_with_admin(admin_exists: bool):
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = uuid4() if admin_exists else None
    db.execute.return_value = result
    return db


def _full_init_db():
    """DB mock for initialize_platform: no admin exists + no username conflict."""
    db = AsyncMock()
    no_admin = MagicMock()
    no_admin.scalar_one_or_none.return_value = None
    no_conflict = MagicMock()
    no_conflict.scalar_one_or_none.return_value = None
    db.execute.side_effect = [no_admin, no_conflict]
    return db


# ── get_setup_status ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_setup_status_not_configured():
    db = _db_with_admin(False)

    with patch("app.api.setup_router._kb_record_count", return_value=0), \
         patch("app.api.setup_router._ollama_reachable", return_value=False):
        result = await get_setup_status(db=db)

    assert result.is_configured is False
    assert result.requires_setup is True
    assert result.kb_record_count == 0
    assert result.ollama_reachable is False


@pytest.mark.asyncio
async def test_setup_status_configured():
    db = _db_with_admin(True)

    with patch("app.api.setup_router._kb_record_count", return_value=8341), \
         patch("app.api.setup_router._ollama_reachable", return_value=True):
        result = await get_setup_status(db=db)

    assert result.is_configured is True
    assert result.requires_setup is False
    assert result.kb_record_count == 8341
    assert result.ollama_reachable is True


@pytest.mark.asyncio
async def test_setup_status_ollama_unreachable():
    db = _db_with_admin(True)

    with patch("app.api.setup_router._kb_record_count", return_value=100), \
         patch("app.api.setup_router._ollama_reachable", return_value=False):
        result = await get_setup_status(db=db)

    assert result.is_configured is True
    assert result.ollama_reachable is False


# ── initialize_platform ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_initialize_creates_admin():
    db = _full_init_db()

    config = SetupInitRequest(
        admin=SetupAdminConfig(username="admin", email="admin@pentra.local", password="securepass"),
        seed_knowledge=False,
    )
    result = await initialize_platform(config=config, db=db)

    assert result.success is True
    assert result.admin_username == "admin"
    db.add.assert_called_once()
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_initialize_blocked_if_admin_exists():
    from fastapi import HTTPException
    db = _db_with_admin(True)

    config = SetupInitRequest(
        admin=SetupAdminConfig(username="admin2", email="a2@pentra.local", password="securepass"),
        seed_knowledge=False,
    )
    with pytest.raises(HTTPException) as exc_info:
        await initialize_platform(config=config, db=db)

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_initialize_triggers_seed_knowledge():
    db = _full_init_db()

    config = SetupInitRequest(
        admin=SetupAdminConfig(username="admin", email="admin@pentra.local", password="securepass"),
        seed_knowledge=True,
    )
    mock_worker = MagicMock()
    mock_worker.send_task = MagicMock()
    with patch.dict("sys.modules", {"app.worker_client": mock_worker}):
        result = await initialize_platform(config=config, db=db)

    assert result.success is True


@pytest.mark.asyncio
async def test_initialize_username_conflict_returns_409():
    from fastapi import HTTPException
    db = AsyncMock()
    no_admin = MagicMock()
    no_admin.scalar_one_or_none.return_value = None
    conflicting_user = MagicMock()
    conflicting_user.scalar_one_or_none.return_value = MagicMock()
    db.execute.side_effect = [no_admin, conflicting_user]

    config = SetupInitRequest(
        admin=SetupAdminConfig(username="taken", email="taken@pentra.local", password="securepass"),
        seed_knowledge=False,
    )
    with pytest.raises(HTTPException) as exc_info:
        await initialize_platform(config=config, db=db)

    assert exc_info.value.status_code == 409
