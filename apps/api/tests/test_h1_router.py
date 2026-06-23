"""Tests for /api/v1/h1/* endpoints (Sprint 36).

Covers get_h1_program_scope — input validation, successful fetch,
404 on unknown program, 502 on network failure.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.api.h1_router import get_h1_program_scope
from app.db.models import UserORM


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_user() -> UserORM:
    u = UserORM()
    u.id = uuid4()
    u.username = "hunter"
    u.email = "hunter@test.com"
    u.hashed_password = "x"
    u.is_active = True
    u.is_admin = False
    return u


def _mock_sync(program_name="Shopify", in_scope=None, out_of_scope=None, notes=None):
    from pentra_knowledge.services.h1_program_sync import H1ProgramScope, H1ProgramSync

    h1_scope = MagicMock()
    h1_scope.program_name = program_name
    h1_scope.program_url = f"https://hackerone.com/{program_name.lower()}"
    h1_scope.in_scope = in_scope or [MagicMock(asset_type="URL", value="*.shopify.com")]
    h1_scope.out_of_scope = out_of_scope or []

    eng_scope = MagicMock()
    eng_scope.in_scope = ["*.shopify.com"]
    eng_scope.out_of_scope = []
    eng_scope.notes = notes or []

    syncer = MagicMock(spec=H1ProgramSync)
    syncer.fetch_program_scope = AsyncMock(return_value=h1_scope)
    syncer.convert_to_engagement_scope = MagicMock(return_value=eng_scope)
    return syncer


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_h1_scope_returns_scope_data():
    user = _make_user()
    mock_syncer = _mock_sync(program_name="Shopify")

    with patch("pentra_knowledge.services.h1_program_sync.H1ProgramSync", return_value=mock_syncer):
        result = await get_h1_program_scope(handle="shopify", _=user)

    assert result["program_name"] == "Shopify"
    assert "*.shopify.com" in result["in_scope"]
    assert result["out_of_scope"] == []
    assert "raw_in_scope_count" in result


@pytest.mark.asyncio
async def test_h1_scope_invalid_handle_returns_422():
    from fastapi import HTTPException
    user = _make_user()

    with pytest.raises(HTTPException) as exc_info:
        await get_h1_program_scope(handle="bad handle!!", _=user)
    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_h1_scope_unknown_program_returns_404():
    from fastapi import HTTPException
    user = _make_user()

    mock_syncer = MagicMock()
    mock_syncer.fetch_program_scope = AsyncMock(side_effect=ValueError("Program not found"))

    with patch("pentra_knowledge.services.h1_program_sync.H1ProgramSync", return_value=mock_syncer):
        with pytest.raises(HTTPException) as exc_info:
            await get_h1_program_scope(handle="nonexistent-prog", _=user)
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_h1_scope_network_error_returns_502():
    from fastapi import HTTPException
    user = _make_user()

    mock_syncer = MagicMock()
    mock_syncer.fetch_program_scope = AsyncMock(side_effect=Exception("Connection timeout"))

    with patch("pentra_knowledge.services.h1_program_sync.H1ProgramSync", return_value=mock_syncer):
        with pytest.raises(HTTPException) as exc_info:
            await get_h1_program_scope(handle="shopify", _=user)
    assert exc_info.value.status_code == 502


@pytest.mark.asyncio
async def test_h1_scope_counts_raw_assets():
    user = _make_user()
    in_scope_items = [MagicMock()] * 5
    out_scope_items = [MagicMock()] * 2
    mock_syncer = _mock_sync(in_scope=in_scope_items, out_of_scope=out_scope_items)

    with patch("pentra_knowledge.services.h1_program_sync.H1ProgramSync", return_value=mock_syncer):
        result = await get_h1_program_scope(handle="shopify", _=user)

    assert result["raw_in_scope_count"] == 5
    assert result["raw_out_of_scope_count"] == 2


@pytest.mark.asyncio
async def test_h1_scope_handle_with_hyphen_and_underscore():
    """Handles like 'my-program_123' should be accepted."""
    user = _make_user()
    mock_syncer = _mock_sync()

    with patch("pentra_knowledge.services.h1_program_sync.H1ProgramSync", return_value=mock_syncer):
        result = await get_h1_program_scope(handle="my-program_123", _=user)

    assert "program_name" in result
