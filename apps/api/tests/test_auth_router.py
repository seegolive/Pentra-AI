"""Tests for /api/v1/auth/* endpoints (Sprint 36).

Covers register, login, refresh, /me, change-password — all via mocked
DB and real JWT helpers (no live database).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.api.auth_router import (
    ChangePasswordRequest,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    change_password,
    get_me,
    login,
    refresh,
    register,
)
from app.core.security import create_refresh_token, hash_password
from app.db.models import UserORM


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_user(username="alice", password="hunter2!", is_active=True, is_admin=False) -> UserORM:
    u = UserORM()
    u.id = uuid4()
    u.username = username
    u.email = f"{username}@test.com"
    u.hashed_password = hash_password(password)
    u.is_active = is_active
    u.is_admin = is_admin
    return u


def _db_find_user(user: UserORM | None):
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = user
    db.execute.return_value = result
    return db


# ── register ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_creates_user():
    db = AsyncMock()
    no_existing = MagicMock()
    no_existing.scalar_one_or_none.return_value = None
    db.execute.return_value = no_existing
    db.refresh = AsyncMock(side_effect=lambda u: setattr(u, "id", uuid4()) or setattr(u, "is_admin", False))

    data = RegisterRequest(username="bob", email="bob@test.com", password="securepass")
    result = await register(data=data, db=db)

    assert result.username == "bob"
    assert result.email == "bob@test.com"
    db.add.assert_called_once()
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_register_conflict_returns_409():
    from fastapi import HTTPException
    existing_user = _make_user("alice")
    db = _db_find_user(existing_user)

    data = RegisterRequest(username="alice", email="alice@test.com", password="securepass")
    with pytest.raises(HTTPException) as exc_info:
        await register(data=data, db=db)

    assert exc_info.value.status_code == 409


# ── login ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_valid_credentials_returns_tokens():
    user = _make_user("alice", password="hunter2!")
    db = _db_find_user(user)

    result = await login(data=LoginRequest(username="alice", password="hunter2!"), db=db)

    assert result.access_token
    assert result.refresh_token
    assert result.token_type == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password_returns_401():
    from fastapi import HTTPException
    user = _make_user("alice", password="hunter2!")
    db = _db_find_user(user)

    with pytest.raises(HTTPException) as exc_info:
        await login(data=LoginRequest(username="alice", password="wrongpass"), db=db)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user_returns_401():
    from fastapi import HTTPException
    db = _db_find_user(None)

    with pytest.raises(HTTPException) as exc_info:
        await login(data=LoginRequest(username="ghost", password="hunter2!"), db=db)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_login_disabled_account_returns_403():
    from fastapi import HTTPException
    user = _make_user("alice", password="hunter2!", is_active=False)
    db = _db_find_user(user)

    with pytest.raises(HTTPException) as exc_info:
        await login(data=LoginRequest(username="alice", password="hunter2!"), db=db)
    assert exc_info.value.status_code == 403


# ── refresh ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_valid_token_returns_new_tokens():
    user = _make_user("alice")
    refresh_tok = create_refresh_token(user.id)
    db = _db_find_user(user)

    result = await refresh(data=RefreshRequest(refresh_token=refresh_tok), db=db)

    assert result.access_token
    assert result.refresh_token


@pytest.mark.asyncio
async def test_refresh_invalid_token_returns_401():
    from fastapi import HTTPException
    db = AsyncMock()

    with pytest.raises(HTTPException) as exc_info:
        await refresh(data=RefreshRequest(refresh_token="not.a.jwt"), db=db)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_refresh_access_token_rejected():
    """Passing an access token to /refresh should be rejected (wrong type)."""
    from fastapi import HTTPException
    from app.core.security import create_access_token
    user = _make_user("alice")
    access_tok = create_access_token(user.id, user.username)
    db = AsyncMock()

    with pytest.raises(HTTPException) as exc_info:
        await refresh(data=RefreshRequest(refresh_token=access_tok), db=db)
    assert exc_info.value.status_code == 401


# ── get_me ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_me_returns_user_info():
    user = _make_user("alice", is_admin=True)
    result = await get_me(current_user=user)

    assert result.username == "alice"
    assert result.email == "alice@test.com"
    assert result.is_admin is True
    assert result.id == str(user.id)


# ── change_password ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_change_password_valid():
    user = _make_user("alice", password="oldpass12")
    db = AsyncMock()

    await change_password(
        data=ChangePasswordRequest(current_password="oldpass12", new_password="newpass99"),
        db=db,
        current_user=user,
    )

    db.commit.assert_called_once()
    from app.core.security import verify_password
    assert verify_password("newpass99", user.hashed_password)


@pytest.mark.asyncio
async def test_change_password_wrong_current_returns_400():
    from fastapi import HTTPException
    user = _make_user("alice", password="oldpass12")
    db = AsyncMock()

    with pytest.raises(HTTPException) as exc_info:
        await change_password(
            data=ChangePasswordRequest(current_password="wrongold", new_password="newpass99"),
            db=db,
            current_user=user,
        )
    assert exc_info.value.status_code == 400
