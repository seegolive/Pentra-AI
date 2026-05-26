"""FastAPI dependency: get the current authenticated user from JWT Bearer token."""

from __future__ import annotations

from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_token
from app.db.base import get_db
from app.db.models import UserORM

_bearer = HTTPBearer(auto_error=False)

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> UserORM:
    if credentials is None:
        raise _CREDENTIALS_EXCEPTION
    try:
        payload = decode_token(credentials.credentials)
        user_id_str: str = payload.get("sub", "")
        if not user_id_str:
            raise _CREDENTIALS_EXCEPTION
        user_id = UUID(user_id_str)
    except (JWTError, ValueError):
        raise _CREDENTIALS_EXCEPTION

    result = await db.execute(select(UserORM).where(UserORM.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise _CREDENTIALS_EXCEPTION
    return user


async def get_current_admin(
    current_user: UserORM = Depends(get_current_user),
) -> UserORM:
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
    return current_user
