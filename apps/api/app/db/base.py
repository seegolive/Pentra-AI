"""Shared SQLAlchemy declarative base and async session factory for apps/api.

This is separate from the pentra-knowledge Base so each package owns its
own table namespace, even though both connect to the same PostgreSQL database.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

_DEFAULT_URL = "postgresql+asyncpg://pentra:pentra@localhost:5432/pentra"


class Base(DeclarativeBase):
    """Declarative base for all apps/api ORM models."""


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        url = os.getenv("DATABASE_URL", _DEFAULT_URL)
        _engine = create_async_engine(url, echo=False, pool_pre_ping=True, pool_size=5)
    return _engine


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=_get_engine(),
            expire_on_commit=False,
            class_=AsyncSession,
        )
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async DB session."""
    factory = _get_session_factory()
    async with factory() as session:
        yield session
