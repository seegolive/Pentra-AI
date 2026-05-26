"""Startup validation — run once on application boot.

Validates all required environment variables and connectivity to external
services (PostgreSQL, Redis, Qdrant, Ollama, MinIO).  Exits the process
with a clear error message if any required dependency is unavailable so
that misconfiguration is surfaced immediately rather than causing obscure
runtime failures.

Usage in main.py lifespan:
    from app.core.startup import StartupValidator

    async with lifespan(app):
        validator = StartupValidator()
        await validator.validate_all()
        ...
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import httpx
from sqlalchemy import text

from app.core.config import get_api_settings

if TYPE_CHECKING:
    pass

_DANGEROUS_SECRET_VALUES = {"changeme", "secret", "pentra", "password", "admin"}
_MIN_SECRET_KEY_LENGTH = 32


class StartupValidator:
    """Validates environment and connectivity before the app accepts traffic.

    Errors are collected (not raised immediately) so the operator sees all
    problems at once, then the process exits.  Warnings are non-fatal — the
    app continues but the operator is informed.
    """

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    # ── Public entry point ────────────────────────────────────────────────────

    async def validate_all(self) -> None:
        """Run all checks.  Exits the process if any error is found."""
        settings = get_api_settings()

        self._validate_env_vars(settings)
        await self._validate_database(settings)
        await self._validate_redis(settings)
        await self._validate_qdrant(settings)
        await self._validate_ollama(settings)
        self._validate_burp_optional(settings)

        if self.warnings:
            print("\n⚠️  Pentra AI startup warnings (non-fatal):\n")
            for warn in self.warnings:
                print(f"  • {warn}")

        if self.errors:
            print("\n❌ STARTUP FAILED — fix the issues below and restart:\n")
            for err in self.errors:
                print(f"  • {err}")
            print(
                "\nCheck your .env file (apps/api/.env) and try again.\n"
                "See apps/api/.env.example for reference.\n"
            )
            sys.exit(1)

        print("✅ Pentra AI startup validation passed")

    # ── Environment variables ─────────────────────────────────────────────────

    def _validate_env_vars(self, settings) -> None:  # type: ignore[no-untyped-def]
        required_attrs = [
            ("database_url", "DATABASE_URL"),
            ("redis_url", "REDIS_URL"),
            ("qdrant_url", "QDRANT_URL"),
            ("ollama_url", "OLLAMA_URL"),
            ("secret_key", "SECRET_KEY"),
        ]
        for attr, env_name in required_attrs:
            value = getattr(settings, attr, None)
            if not value:
                self.errors.append(f"Missing required env var: {env_name}")

        # SECRET_KEY length check
        key = getattr(settings, "secret_key", "") or ""
        if key and len(key) < _MIN_SECRET_KEY_LENGTH:
            self.errors.append(
                f"SECRET_KEY is too short ({len(key)} chars) — "
                f"minimum {_MIN_SECRET_KEY_LENGTH} characters required"
            )

        # SECRET_KEY must not be a well-known placeholder
        if key.lower().strip() in _DANGEROUS_SECRET_VALUES:
            self.errors.append(
                f"SECRET_KEY is set to an insecure default value — "
                "generate a strong random key and set it in .env"
            )

    # ── Database ──────────────────────────────────────────────────────────────

    async def _validate_database(self, settings) -> None:  # type: ignore[no-untyped-def]
        from app.db.base import _get_engine
        try:
            engine = _get_engine()
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"PostgreSQL is not reachable: {exc}")
            return

        # Verify the migrations are up-to-date
        try:
            from alembic.config import Config
            from alembic.script import ScriptDirectory

            import os
            _alembic_ini = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "alembic.ini")
            )
            alembic_cfg = Config(_alembic_ini)
            script = ScriptDirectory.from_config(alembic_cfg)
            head_rev = script.get_current_head()

            engine = _get_engine()
            async with engine.connect() as conn:
                result = await conn.execute(
                    text("SELECT version_num FROM alembic_version_api LIMIT 1")
                )
                row = result.fetchone()
                current_rev = row[0] if row else None

            if current_rev != head_rev:
                self.warnings.append(
                    f"Database migrations are not up-to-date. "
                    f"Current: {current_rev or 'none'}, Head: {head_rev}. "
                    "Run: uv run alembic upgrade head"
                )
        except Exception as exc:  # noqa: BLE001
            self.warnings.append(f"Could not verify migration status: {exc}")

    # ── Redis ─────────────────────────────────────────────────────────────────

    async def _validate_redis(self, settings) -> None:  # type: ignore[no-untyped-def]
        try:
            import redis.asyncio as redis_async
            client = redis_async.from_url(settings.redis_url, socket_connect_timeout=3)
            await client.ping()
            await client.aclose()
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"Redis is not reachable ({settings.redis_url}): {exc}")

    # ── Qdrant ────────────────────────────────────────────────────────────────

    async def _validate_qdrant(self, settings) -> None:  # type: ignore[no-untyped-def]
        qdrant_url = getattr(settings, "qdrant_url", "http://localhost:6333")
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{qdrant_url}/healthz")
            if resp.status_code != 200:
                self.errors.append(
                    f"Qdrant health check returned HTTP {resp.status_code} "
                    f"(expected 200)"
                )
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"Qdrant is not reachable ({qdrant_url}): {exc}")

    # ── Ollama ────────────────────────────────────────────────────────────────

    async def _validate_ollama(self, settings) -> None:  # type: ignore[no-untyped-def]
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{settings.ollama_url}/api/tags")
            resp.raise_for_status()
            available = {m["name"] for m in resp.json().get("models", [])}
        except Exception as exc:  # noqa: BLE001
            self.errors.append(
                f"Ollama is not reachable ({settings.ollama_url}): {exc}. "
                "Ensure Ollama is running on the host machine."
            )
            return

        # Check embedding model — required for KB indexing
        embedding_model = getattr(settings, "ollama_model_embedding", "bge-m3")
        if embedding_model not in available:
            self.warnings.append(
                f"Embedding model '{embedding_model}' not found in Ollama. "
                f"Run: ollama pull {embedding_model}"
            )

        # Check default LLM — required for agent operation
        default_model = getattr(settings, "ollama_model_default", "qwen2.5-coder:32b")
        if default_model not in available:
            self.warnings.append(
                f"Default LLM '{default_model}' not found in Ollama. "
                f"Run: ollama pull {default_model}"
            )

    # ── Burp Suite (optional) ─────────────────────────────────────────────────

    def _validate_burp_optional(self, settings) -> None:  # type: ignore[no-untyped-def]
        burp_url = getattr(settings, "burp_mcp_url", None)
        if not burp_url:
            self.warnings.append(
                "BURP_MCP_URL is not configured — "
                "Burp Suite MCP integration will be unavailable"
            )
