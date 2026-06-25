from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiSettings(BaseSettings):
    """Runtime configuration for pentra-api.

    All values are read from environment variables (or .env files).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Server ────────────────────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_debug: bool = Field(default=False)

    # ── Database ──────────────────────────────────────────────────────────
    database_url: str = Field(
        default="postgresql+asyncpg://pentra:pentra@localhost:5432/pentra",
        description="Async PostgreSQL connection string for SQLAlchemy",
    )

    # ── Redis ─────────────────────────────────────────────────────────────
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection string for rate limiting and caching",
    )

    # ── Auth / JWT ────────────────────────────────────────────────────────
    secret_key: str = Field(
        default="change-this-in-production-min-32-chars",
        description="JWT signing secret — minimum 32 characters",
    )
    access_token_expire_minutes: int = Field(default=480)
    refresh_token_expire_days: int = Field(default=30)
    algorithm: str = Field(default="HS256")

    # ── CORS ──────────────────────────────────────────────────────────────
    cors_origins: list[str] = Field(
        default=[
            "http://localhost:5173",
            "http://localhost:5174",
            "http://localhost:4173",
        ],
        description="Allowed CORS origins for the React frontend",
    )

    # ── Ollama ────────────────────────────────────────────────────────────
    ollama_url: str = Field(default="http://localhost:11434")
    ollama_model_default: str = Field(default="qwen2.5:32b")
    ollama_model_reasoning: str = Field(default="qwen2.5:32b")
    ollama_model_fast: str = Field(default="qwen2.5:7b")
    # ── Qdrant ────────────────────────────────────────────────────────────
    qdrant_url: str = Field(default="http://localhost:6333")
    qdrant_collection_knowledge: str = Field(default="knowledge")

    # ── MinIO ─────────────────────────────────────────────────────────────
    minio_url: str = Field(default="http://localhost:9000")
    minio_access_key: str = Field(default="pentra")
    minio_secret_key: str = Field(default="changeme")
    minio_bucket_evidence: str = Field(default="evidence")

    # ── Embedding ─────────────────────────────────────────────────────────
    ollama_model_embedding: str = Field(default="bge-m3")
    # ── Internal API (agent ↔ api shared secret) ───────────────────────────────
    internal_api_token: str = Field(
        default="",
        description="Shared secret for /internal/* endpoints (set in .env)",
    )
    # ── Burp Suite MCP ────────────────────────────────────────────────────
    burp_mcp_url: str | None = Field(default=None)

    # ── Notifications ──────────────────────────────────────────────
    slack_webhook_url: str | None = Field(default=None)
    telegram_bot_token: str | None = Field(default=None)
    telegram_chat_id: str | None = Field(default=None)

@lru_cache
def get_api_settings() -> ApiSettings:
    return ApiSettings()
