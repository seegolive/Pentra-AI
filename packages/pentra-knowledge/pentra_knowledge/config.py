from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class KnowledgeSettings(BaseSettings):
    """Runtime configuration for pentra-knowledge.

    All values are read from environment variables (or .env files).
    Defaults match the docker-compose service names defined in infra/.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────────
    database_url: str = Field(
        default="postgresql+asyncpg://pentra:password@localhost:5432/pentra",
        description="Async PostgreSQL connection string",
    )

    # ── Qdrant ────────────────────────────────────────────────────────────
    qdrant_url: str = Field(
        default="http://localhost:6333",
        description="Qdrant HTTP endpoint",
    )
    qdrant_collection_knowledge: str = Field(
        default="knowledge",
        description="Qdrant collection name for knowledge records",
    )
    qdrant_dense_dim: int = Field(
        default=1024,
        description="BGE-M3 dense vector dimension",
    )

    # ── Ollama ────────────────────────────────────────────────────────────
    ollama_url: str = Field(
        default="http://localhost:11434",
        description="Ollama API base URL",
    )
    ollama_model_fast: str = Field(
        default="qwen2.5-coder:7b",
        description="Fast model used for bulk LLM extraction in the KB pipeline",
    )
    ollama_model_embedding: str = Field(
        default="bge-m3",
        description="Embedding model for BGE-M3 dense + sparse vectors",
    )

    # ── Search ────────────────────────────────────────────────────────────
    knowledge_search_default_top_k: int = Field(
        default=8,
        description="Default number of results returned by hybrid_search()",
    )
    knowledge_search_max_top_k: int = Field(
        default=50,
        description="Hard cap on top_k to prevent overloading LangGraph context",
    )
    knowledge_min_score: float = Field(
        default=0.60,
        description="Minimum relevance score to include a result",
    )

    # ── Ingestion ─────────────────────────────────────────────────────────
    ingest_batch_size: int = Field(
        default=50,
        description="Records processed per batch to avoid Ollama timeout",
    )

    # ── MinIO ─────────────────────────────────────────────────────────────
    minio_url: str = Field(default="http://localhost:9000")
    minio_access_key: str = Field(default="pentra")
    minio_secret_key: str = Field(default="changeme")
    minio_bucket_raw_kb: str = Field(default="raw-knowledge")


@lru_cache
def get_settings() -> KnowledgeSettings:
    """Return a cached singleton of KnowledgeSettings."""
    return KnowledgeSettings()
