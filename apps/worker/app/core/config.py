"""Worker configuration — all values from environment variables."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Database (passed through to pentra-knowledge)
    database_url: str = "postgresql+asyncpg://pentra:pentra@localhost:5432/pentra"

    # Qdrant
    qdrant_url: str = "http://localhost:6333"
    qdrant_collection_knowledge: str = "knowledge"

    # MinIO
    minio_url: str = "http://localhost:9000"
    minio_access_key: str = "pentra"
    minio_secret_key: str = "changeme"

    # Ollama
    ollama_url: str = "http://localhost:11434"
    ollama_model_fast: str = "qwen3:8b"
    ollama_model_embedding: str = "bge-m3"

    # H1 scraper settings
    h1_graphql_url: str = "https://hackerone.com/graphql"
    h1_scrape_page_size: int = 25          # H1 limits to 25 per page
    h1_scrape_concurrency: int = 2         # concurrent page fetches — be polite
    h1_scrape_delay_seconds: float = 2.0   # delay between requests
    h1_max_pages: int = 0                  # 0 = no limit (scrape all)

    # Notifications
    slack_webhook_url: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    @property
    def celery_config(self) -> dict:
        return {
            "broker_url": self.redis_url,
            "result_backend": self.redis_url,
            "task_serializer": "json",
            "result_serializer": "json",
            "accept_content": ["json"],
            "timezone": "UTC",
            "enable_utc": True,
            "task_routes": {
                "app.tasks.knowledge_scrape.*": {"queue": "knowledge"},
                "app.tasks.knowledge_update.*": {"queue": "knowledge"},
            },
            "beat_schedule": {
                "h1-daily-scrape": {
                    "task": "app.tasks.knowledge_scrape.scrape_h1_hacktivity",
                    "schedule": 86400.0,   # every 24 hours
                    "kwargs": {"max_pages": 10},   # ~250 newest reports per day
                },
                "embed-pending-hourly": {
                    "task": "app.tasks.knowledge_update.embed_pending_records",
                    "schedule": 3600.0,    # every hour
                    "kwargs": {"batch_size": 100, "max_records": 500},
                },
                "rss-ingestion-daily": {
                    "task": "app.tasks.rss_ingestion.ingest_rss_feeds",
                    "schedule": 86400.0,   # every 24 hours (03:00 UTC via start_period)
                },
                "payloads-sync-weekly": {
                    "task": "app.tasks.payloads_all_things.import_payloads_all_things",
                    "schedule": 604800.0,  # every 7 days
                },
                "monitoring-daily": {
                    "task": "app.tasks.monitoring.run_all_engagement_monitors",
                    "schedule": 86400.0,   # every 24 hours
                },
                "nuclei-template-update-weekly": {
                    "task": "app.tasks.nuclei_update.update_nuclei_templates",
                    "schedule": 604800.0,  # every 7 days (Sunday 05:00 UTC)
                },
                "cve-enrichment-daily": {
                    "task": "app.tasks.cve_enrichment.enrich_pending_findings",
                    "schedule": 86400.0,   # every 24 hours
                    "kwargs": {"batch_size": 50},
                },
                "backup-postgresql-daily": {
                    "task": "app.tasks.backup.backup_postgresql",
                    "schedule": 3600.0 * 24,  # every 24 hours (01:00 UTC)
                    "options": {"queue": "default"},
                },
                "backup-qdrant-daily": {
                    "task": "app.tasks.backup.backup_qdrant",
                    "schedule": 3600.0 * 24 + 1800.0,  # every 24h + 30min offset
                    "options": {"queue": "default"},
                },
            },
        }


settings = WorkerSettings()
