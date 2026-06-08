"""Thin Celery client for the API service.

The API service does NOT run a Celery worker, but it can enqueue tasks
by sending messages directly to the Redis broker.
"""

from __future__ import annotations

from celery import Celery

from app.core.config import get_api_settings

_celery: Celery | None = None


def _get_celery() -> Celery:
    global _celery
    if _celery is None:
        settings = get_api_settings()
        _celery = Celery(
            "pentra_api_client",
            broker=settings.redis_url,
        )
        _celery.conf.update(
            task_serializer="json",
            accept_content=["json"],
            # Mirror the worker's routing so tasks land in the right queues.
            task_default_queue="default",
            task_routes={
                "app.tasks.knowledge_scrape.*": {"queue": "knowledge"},
                "app.tasks.knowledge_update.*": {"queue": "knowledge"},
            },
        )
    return _celery


def send_task(task_name: str, kwargs: dict | None = None) -> str:
    """Enqueue a Celery task and return the task ID."""
    result = _get_celery().send_task(task_name, kwargs=kwargs or {})
    return result.id
