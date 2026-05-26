"""Celery application factory for pentra-worker."""
from __future__ import annotations

from celery import Celery

from app.core.config import settings


def create_celery() -> Celery:
    app = Celery("pentra_worker")
    app.config_from_object(settings.celery_config)

    # Auto-discover tasks in app/tasks/
    app.autodiscover_tasks(["app.tasks"])

    return app


celery_app = create_celery()
