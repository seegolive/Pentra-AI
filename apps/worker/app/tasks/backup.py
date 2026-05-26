"""Backup tasks — PostgreSQL dump and Qdrant snapshot to MinIO.

Schedule (via Celery Beat):
  - backup-postgresql-daily: every day at 01:00 UTC
  - backup-qdrant-daily:     every day at 01:30 UTC

Retention: 7 most-recent backups are kept per storage type.
All backups land in MinIO bucket "backups".
"""
from __future__ import annotations

import io
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from celery import Task
from miniopy_async import Minio

from app.worker import celery_app
from app.core.config import settings

logger = logging.getLogger(__name__)

_BACKUP_BUCKET = "backups"
_PG_PREFIX = "postgresql/"
_QDRANT_PREFIX = "qdrant/"
_RETAIN_COUNT = 7


def _get_minio() -> Minio:
    """Return a configured async MinIO client."""
    url = settings.minio_url.removeprefix("http://").removeprefix("https://")
    secure = settings.minio_url.startswith("https://")
    return Minio(
        url,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=secure,
    )


async def _ensure_bucket(client: Minio, bucket: str) -> None:
    if not await client.bucket_exists(bucket):
        await client.make_bucket(bucket)


async def _cleanup_old_backups(
    client: Minio,
    bucket: str,
    prefix: str,
    keep: int,
) -> int:
    """Delete oldest backups beyond the retention count. Returns number deleted."""
    objects = [
        obj
        async for obj in await client.list_objects(bucket, prefix=prefix, recursive=True)
    ]
    # Sort newest-first by object name (timestamp embedded in name)
    objects.sort(key=lambda o: o.object_name, reverse=True)
    to_delete = objects[keep:]
    for obj in to_delete:
        await client.remove_object(bucket, obj.object_name)
        logger.info("Deleted old backup: %s/%s", bucket, obj.object_name)
    return len(to_delete)


# ── PostgreSQL Backup ─────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="app.tasks.backup.backup_postgresql", max_retries=2)
def backup_postgresql(self: Task) -> dict:
    """Dump PostgreSQL database with pg_dump, compress, upload to MinIO."""
    import asyncio
    return asyncio.get_event_loop().run_until_complete(_backup_postgresql_async())


async def _backup_postgresql_async() -> dict:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    object_name = f"{_PG_PREFIX}{timestamp}.sql.gz"

    # Build pg_dump command — convert asyncpg URL to psql URL
    db_url = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")

    with tempfile.NamedTemporaryFile(suffix=".sql.gz", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        cmd = f"pg_dump '{db_url}' | gzip > '{tmp_path}'"
        result = subprocess.run(
            cmd,
            shell=True,  # noqa: S602 — controlled input from settings
            capture_output=True,
            timeout=300,
        )
        if result.returncode != 0:
            err = result.stderr.decode(errors="replace")
            raise RuntimeError(f"pg_dump failed (exit {result.returncode}): {err}")

        file_size = Path(tmp_path).stat().st_size
        if file_size == 0:
            raise RuntimeError("pg_dump produced an empty file")

        client = _get_minio()
        await _ensure_bucket(client, _BACKUP_BUCKET)

        await client.fput_object(
            bucket_name=_BACKUP_BUCKET,
            object_name=object_name,
            file_path=tmp_path,
            content_type="application/gzip",
        )
        logger.info("PostgreSQL backup uploaded: %s (%d bytes)", object_name, file_size)

        deleted = await _cleanup_old_backups(client, _BACKUP_BUCKET, _PG_PREFIX, _RETAIN_COUNT)
        return {
            "status": "success",
            "object": object_name,
            "size_bytes": file_size,
            "old_backups_deleted": deleted,
        }
    finally:
        Path(tmp_path).unlink(missing_ok=True)


# ── Qdrant Snapshot Backup ────────────────────────────────────────────────────

@celery_app.task(bind=True, name="app.tasks.backup.backup_qdrant", max_retries=2)
def backup_qdrant(self: Task) -> dict:
    """Create Qdrant snapshot for 'knowledge' collection and upload to MinIO."""
    import asyncio
    return asyncio.get_event_loop().run_until_complete(_backup_qdrant_async())


async def _backup_qdrant_async() -> dict:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    collection = settings.qdrant_collection_knowledge
    qdrant_base = settings.qdrant_url.rstrip("/")

    async with httpx.AsyncClient(timeout=30) as client:
        # 1. Create snapshot
        resp = await client.post(
            f"{qdrant_base}/collections/{collection}/snapshots"
        )
        resp.raise_for_status()
        snapshot_name: str = resp.json()["result"]["name"]
        logger.info("Qdrant snapshot created: %s", snapshot_name)

        # 2. Download snapshot (can be large — stream it)
        download_url = (
            f"{qdrant_base}/collections/{collection}/snapshots/{snapshot_name}"
        )
        async with client.stream("GET", download_url, timeout=300) as stream:
            stream.raise_for_status()
            data = await stream.aread()

    object_name = f"{_QDRANT_PREFIX}{timestamp}_{snapshot_name}"
    minio = _get_minio()
    await _ensure_bucket(minio, _BACKUP_BUCKET)

    await minio.put_object(
        bucket_name=_BACKUP_BUCKET,
        object_name=object_name,
        data=io.BytesIO(data),
        length=len(data),
        content_type="application/octet-stream",
    )
    logger.info("Qdrant backup uploaded: %s (%d bytes)", object_name, len(data))

    # 3. Delete the snapshot from Qdrant (free disk space)
    async with httpx.AsyncClient(timeout=15) as client:
        await client.delete(
            f"{qdrant_base}/collections/{collection}/snapshots/{snapshot_name}"
        )

    deleted = await _cleanup_old_backups(minio, _BACKUP_BUCKET, _QDRANT_PREFIX, _RETAIN_COUNT)
    return {
        "status": "success",
        "object": object_name,
        "size_bytes": len(data),
        "old_backups_deleted": deleted,
    }
