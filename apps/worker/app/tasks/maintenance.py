"""
Maintenance tasks — scheduled via Celery beat.
"""
import asyncio
import subprocess
import logging
from datetime import datetime
from app.worker import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="tasks.maintenance.update_nuclei_templates", bind=True)
def update_nuclei_templates(self):
    """
    Update nuclei templates to latest version.
    Scheduled: daily at 02:00 UTC.
    """
    logger.info("Starting nuclei template update...")

    try:
        count_before = _count_nuclei_templates()

        result = subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=True,
            text=True,
            timeout=300,
        )

        count_after = _count_nuclei_templates()
        new_templates = max(0, count_after - count_before)

        summary = {
            "status": "success",
            "templates_before": count_before,
            "templates_after": count_after,
            "new_templates": new_templates,
            "timestamp": datetime.utcnow().isoformat(),
            "stdout": result.stdout[-500:] if result.stdout else "",
        }

        logger.info(f"Nuclei templates updated: {count_after} total (+{new_templates} new)")

        asyncio.run(_broadcast_update(summary))

        return summary

    except subprocess.TimeoutExpired:
        logger.error("Nuclei template update timed out after 5 minutes")
        return {"status": "timeout", "timestamp": datetime.utcnow().isoformat()}
    except FileNotFoundError:
        logger.error("nuclei binary not found in PATH")
        return {"status": "nuclei_not_found", "timestamp": datetime.utcnow().isoformat()}
    except Exception as e:
        logger.error(f"Nuclei template update failed: {e}")
        return {"status": "error", "error": str(e), "timestamp": datetime.utcnow().isoformat()}


def _count_nuclei_templates() -> int:
    """Count total nuclei templates available."""
    try:
        result = subprocess.run(
            ["nuclei", "-tl"],
            capture_output=True, text=True, timeout=30
        )
        lines = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith("[")]
        return len(lines)
    except Exception:
        return 0


async def _broadcast_update(summary: dict):
    """Broadcast template update event to WebSocket clients."""
    try:
        # Import lazily — manager lives in API, not worker
        from apps.api.app.ws.manager import manager  # type: ignore[import]
        await manager.broadcast_system_event({
            "type": "TEMPLATES_UPDATED",
            "data": summary,
        })
    except Exception as e:
        logger.warning(f"Could not broadcast template update: {e}")
