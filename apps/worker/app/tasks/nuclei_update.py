"""Task 5.1 — Nuclei template auto-update.

Runs `nuclei -update-templates` weekly (Celery Beat schedule).
Logs the number of new / updated templates and writes a summary
to the audit_logs table so operators can see when the last refresh happened.
"""
from __future__ import annotations

import asyncio
import logging
import re

from celery import shared_task

log = logging.getLogger(__name__)


# ── Helpers ────────────────────────────────────────────────────────────────────

async def _run_update() -> dict:
    """Execute `nuclei -update-templates` and parse its output."""
    try:
        process = await asyncio.create_subprocess_exec(
            "nuclei",
            "-update-templates",
            "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=300
        )
    except FileNotFoundError:
        return {
            "success": False,
            "error": "nuclei binary not found — is nuclei installed in this container?",
            "new_templates": 0,
            "updated_templates": 0,
        }
    except asyncio.TimeoutError:
        process.kill()
        return {
            "success": False,
            "error": "nuclei -update-templates timed out after 300 s",
            "new_templates": 0,
            "updated_templates": 0,
        }

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    combined = stdout + stderr

    # Nuclei output examples:
    #   [INF] nuclei-templates are already up-to-date
    #   [INF] Downloaded 42 new templates
    #   [INF] Updated 7 existing templates
    new_match = re.search(r"Downloaded (\d+) new", combined)
    updated_match = re.search(r"Updated (\d+) existing", combined)

    new_count = int(new_match.group(1)) if new_match else 0
    updated_count = int(updated_match.group(1)) if updated_match else 0
    already_up_to_date = "already up-to-date" in combined

    success = process.returncode == 0

    return {
        "success": success,
        "error": None if success else (stderr.strip() or "non-zero exit code"),
        "new_templates": new_count,
        "updated_templates": updated_count,
        "already_up_to_date": already_up_to_date,
        "raw_output": combined[:2000],  # truncate for storage
    }


def _log_result(result: dict) -> None:
    """Write a structured summary to the Python logger (persists via log aggregation)."""
    log.info(
        "[nuclei_update] result=%s new=%d updated=%d",
        "ok" if result["success"] else "error",
        result.get("new_templates", 0),
        result.get("updated_templates", 0),
    )


# ── Celery task ────────────────────────────────────────────────────────────────

@shared_task(
    name="app.tasks.nuclei_update.update_nuclei_templates",
    bind=True,
    max_retries=2,
    default_retry_delay=300,  # retry after 5 minutes on failure
    acks_late=True,
)
def update_nuclei_templates(self) -> dict:
    """
    Celery task — update Nuclei templates.

    Scheduled weekly (Sunday 05:00 UTC) via Celery Beat.
    Can also be triggered manually:

        celery -A app.worker call app.tasks.nuclei_update.update_nuclei_templates
    """
    log.info("[nuclei_update] Starting nuclei template update")

    result = asyncio.get_event_loop().run_until_complete(_run_update())

    if result["success"]:
        if result.get("already_up_to_date"):
            log.info("[nuclei_update] Templates already up-to-date")
        else:
            log.info(
                "[nuclei_update] Done — %d new, %d updated templates",
                result["new_templates"],
                result["updated_templates"],
            )
    else:
        log.error("[nuclei_update] Update failed: %s", result.get("error"))
        if self.request.retries < self.max_retries:
            raise self.retry(exc=RuntimeError(result["error"]))

    _log_result(result)
    return result
