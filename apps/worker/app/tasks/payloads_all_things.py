"""PayloadsAllThings GitHub importer Celery task.

Fetches markdown payload files from the PayloadsAllThings repository on
GitHub, maps each top-level folder to a :class:`pentra_knowledge.models.VulnClass`,
parses payload lists and technique descriptions, then stores new entries in
the knowledge base.

Beat schedule entry (added to ``core/config.py``)::

    "payloads-sync-weekly": {
        "task": "app.tasks.payloads_all_things.import_payloads_all_things",
        "schedule": crontab(day_of_week=1, hour=4, minute=0),  # Monday 04:00 UTC
    }

No GitHub token is required — the GitHub Contents API is used without
authentication at the standard rate limit (60 req/h for public repos).
For higher throughput set ``GITHUB_TOKEN`` in the environment.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from typing import Any

import httpx

from pentra_knowledge.db.base import _get_session_factory as _kb_session_factory
from pentra_knowledge.db.repository import KnowledgeRepository
from pentra_shared.types import VulnClass

from app.worker import celery_app

log = logging.getLogger(__name__)

# ── GitHub API base URL for PayloadsAllThings ─────────────────────────────────
_PAT_OWNER = "swisskyrepo"
_PAT_REPO = "PayloadsAllThings"
_PAT_BRANCH = "master"
_GITHUB_API = "https://api.github.com"
_GITHUB_RAW = "https://raw.githubusercontent.com"
_GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # optional — raises rate limit to 5 000/h

# ── Folder-name → VulnClass mapping ──────────────────────────────────────────

_FOLDER_MAP: dict[str, VulnClass] = {
    "XSS Injection": VulnClass.XSS_STORED,
    "SQL Injection": VulnClass.SQLI,
    "SSRF injection": VulnClass.SSRF,
    "IDOR": VulnClass.IDOR,
    "Command Injection": VulnClass.RCE,
    "Remote Code Execution": VulnClass.RCE,
    "File Inclusion": VulnClass.PATH_TRAVERSAL,
    "Path Traversal": VulnClass.PATH_TRAVERSAL,
    "Open Redirect": VulnClass.OPEN_REDIRECT,
    "CSRF Injection": VulnClass.AUTH_BYPASS,
    "XXE Injection": VulnClass.XXE,
    "Insecure Deserialization": VulnClass.DESERIALIZATION,
    "Server Side Template Injection": VulnClass.SSTI,
    "CRLF Injection": VulnClass.OTHER,
    "HTTP Request Smuggling": VulnClass.OTHER,
    "OAuth Misconfiguration": VulnClass.OTHER,
}

_DEFAULT_VULN_CLASS = VulnClass.OTHER


def _match_vuln_class(folder_name: str) -> VulnClass:
    """Fuzzy-match folder name to the closest VulnClass."""
    # Exact match first
    if folder_name in _FOLDER_MAP:
        return _FOLDER_MAP[folder_name]
    # Prefix / substring match
    lower = folder_name.lower()
    for key, cls in _FOLDER_MAP.items():
        if key.lower() in lower or lower in key.lower():
            return cls
    return _DEFAULT_VULN_CLASS


def _stable_id(folder: str, section: str) -> str:
    return hashlib.sha256(f"payloads_all_things:{folder}:{section}".encode()).hexdigest()[:32]


# ── GitHub API helpers ────────────────────────────────────────────────────────

def _github_headers() -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
    if _GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {_GITHUB_TOKEN}"
    return headers


async def _github_get(client: httpx.AsyncClient, url: str) -> Any:
    resp = await client.get(url, headers=_github_headers(), timeout=30)
    resp.raise_for_status()
    return resp.json()


async def _list_top_level_folders(client: httpx.AsyncClient) -> list[dict[str, str]]:
    url = f"{_GITHUB_API}/repos/{_PAT_OWNER}/{_PAT_REPO}/contents"
    entries = await _github_get(client, url)
    return [e for e in entries if e.get("type") == "dir" and not e["name"].startswith(".")]


async def _fetch_readme(client: httpx.AsyncClient, folder_name: str) -> str | None:
    """Download the README.md for a PayloadsAllThings folder."""
    raw_url = (
        f"{_GITHUB_RAW}/{_PAT_OWNER}/{_PAT_REPO}/{_PAT_BRANCH}/{folder_name}/README.md"
    )
    try:
        resp = await client.get(raw_url, headers=_github_headers(), timeout=30)
        if resp.status_code == 200:
            return resp.text
    except Exception as exc:  # noqa: BLE001
        log.warning("Failed to fetch README for %s: %s", folder_name, exc)
    return None


# ── Markdown parser ───────────────────────────────────────────────────────────

def _parse_sections(markdown: str) -> list[dict[str, str]]:
    """Split a PayloadsAllThings README into sections by H2/H3 headings.

    Returns a list of dicts: ``{"heading": str, "body": str}``.
    """
    sections: list[dict[str, str]] = []
    # Split on any ## or ### heading
    parts = re.split(r"\n(?=#{2,3} )", markdown)
    for part in parts:
        lines = part.strip().splitlines()
        if not lines:
            continue
        heading_match = re.match(r"#{2,3} (.+)", lines[0])
        if not heading_match:
            continue
        heading = heading_match.group(1).strip()
        body = "\n".join(lines[1:]).strip()
        if body:
            sections.append({"heading": heading, "body": body})
    return sections


def _extract_payloads(body: str) -> list[str]:
    """Extract payloads from code blocks and bullet lists in a section."""
    payloads: list[str] = []
    # Code blocks
    for m in re.finditer(r"```[a-z]*\n(.*?)```", body, re.DOTALL):
        block = m.group(1).strip()
        if block:
            payloads.extend(line for line in block.splitlines() if line.strip())
    # Bullet items starting with `- ` or `* `
    for m in re.finditer(r"^[*\-]\s+(.+)$", body, re.MULTILINE):
        candidate = m.group(1).strip()
        if len(candidate) > 3 and not candidate.startswith("["):
            payloads.append(candidate)
    return payloads[:50]  # cap at 50 payloads per section to avoid bloat


# ── Main Celery task ──────────────────────────────────────────────────────────

@celery_app.task(
    name="app.tasks.payloads_all_things.import_payloads_all_things",
    bind=True,
    max_retries=3,
)
def import_payloads_all_things(
    self: Any,
    folder_filter: list[str] | None = None,
) -> dict[str, int]:
    """Import payload lists from PayloadsAllThings into the knowledge base.

    Parameters
    ----------
    folder_filter:
        Optional list of exact folder names to restrict this run to.
        If *None*, all mapped folders (see ``_FOLDER_MAP``) are processed.

    Returns
    -------
    dict
        ``{"ingested": <count>, "skipped": <count>, "errors": <count>}``
    """
    return asyncio.get_event_loop().run_until_complete(
        _import_async(folder_filter)
    )


async def _import_async(folder_filter: list[str] | None) -> dict[str, int]:
    ingested = skipped = errors = 0

    async with httpx.AsyncClient() as client:
        try:
            folders = await _list_top_level_folders(client)
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to list PayloadsAllThings folders: %s", exc)
            return {"ingested": 0, "skipped": 0, "errors": 1}

        for folder_entry in folders:
            folder_name: str = folder_entry["name"]

            # Apply filter if set
            if folder_filter and folder_name not in folder_filter:
                continue
            # Only process folders we have a VulnClass mapping for
            vuln_class = _match_vuln_class(folder_name)
            if vuln_class == VulnClass.OTHER and folder_name not in _FOLDER_MAP:
                continue

            readme = await _fetch_readme(client, folder_name)
            if not readme:
                log.info("No README for %s — skipping", folder_name)
                continue

            sections = _parse_sections(readme)
            log.info(
                "Processing %s (%s) — %d sections",
                folder_name, vuln_class.value, len(sections),
            )

            async with _kb_session_factory()() as db:
                repo = KnowledgeRepository(db)
                for section in sections:
                    section_id = _stable_id(folder_name, section["heading"])

                    existing = await repo.get_by_source_id(section_id)
                    if existing:
                        skipped += 1
                        continue

                    payloads = _extract_payloads(section["body"])
                    technique = section["heading"]

                    record_data: dict = {
                        "source": "payloads_all_things",
                        "source_id": section_id,
                        "source_url": f"https://github.com/{_PAT_OWNER}/{_PAT_REPO}/tree/{_PAT_BRANCH}/{folder_name}",
                        "title": f"[{folder_name}] {technique}",
                        "vuln_class": vuln_class.value,
                        "vuln_subclass": "",
                        "severity": "info",
                        "program": "payloads_all_things",
                        "tech_stack": [],
                        "platform_type": ["web"],
                        "attack_technique": technique[:200],
                        "attack_steps": payloads[:20],
                        "key_insight": technique,
                        "indicators": payloads[:20],
                        "pentra_tags": ["payloads_all_things", folder_name.lower().replace(" ", "_")],
                    }

                    try:
                        await repo.create(record_data)
                        await db.commit()
                        ingested += 1
                    except Exception as exc:  # noqa: BLE001
                        await db.rollback()
                        log.warning(
                            "Failed to save PAT entry %s/%s: %s",
                            folder_name, section["heading"], exc,
                        )
                        errors += 1

    log.info(
        "PayloadsAllThings import complete — ingested=%d skipped=%d errors=%d",
        ingested, skipped, errors,
    )
    return {"ingested": ingested, "skipped": skipped, "errors": errors}
