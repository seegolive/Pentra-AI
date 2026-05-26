"""RSS feed ingestion Celery task.

Fetches articles from curated security research RSS feeds, uses the fast LLM
to extract vulnerability technique metadata, and stores new records in the
knowledge base (PostgreSQL + Qdrant).

Beat schedule entry (added to ``core/config.py``)::

    "rss-ingestion-daily": {
        "task": "app.tasks.rss_ingestion.ingest_rss_feeds",
        "schedule": crontab(hour=3, minute=0),   # 03:00 UTC daily
    }
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from datetime import UTC, datetime
from typing import Any

import httpx

from pentra_knowledge.db.base import AsyncSessionLocal
from pentra_knowledge.db.repository import KnowledgeRepository
from pentra_shared.types import VulnClass

from app.worker import celery_app

log = logging.getLogger(__name__)

# ── Feed definitions ──────────────────────────────────────────────────────────

RSS_FEEDS: list[dict[str, str]] = [
    {
        "url": "https://portswigger.net/research/rss",
        "source": "portswigger",
        "default_category": "web",
    },
    {
        "url": "https://www.hackerone.com/blog.rss",
        "source": "hackerone_blog",
        "default_category": "web",
    },
    {
        "url": "https://pentester.land/newsletter/rss.xml",
        "source": "pentester_land",
        "default_category": "web",
    },
    {
        "url": "https://blog.assetnote.io/feed.xml",
        "source": "assetnote",
        "default_category": "web",
    },
]

# ── Vuln class keyword map ────────────────────────────────────────────────────

_VULN_KEYWORDS: list[tuple[list[str], VulnClass]] = [
    (["xss", "cross-site scripting"], VulnClass.XSS),
    (["sql injection", "sqli"], VulnClass.SQLI),
    (["ssrf", "server-side request forgery"], VulnClass.SSRF),
    (["idor", "insecure direct object"], VulnClass.IDOR),
    (["rce", "remote code execution", "command injection"], VulnClass.RCE),
    (["path traversal", "directory traversal", "lfi", "local file inclusion"], VulnClass.PATH_TRAVERSAL),
    (["open redirect"], VulnClass.OPEN_REDIRECT),
    (["csrf", "cross-site request forgery"], VulnClass.CSRF),
    (["xxe", "xml external entity"], VulnClass.XXE),
    (["deserialization"], VulnClass.DESERIALIZATION),
]


def _guess_vuln_class(text: str) -> VulnClass:
    lower = text.lower()
    for keywords, cls in _VULN_KEYWORDS:
        if any(kw in lower for kw in keywords):
            return cls
    return VulnClass.OTHER


def _stable_id(source: str, url: str) -> str:
    """Deterministic hash used to skip already-imported articles."""
    return hashlib.sha256(f"{source}:{url}".encode()).hexdigest()[:32]


# ── RSS parser ────────────────────────────────────────────────────────────────

async def _fetch_feed(url: str, timeout: int = 30) -> list[dict[str, Any]]:
    """Fetch and parse an RSS/Atom feed.  Returns list of item dicts."""
    try:
        # feedparser is optional — fall back to minimal regex parsing if absent
        import feedparser  # type: ignore[import]

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()

        feed = feedparser.parse(resp.text)
        items = []
        for entry in feed.entries:
            items.append({
                "title": getattr(entry, "title", ""),
                "url": getattr(entry, "link", ""),
                "summary": getattr(entry, "summary", ""),
                "published_at": getattr(entry, "published", ""),
            })
        return items
    except ImportError:
        log.warning("feedparser not installed — using minimal regex parser for %s", url)
        return await _fetch_feed_minimal(url, timeout)
    except Exception as exc:  # noqa: BLE001
        log.warning("_fetch_feed failed for %s: %s", url, exc)
        return []


async def _fetch_feed_minimal(url: str, timeout: int = 30) -> list[dict[str, Any]]:
    """Minimal RSS parser that handles basic RSS 2.0 without feedparser."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(url)
        resp.raise_for_status()

    content = resp.text
    # Extract <item> blocks
    item_blocks = re.findall(r"<item>(.*?)</item>", content, re.DOTALL)
    items = []
    for block in item_blocks:
        title_m = re.search(r"<title><!\[CDATA\[(.*?)\]\]>|<title>(.*?)</title>", block, re.DOTALL)
        link_m = re.search(r"<link>(.*?)</link>", block, re.DOTALL)
        desc_m = re.search(r"<description><!\[CDATA\[(.*?)\]\]>|<description>(.*?)</description>", block, re.DOTALL)
        pub_m = re.search(r"<pubDate>(.*?)</pubDate>", block)

        title = (title_m.group(1) or title_m.group(2) or "").strip() if title_m else ""
        link = link_m.group(1).strip() if link_m else ""
        desc = (desc_m.group(1) or desc_m.group(2) or "").strip() if desc_m else ""
        pub = pub_m.group(1).strip() if pub_m else ""

        if link:
            items.append({"title": title, "url": link, "summary": desc[:2000], "published_at": pub})
    return items


# ── LLM extraction ────────────────────────────────────────────────────────────

async def _extract_insight(title: str, summary: str, ollama_url: str, model: str) -> str:
    """Ask the fast LLM to summarise the key security insight from an article."""
    prompt = (
        f"Title: {title}\n\nSummary:\n{summary[:1500]}\n\n"
        "In 1-2 sentences, extract the key security technique or vulnerability class "
        "described. Be concise and technical. Output only the insight sentence."
    )
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{ollama_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
    except Exception as exc:  # noqa: BLE001
        log.warning("LLM insight extraction failed: %s", exc)
        return ""


# ── Main Celery task ──────────────────────────────────────────────────────────

@celery_app.task(name="app.tasks.rss_ingestion.ingest_rss_feeds", bind=True, max_retries=3)
def ingest_rss_feeds(self: Any, feeds: list[str] | None = None) -> dict[str, int]:
    """Fetch configured RSS feeds and ingest new articles into the knowledge base.

    Parameters
    ----------
    feeds:
        Optional list of feed URLs to restrict this run to. If *None*, all
        feeds in :data:`RSS_FEEDS` are processed.

    Returns
    -------
    dict
        ``{"ingested": <count>, "skipped": <count>, "errors": <count>}``
    """
    return asyncio.get_event_loop().run_until_complete(_ingest_feeds_async(feeds))


async def _ingest_feeds_async(feeds: list[str] | None) -> dict[str, int]:
    from app.core.config import settings as worker_settings  # lazy import avoids circular

    target_feeds = (
        [f for f in RSS_FEEDS if f["url"] in feeds]
        if feeds
        else RSS_FEEDS
    )

    ingested = skipped = errors = 0

    async with AsyncSessionLocal() as db:
        for feed_def in target_feeds:
            items = await _fetch_feed(feed_def["url"])
            log.info("Feed %s returned %d items", feed_def["source"], len(items))
            repo = KnowledgeRepository(db)

            for item in items:
                if not item.get("url"):
                    errors += 1
                    continue

                stable_hash = _stable_id(feed_def["source"], item["url"])

                # Skip if already imported (hash stored in source_id)
                existing = await repo.get_by_source_id(stable_hash)
                if existing:
                    skipped += 1
                    continue

                title: str = item.get("title", "")
                summary: str = item.get("summary", "")
                vuln_class = _guess_vuln_class(f"{title} {summary}")

                insight = await _extract_insight(
                    title,
                    summary,
                    worker_settings.ollama_url,
                    worker_settings.ollama_model_fast,
                )

                record_data: dict = {
                    "source": feed_def["source"],
                    "source_id": stable_hash,
                    "source_url": item["url"],
                    "title": title,
                    "vuln_class": vuln_class.value,
                    "vuln_subclass": "",
                    "severity": "info",
                    "program": feed_def["source"],
                    "tech_stack": [],
                    "platform_type": ["web"],
                    "attack_technique": insight[:200] if insight else "",
                    "attack_steps": [],
                    "key_insight": insight or title,
                    "indicators": [],
                    "pentra_tags": ["rss", feed_def["source"]],
                }

                try:
                    await repo.create(record_data)
                    await db.commit()
                    ingested += 1
                except Exception as exc:  # noqa: BLE001
                    await db.rollback()
                    log.warning("Failed to save RSS item %s: %s", item["url"], exc)
                    errors += 1

    log.info(
        "RSS ingestion complete — ingested=%d skipped=%d errors=%d",
        ingested, skipped, errors,
    )
    return {"ingested": ingested, "skipped": skipped, "errors": errors}
