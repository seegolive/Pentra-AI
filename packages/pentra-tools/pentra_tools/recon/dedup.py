"""
Smart duplicate removal — fingerprint-based dedup untuk endpoint lists.
Terinspirasi dari reNgine's duplicate_fields: [content_length, page_title] config.
"""

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def smart_dedup_endpoints(endpoints: list[dict]) -> list[dict]:
    """
    Smart dedup berdasarkan content_length + page_title fingerprint.
    Lebih akurat dari URL-only karena:
    /products?id=1 dan /products?id=2 yang return konten sama = 1 endpoint.

    Terinspirasi dari reNgine's duplicate_fields config.
    """
    seen: dict[str, str] = {}   # sig → first_url
    unique: list[dict] = []
    removed = 0

    for ep in endpoints:
        url = ep.get("url", "")
        content_len = ep.get("content_length")
        page_title = (ep.get("page_title") or "").strip().lower()

        # Build fingerprint
        if content_len is not None and page_title:
            sig = f"cl:{content_len}|title:{page_title[:80]}"
        elif content_len is not None:
            sig = f"cl:{content_len}"
        else:
            # Fallback: URL path dedup (strip query params variasi)
            parsed = urlparse(url)
            # Normalize: remove ID-like params yang nilainya berbeda tapi path sama
            sig = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if sig not in seen:
            seen[sig] = url
            unique.append(ep)
        else:
            removed += 1
            logger.debug("[dedup] Removed duplicate: %s ≈ %s", url, seen[sig])

    logger.info(
        "[dedup] %d → %d endpoints (removed %d duplicates, %.0f%%)",
        len(endpoints), len(unique), removed,
        (removed / max(len(endpoints), 1)) * 100,
    )
    return unique
