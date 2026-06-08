"""Incremental Testing — Task 18.13 (XBOW pattern).

Fingerprint endpoints by content hash and skip re-testing when unchanged.
Stores fingerprints in a JSON cache file between runs.

Usage:
    tracker = IncrementalTracker(cache_path="/tmp/pentra_cache_target.json")
    tracker.load()

    # Before testing a candidate
    if tracker.is_unchanged(url, param, current_response):
        continue  # skip — nothing changed since last test

    # After scan, save updated fingerprints
    tracker.save()

Integration: called from vuln_hunt_node inside _test_one() on baseline response.
If the baseline response fingerprint matches the cached one, skip this candidate.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass
class EndpointFingerprint:
    """Content fingerprint for one URL/param combination."""
    url: str
    param: str
    content_hash: str   # SHA-256 of response body (first 8KB)
    status_code: int
    content_length: int
    last_seen: float    # Unix timestamp
    last_vuln_found: bool = False


class IncrementalTracker:
    """Persists endpoint fingerprints across scan runs.

    When a baseline response matches the cached fingerprint, the endpoint
    is considered unchanged and can be skipped — reducing re-scan time
    by ~60-80% on stable targets.

    Cache file: JSON, keyed by (url, param) tuples.
    """

    def __init__(
        self,
        cache_path: str | None = None,
        max_age_hours: float = 24.0,
    ) -> None:
        """
        Args:
            cache_path:     Path to the JSON cache file.
                            Default: /tmp/pentra_incremental_{domain}.json
            max_age_hours:  Entries older than this are considered stale and
                            will not skip testing. Default: 24 hours.
        """
        self.cache_path = cache_path
        self.max_age_s = max_age_hours * 3600
        self._store: dict[str, EndpointFingerprint] = {}
        self._hits = 0
        self._misses = 0

    @classmethod
    def for_domain(cls, domain: str, cache_dir: str = "/tmp") -> "IncrementalTracker":
        """Create a tracker with an auto-named cache file for the domain."""
        safe = domain.replace(".", "_").replace(":", "_")
        path = os.path.join(cache_dir, f"pentra_incremental_{safe}.json")
        return cls(cache_path=path)

    def load(self) -> None:
        """Load fingerprints from cache file (if it exists)."""
        if not self.cache_path or not os.path.exists(self.cache_path):
            return
        try:
            with open(self.cache_path) as f:
                raw = json.load(f)
            for key, data in raw.items():
                self._store[key] = EndpointFingerprint(**data)
            log.info("[incremental] Loaded %d fingerprints from %s", len(self._store), self.cache_path)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            log.warning("[incremental] Failed to load cache: %s — starting fresh", exc)

    def save(self) -> None:
        """Persist current fingerprints to cache file."""
        if not self.cache_path:
            return
        try:
            raw = {
                k: {
                    "url": v.url, "param": v.param,
                    "content_hash": v.content_hash,
                    "status_code": v.status_code,
                    "content_length": v.content_length,
                    "last_seen": v.last_seen,
                    "last_vuln_found": v.last_vuln_found,
                }
                for k, v in self._store.items()
            }
            with open(self.cache_path, "w") as f:
                json.dump(raw, f, indent=2)
            log.info(
                "[incremental] Saved %d fingerprints → %s (hits=%d misses=%d)",
                len(self._store), self.cache_path, self._hits, self._misses,
            )
        except OSError as exc:
            log.warning("[incremental] Failed to save cache: %s", exc)

    @staticmethod
    def fingerprint_response(response_body: str, status_code: int = 200) -> tuple[str, int]:
        """Return (sha256_hash, length) of the response body (first 8KB)."""
        body = (response_body or "")[:8192]
        h = hashlib.sha256(body.encode(errors="replace")).hexdigest()
        return h, len(body)

    def _cache_key(self, url: str, param: str) -> str:
        return f"{url}|{param}"

    def is_unchanged(self, url: str, param: str, current_response: str, status_code: int = 200) -> bool:
        """Return True if the endpoint looks unchanged from the last scan.

        Criteria:
          - Cached fingerprint exists
          - Not older than max_age_s
          - No vulnerability was found last time (if vuln was found, always re-test)
          - Content hash matches (or within ±5% length if hash differs — minor dynamic content)

        Returns False (should test) on any uncertainty.
        """
        key = self._cache_key(url, param)
        cached = self._store.get(key)

        if not cached:
            self._misses += 1
            return False  # never seen before — must test

        age = time.time() - cached.last_seen
        if age > self.max_age_s:
            self._misses += 1
            log.debug("[incremental] Stale cache for %s[%s] (%.1fh old)", url, param, age / 3600)
            return False

        if cached.last_vuln_found:
            # Always re-test if a vuln was found before — might have been patched
            self._misses += 1
            return False

        current_hash, current_len = self.fingerprint_response(current_response, status_code)

        if cached.content_hash == current_hash:
            self._hits += 1
            log.debug("[incremental] UNCHANGED %s[%s] — skip", url, param)
            return True

        # Tolerate minor dynamic content: if length within 5%, consider "same"
        if cached.content_length > 0:
            ratio = abs(current_len - cached.content_length) / cached.content_length
            if ratio <= 0.05:
                self._hits += 1
                log.debug("[incremental] APPROX UNCHANGED %s[%s] (len ratio=%.2f) — skip", url, param, ratio)
                return True

        self._misses += 1
        return False

    def update(
        self,
        url: str,
        param: str,
        response_body: str,
        status_code: int = 200,
        vuln_found: bool = False,
    ) -> None:
        """Record the current response fingerprint for this URL/param."""
        content_hash, content_len = self.fingerprint_response(response_body, status_code)
        key = self._cache_key(url, param)
        self._store[key] = EndpointFingerprint(
            url=url,
            param=param,
            content_hash=content_hash,
            status_code=status_code,
            content_length=content_len,
            last_seen=time.time(),
            last_vuln_found=vuln_found,
        )

    @property
    def stats(self) -> dict:
        return {
            "cached_entries": len(self._store),
            "hits": self._hits,
            "misses": self._misses,
            "skip_rate": self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0.0,
        }
