"""Task 5.2 — CVE enrichment service.

Queries the NVD (National Vulnerability Database) REST API v2.0 to find
CVE records that correlate with a security finding.

Strategy:
1. If the finding was created by Nuclei and contains a CVE ID in its
   ``discovered_by`` field or title, extract and look it up directly.
2. Otherwise, search NVD by keyword (vuln_class + tech stack tokens).

NVD rate limits (without API key): 5 requests per 30 s.
NVD rate limits (with API key):   50 requests per 30 s.
Set NVD_API_KEY env var to get the higher limit.
"""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime

import httpx
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class CVEData(BaseModel):
    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str = "unknown"
    published: str = ""
    references: list[str] = Field(default_factory=list)
    cpe: list[str] = Field(default_factory=list)


class CVEEnrichmentResult(BaseModel):
    cve_ids: list[str] = Field(default_factory=list)
    cve_data: CVEData | None = None          # first / most severe match
    enriched: bool = False


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_cve_ids_from_text(*texts: str) -> list[str]:
    """Pull CVE IDs out of arbitrary strings (title, description, tags)."""
    found: list[str] = []
    for text in texts:
        for m in _CVE_RE.finditer(text or ""):
            cid = m.group(0).upper()
            if cid not in found:
                found.append(cid)
    return found


def _parse_nvd_item(item: dict) -> CVEData | None:
    """Parse one NVD API v2 vulnerabilities item into a CVEData object."""
    try:
        cve = item["cve"]
        cve_id: str = cve["id"]

        # Description (English preferred)
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS v3 preferred, fall back to v2
        cvss_score: float | None = None
        cvss_vector: str | None = None
        severity = "unknown"

        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                entry = entries[0]
                data = entry.get("cvssData", {})
                cvss_score = data.get("baseScore")
                cvss_vector = data.get("vectorString")
                severity = (
                    entry.get("baseSeverity")
                    or data.get("baseSeverity", "unknown")
                ).lower()
                break

        # References
        refs = [r["url"] for r in cve.get("references", []) if r.get("url")][:5]

        # CPE (affected software identifiers)
        cpes: list[str] = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe and cpe not in cpes:
                        cpes.append(cpe)
        cpes = cpes[:10]

        published = cve.get("published", "")[:10]  # YYYY-MM-DD

        return CVEData(
            cve_id=cve_id,
            description=desc[:500],
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            published=published,
            references=refs,
            cpe=cpes,
        )
    except (KeyError, IndexError, TypeError) as exc:
        log.debug("Failed to parse NVD item: %s", exc)
        return None


# ── Service ───────────────────────────────────────────────────────────────────

class CVEEnrichmentService:
    """Enrich a security finding with CVE data from NVD."""

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key
        # Respect NVD rate limits (conservative: 1 req / 6 s without key)
        self._delay = 0.7 if api_key else 6.5

    async def enrich(
        self,
        *,
        title: str,
        vuln_class: str,
        tech_stack: list[str] | None = None,
        description: str | None = None,
    ) -> CVEEnrichmentResult:
        """
        Find CVE correlations for a finding.

        Returns a ``CVEEnrichmentResult`` with up to 5 CVE IDs and full
        detail for the first / most critical match.
        """
        # Step 1: Look for explicit CVE IDs in the title / description
        explicit = _extract_cve_ids_from_text(title, description or "")

        if explicit:
            # Look up the first one directly for full detail
            detail = await self._get_cve(explicit[0])
            return CVEEnrichmentResult(
                cve_ids=explicit,
                cve_data=detail,
                enriched=detail is not None,
            )

        # Step 2: Keyword search in NVD
        keywords: list[str] = [vuln_class.replace("_", " ")]
        if tech_stack:
            keywords.extend(tech_stack[:2])  # limit keyword width
        query = " ".join(keywords)[:200]

        results = await self._search_nvd(query)
        if not results:
            return CVEEnrichmentResult()

        # Sort by CVSS score descending
        results.sort(key=lambda x: x.cvss_score or 0.0, reverse=True)

        return CVEEnrichmentResult(
            cve_ids=[r.cve_id for r in results],
            cve_data=results[0],
            enriched=True,
        )

    async def _get_cve(self, cve_id: str) -> CVEData | None:
        """Fetch a single CVE by ID."""
        await asyncio.sleep(self._delay)
        headers = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    NVD_API_BASE,
                    params={"cveId": cve_id},
                    headers=headers,
                )
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    return _parse_nvd_item(vulns[0])
        except httpx.HTTPError as exc:
            log.warning("[cve_enrichment] HTTP error fetching %s: %s", cve_id, exc)
        return None

    async def _search_nvd(self, keyword: str, top_k: int = 5) -> list[CVEData]:
        """Search NVD by keyword, returning up to top_k results."""
        await asyncio.sleep(self._delay)
        headers = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                response = await client.get(
                    NVD_API_BASE,
                    params={
                        "keywordSearch": keyword,
                        "resultsPerPage": top_k,
                    },
                    headers=headers,
                )
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                results = []
                for item in vulns:
                    parsed = _parse_nvd_item(item)
                    if parsed:
                        results.append(parsed)
                return results
        except httpx.HTTPError as exc:
            log.warning("[cve_enrichment] HTTP error searching NVD: %s", exc)
        return []
