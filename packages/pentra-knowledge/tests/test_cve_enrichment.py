"""Tests for CVEEnrichmentService (Task 5.2).

All HTTP calls to NVD are mocked — no network access required.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_knowledge.services.cve_enrichment import (
    CVEData,
    CVEEnrichmentResult,
    CVEEnrichmentService,
    _extract_cve_ids_from_text,
    _parse_nvd_item,
)


# ── Helper: minimal NVD API response item ─────────────────────────────────────

def _nvd_item(
    cve_id: str = "CVE-2024-1234",
    score: float = 9.8,
    severity: str = "critical",
    desc: str = "A critical RCE vulnerability.",
) -> dict:
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": desc}],
            "published": "2024-06-01T00:00:00.000",
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/" + cve_id}],
            "configurations": [],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "baseSeverity": severity.upper(),
                        "cvssData": {
                            "baseScore": score,
                            "baseSeverity": severity.upper(),
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                    }
                ]
            },
        }
    }


def _nvd_response(items: list[dict]) -> dict:
    return {"resultsPerPage": len(items), "startIndex": 0, "totalResults": len(items), "vulnerabilities": items}


# ── _extract_cve_ids_from_text ─────────────────────────────────────────────────

def test_extract_cve_ids_single():
    ids = _extract_cve_ids_from_text("Found CVE-2024-1234 in dependency.")
    assert ids == ["CVE-2024-1234"]


def test_extract_cve_ids_multiple():
    ids = _extract_cve_ids_from_text("CVE-2023-0001 and CVE-2024-99999 both apply.")
    assert "CVE-2023-0001" in ids
    assert "CVE-2024-99999" in ids
    assert len(ids) == 2


def test_extract_cve_ids_deduplication():
    ids = _extract_cve_ids_from_text("CVE-2024-1234", "cve-2024-1234 again")
    # lowercase normalised to uppercase, deduplicated
    assert ids.count("CVE-2024-1234") == 1


def test_extract_cve_ids_no_match():
    ids = _extract_cve_ids_from_text("No CVE here", "just a plain text")
    assert ids == []


def test_extract_cve_ids_across_multiple_texts():
    ids = _extract_cve_ids_from_text("CVE-2024-0001", "CVE-2024-0002")
    assert len(ids) == 2


# ── _parse_nvd_item ────────────────────────────────────────────────────────────

def test_parse_nvd_item_returns_cve_data():
    item = _nvd_item("CVE-2024-5678", score=7.5, severity="high")
    result = _parse_nvd_item(item)
    assert result is not None
    assert result.cve_id == "CVE-2024-5678"
    assert result.cvss_score == 7.5
    assert result.severity == "high"


def test_parse_nvd_item_description_english():
    item = _nvd_item(desc="English description of the vuln.")
    result = _parse_nvd_item(item)
    assert result is not None
    assert "English description" in result.description


def test_parse_nvd_item_includes_references():
    item = _nvd_item("CVE-2024-9999")
    result = _parse_nvd_item(item)
    assert result is not None
    assert any("nvd.nist.gov" in ref for ref in result.references)


def test_parse_nvd_item_returns_none_on_bad_input():
    result = _parse_nvd_item({"invalid": "structure"})
    assert result is None


def test_parse_nvd_item_cvss_v2_fallback():
    item = {
        "cve": {
            "id": "CVE-2020-0001",
            "descriptions": [{"lang": "en", "value": "Old vuln"}],
            "published": "2020-01-01T00:00:00.000",
            "references": [],
            "configurations": [],
            "metrics": {
                "cvssMetricV2": [
                    {
                        "baseSeverity": "HIGH",
                        "cvssData": {
                            "baseScore": 8.0,
                            "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                        },
                    }
                ]
            },
        }
    }
    result = _parse_nvd_item(item)
    assert result is not None
    assert result.cvss_score == 8.0


# ── CVEEnrichmentService.enrich — explicit CVE IDs ────────────────────────────

@pytest.mark.asyncio
async def test_enrich_finds_explicit_cve_in_title():
    """If title contains a CVE ID, it should be returned directly."""
    service = CVEEnrichmentService()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _nvd_response([_nvd_item("CVE-2024-1234")])

    with patch("pentra_knowledge.services.cve_enrichment.asyncio.sleep", new=AsyncMock()):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)

            result = await service.enrich(
                title="Nuclei found CVE-2024-1234 in log4j",
                vuln_class="rce",
            )

    assert "CVE-2024-1234" in result.cve_ids
    assert result.cve_data is not None
    assert result.cve_data.cve_id == "CVE-2024-1234"
    assert result.enriched is True


@pytest.mark.asyncio
async def test_enrich_falls_back_to_keyword_search():
    """When no CVE ID in title, should keyword-search NVD."""
    service = CVEEnrichmentService()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _nvd_response([
        _nvd_item("CVE-2023-0001", score=9.0, severity="critical"),
        _nvd_item("CVE-2023-0002", score=7.0, severity="high"),
    ])

    with patch("pentra_knowledge.services.cve_enrichment.asyncio.sleep", new=AsyncMock()):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)

            result = await service.enrich(
                title="SQL injection in login form",
                vuln_class="sql_injection",
                tech_stack=["mysql"],
            )

    assert len(result.cve_ids) == 2
    # Most critical should be first
    assert result.cve_data is not None
    assert result.cve_data.cvss_score == 9.0
    assert result.enriched is True


@pytest.mark.asyncio
async def test_enrich_returns_empty_on_no_results():
    """When NVD returns nothing, result should be empty and enriched=False."""
    service = CVEEnrichmentService()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _nvd_response([])

    with patch("pentra_knowledge.services.cve_enrichment.asyncio.sleep", new=AsyncMock()):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)

            result = await service.enrich(
                title="Custom business logic bug",
                vuln_class="idor",
            )

    assert result.cve_ids == []
    assert result.cve_data is None
    assert result.enriched is False


@pytest.mark.asyncio
async def test_enrich_handles_http_error_gracefully():
    """Network errors should return empty result (not raise)."""
    import httpx as _httpx

    service = CVEEnrichmentService()

    with patch("pentra_knowledge.services.cve_enrichment.asyncio.sleep", new=AsyncMock()):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=_httpx.ConnectError("timeout"))

            result = await service.enrich(
                title="CVE-2024-1234 in some library",
                vuln_class="rce",
            )

    assert result.enriched is False


@pytest.mark.asyncio
async def test_enrich_uses_api_key_when_provided():
    """With API key, delay should be 0.7s (not 6.5s)."""
    service = CVEEnrichmentService(api_key="test-key-xyz")
    assert service._delay == 0.7
    assert service._api_key == "test-key-xyz"


def test_enrich_no_api_key_delay():
    """Without API key, delay should be 6.5s."""
    service = CVEEnrichmentService()
    assert service._delay == 6.5
