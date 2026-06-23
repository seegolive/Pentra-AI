from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_tools.osint.email_osint import BreachResult, EmailOSINT, EmailOSINTResult


def test_breach_result_severity_defaults():
    assert BreachResult(email="a@example.com", breached=False).severity == "INFO"
    assert BreachResult(email="a@example.com", breached=True).severity == "MEDIUM"
    assert BreachResult(email="a@example.com", breached=True, has_passwords=True).severity == "CRITICAL"


def test_extract_emails_from_text_dedupes_and_filters_domain():
    text = "Alice@Example.com bob@example.com mallory@evil.com alice@example.com"

    emails = EmailOSINT()._extract_emails_from_text(text, "example.com")

    assert emails == ["alice@example.com", "bob@example.com"]


def test_generate_email_patterns():
    patterns = EmailOSINT().generate_email_patterns("example.com", "Alice", "Smith")

    assert "alice.smith@example.com" in patterns
    assert "asmith@example.com" in patterns
    assert "smith@example.com" in patterns
    assert len(patterns) == len(set(patterns))


@pytest.mark.asyncio
async def test_enumerate_emails_combines_harvester_and_hunter():
    osint = EmailOSINT()
    osint._run_harvester = AsyncMock(return_value=["a@example.com", "b@example.com"])  # type: ignore[method-assign]
    osint._run_hunter = AsyncMock(return_value=["b@example.com", "c@example.com"])  # type: ignore[method-assign]

    emails = await osint.enumerate_emails("example.com", hunter_api_key="hunter-key")

    assert emails == ["a@example.com", "b@example.com", "c@example.com"]


@pytest.mark.asyncio
async def test_run_harvester_skips_when_binary_missing():
    with patch("shutil.which", return_value=None):
        emails = await EmailOSINT()._run_harvester("example.com")

    assert emails == []


@pytest.mark.asyncio
async def test_run_hunter_success():
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "data": {
            "emails": [
                {"value": "Alice@Example.com"},
                {"value": "bob@example.com"},
                {},
            ]
        }
    }

    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.get = AsyncMock(return_value=response)
        emails = await EmailOSINT()._run_hunter("example.com", "key")

    assert emails == ["alice@example.com", "bob@example.com"]


@pytest.mark.asyncio
async def test_check_breaches_200_with_passwords():
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = [
        {"Name": "BreachOne", "DataClasses": ["Email addresses", "Passwords"]},
        {"Name": "BreachTwo", "DataClasses": ["Email addresses"]},
    ]

    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.get = AsyncMock(return_value=response)
        results = await EmailOSINT().check_breaches(["a@example.com"], delay=0)

    result = results["a@example.com"]
    assert result.breached is True
    assert result.breach_count == 2
    assert result.breaches == ["BreachOne", "BreachTwo"]
    assert result.has_passwords is True
    assert result.severity == "CRITICAL"


@pytest.mark.asyncio
async def test_check_breaches_404_not_breached():
    response = MagicMock()
    response.status_code = 404

    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.get = AsyncMock(return_value=response)
        results = await EmailOSINT().check_breaches(["a@example.com"], delay=0)

    assert results["a@example.com"].breached is False


@pytest.mark.asyncio
async def test_check_breaches_handles_api_error():
    with patch("httpx.AsyncClient") as client_cls:
        client_cls.return_value.__aenter__.return_value.get = AsyncMock(side_effect=RuntimeError("boom"))
        results = await EmailOSINT().check_breaches(["a@example.com"], delay=0)

    assert results == {}


@pytest.mark.asyncio
async def test_run_returns_email_osint_result_with_critical_emails():
    osint = EmailOSINT()
    osint.enumerate_emails = AsyncMock(return_value=["a@example.com", "b@example.com"])  # type: ignore[method-assign]
    osint.check_breaches = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "a@example.com": BreachResult("a@example.com", breached=True, has_passwords=True),
            "b@example.com": BreachResult("b@example.com", breached=False),
        }
    )

    result = await osint.run("example.com")

    assert isinstance(result, EmailOSINTResult)
    assert result.emails == ["a@example.com", "b@example.com"]
    assert result.critical_emails == ["a@example.com"]
