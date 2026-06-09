"""Tests for Second-Order SQLi and Business Logic testers — Sprint 20 P3."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_tools.vuln.second_order_sqli import SecondOrderFinding, run_second_order_sqli_test
from pentra_tools.vuln.business_logic import BizLogicFinding, run_business_logic_test


# ── Second-Order SQLi ─────────────────────────────────────────────────────────

def test_second_order_finding_to_finding_schema():
    f = SecondOrderFinding(
        title="Second-Order SQLi — /register[username]",
        severity="high",
        write_endpoint="https://t.com/register",
        read_endpoint="https://t.com/profile",
        payload="'; WAITFOR DELAY '0:0:5'--",
        technique="MSSQL WAITFOR",
        evidence="Read endpoint took 5.2s after injection",
    )
    d = f.to_finding()
    assert d["vuln_class"] == "SECOND_ORDER_SQLI"
    assert d["severity"] == "high"
    assert d["source"] == "second_order_sqli_tester"
    assert "remediation" in d
    assert "second-order" in d["description"].lower()


@pytest.mark.asyncio
async def test_second_order_sqli_timing_detection():
    """Timing delay on read endpoint should confirm second-order SQLi."""
    write_resp = MagicMock(); write_resp.status_code = 200; write_resp.text = "registered"

    call_count = [0]
    def fast_time():
        call_count[0] += 1
        return 0.0 if call_count[0] == 1 else 5.5  # simulates 5.5s delay

    read_resp = MagicMock(); read_resp.status_code = 200; read_resp.text = "profile"

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=write_resp)
    mock_client.get = AsyncMock(return_value=read_resp)

    with patch("pentra_tools.vuln.second_order_sqli.httpx.AsyncClient", return_value=mock_client), \
         patch("pentra_tools.vuln.second_order_sqli.time.monotonic", side_effect=fast_time), \
         patch("pentra_tools.vuln.second_order_sqli.asyncio.sleep", return_value=None):
        findings = await run_second_order_sqli_test(
            base_url="https://target.com",
            write_endpoints=[{
                "path": "/register", "method": "POST",
                "fields": {"username": "", "password": "Test@2026!"},
                "inject_param": "username",
            }],
            read_endpoints=["https://target.com/profile"],
        )

    assert len(findings) == 1
    assert findings[0]["vuln_class"] == "SECOND_ORDER_SQLI"


@pytest.mark.asyncio
async def test_second_order_sqli_no_delay_no_finding():
    """No delay on read endpoint → no finding."""
    write_resp = MagicMock(); write_resp.status_code = 200; write_resp.text = "ok"
    read_resp = MagicMock(); read_resp.status_code = 200; read_resp.text = "profile"

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=write_resp)
    mock_client.get = AsyncMock(return_value=read_resp)

    # Fast monotonic — always returns 0 (< 4.5s threshold)
    with patch("pentra_tools.vuln.second_order_sqli.httpx.AsyncClient", return_value=mock_client), \
         patch("pentra_tools.vuln.second_order_sqli.time.monotonic", return_value=0.3), \
         patch("pentra_tools.vuln.second_order_sqli.asyncio.sleep", return_value=None):
        findings = await run_second_order_sqli_test(
            base_url="https://target.com",
            write_endpoints=[{"path": "/register", "method": "POST",
                              "fields": {"username": ""}, "inject_param": "username"}],
            read_endpoints=["https://target.com/profile"],
        )

    assert len(findings) == 0


# ── Business Logic ────────────────────────────────────────────────────────────

def test_biz_logic_finding_schema():
    f = BizLogicFinding(
        title="Negative Quantity Accepted",
        severity="critical",
        endpoint="https://t.com/cart",
        attack_type="Negative quantity manipulation",
        payload={"quantity": -1},
        evidence="Server returned 200 with negative quantity",
        remediation="Validate server-side",
    )
    d = f.to_finding()
    assert d["vuln_class"] == "BUSINESS_LOGIC"
    assert d["severity"] == "critical"
    assert d["source"] == "business_logic_tester"
    assert "remediation" in d


@pytest.mark.asyncio
async def test_business_logic_negative_qty_detected():
    """Negative quantity accepted → business logic finding."""
    cart_resp = MagicMock()
    cart_resp.status_code = 200
    cart_resp.text = '{"status":"success","item_added":true,"total":"-10.00"}'

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=cart_resp)
    mock_client.get = AsyncMock(return_value=MagicMock(status_code=404, text=""))

    with patch("pentra_tools.vuln.business_logic.httpx.AsyncClient", return_value=mock_client), \
         patch("pentra_tools.vuln.business_logic.asyncio.sleep", return_value=None):
        findings = await run_business_logic_test("https://target.com")

    assert len(findings) >= 1
    biz = [f for f in findings if f["vuln_class"] == "BUSINESS_LOGIC"]
    assert len(biz) >= 1


@pytest.mark.asyncio
async def test_business_logic_no_finding_on_rejection():
    """Properly rejecting negative qty → no finding."""
    reject_resp = MagicMock()
    reject_resp.status_code = 400
    reject_resp.text = '{"error":"invalid quantity"}'

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=reject_resp)
    mock_client.get = AsyncMock(return_value=MagicMock(status_code=404, text=""))

    with patch("pentra_tools.vuln.business_logic.httpx.AsyncClient", return_value=mock_client), \
         patch("pentra_tools.vuln.business_logic.asyncio.sleep", return_value=None):
        findings = await run_business_logic_test("https://secure.target.com")

    assert len(findings) == 0
