"""Tests for SOAP/WSDL scanner + XXE injection — Task 18.8."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_tools.vuln.soap_xxe import (
    SoapXxeScanner,
    WsdlEndpoint,
    XxeFinding,
    scan_soap_xxe,
)


def _mock_response(text: str, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    return resp


# ── WSDL detection ────────────────────────────────────────────────────────────

def test_looks_like_wsdl_positive():
    scanner = SoapXxeScanner("https://target.com")
    wsdl_text = """<?xml version="1.0"?>
    <definitions xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
        targetNamespace="http://target.com/service">
        <portType name="ServicePortType">
            <operation name="GetUser"/>
            <operation name="CreateUser"/>
        </portType>
    </definitions>"""
    assert scanner._looks_like_wsdl(wsdl_text) is True


def test_looks_like_wsdl_negative():
    scanner = SoapXxeScanner("https://target.com")
    html_text = "<html><body><h1>Hello World</h1></body></html>"
    assert scanner._looks_like_wsdl(html_text) is False


def test_parse_wsdl_extracts_operations():
    scanner = SoapXxeScanner("https://target.com")
    wsdl_text = """
    <definitions targetNamespace="http://example.com/ws">
        <service name="UserService"/>
        <operation name="GetUser"/>
        <operation name="CreateUser"/>
        <operation name="DeleteUser"/>
    </definitions>
    """
    ep = scanner._parse_wsdl("https://target.com/service.asmx", wsdl_text)
    assert ep.url == "https://target.com/service.asmx"
    assert len(ep.operations) == 3
    assert "GetUser" in ep.operations
    assert ep.service_name == "UserService"
    assert ep.namespace == "http://example.com/ws"


# ── XXE injection ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_xxe_linux_file_read_confirmed():
    """XXE scanner detects /etc/passwd in response."""
    scanner = SoapXxeScanner("https://target.com")

    mock_resp = _mock_response(
        "<?xml version='1.0'?><root>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:</root>"
    )

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=_mock_response("<html>404</html>", 404))
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("pentra_tools.vuln.soap_xxe.httpx.AsyncClient", return_value=mock_client):
        findings = await scanner._test_xxe(
            url="https://target.com/service.asmx",
            operations=[],
        )

    assert len(findings) >= 1
    assert findings[0].vuln_class == "XXE"
    assert findings[0].severity == "critical"
    assert "passwd" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_xxe_no_finding_on_normal_response():
    """XXE scanner returns no findings on normal responses."""
    scanner = SoapXxeScanner("https://target.com")

    mock_resp = _mock_response("<html><body>Normal page</body></html>")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=_mock_response("<html>404</html>", 404))
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("pentra_tools.vuln.soap_xxe.httpx.AsyncClient", return_value=mock_client):
        findings = await scanner._test_xxe(
            url="https://target.com/api/endpoint",
            operations=[],
        )

    # Should have at most 1 "potential blind XXE" finding (if collaborator set)
    # but no confirmed XXE
    confirmed = [f for f in findings if f.severity == "critical"]
    assert len(confirmed) == 0


@pytest.mark.asyncio
async def test_xxe_oob_sent_when_collaborator_configured():
    """OOB/blind XXE payload is sent when Burp Collaborator URL is provided."""
    scanner = SoapXxeScanner(
        "https://target.com",
        burp_collaborator="abc123.oastify.com",
    )

    mock_resp = _mock_response("<html>Processing...</html>")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=_mock_response("<html>404</html>", 404))
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("pentra_tools.vuln.soap_xxe.httpx.AsyncClient", return_value=mock_client):
        findings = await scanner._test_xxe(
            url="https://target.com/service",
            operations=[],
        )

    # Should have a "Potential Blind XXE" finding (OOB probe sent)
    blind_findings = [f for f in findings if "blind" in f.title.lower() or "potential" in f.title.lower()]
    assert len(blind_findings) >= 1
    assert "abc123.oastify.com" in blind_findings[0].evidence


@pytest.mark.asyncio
async def test_scan_soap_xxe_no_wsdl_no_crash():
    """scan_soap_xxe runs without error when target has no SOAP endpoints."""
    mock_resp = _mock_response("<html>404 Not Found</html>", 404)

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("pentra_tools.vuln.soap_xxe.httpx.AsyncClient", return_value=mock_client):
        results = await scan_soap_xxe("https://target.com")

    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_xxe_finding_to_dict_schema():
    """XxeFinding.to_dict() returns expected schema keys."""
    finding = XxeFinding(
        title="XXE — /etc/passwd",
        severity="critical",
        target_url="https://target.com/ws",
        payload="<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        evidence="root:x:0:0:",
        description="XXE confirmed",
    )
    d = finding.to_dict()
    assert d["vuln_class"] == "XXE"
    assert d["severity"] == "critical"
    assert d["source"] == "soap_xxe_scanner"
    assert "payload" in d
    assert "evidence" in d
