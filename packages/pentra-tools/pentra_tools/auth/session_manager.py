"""SessionManager — Authenticated scan support for Pentra AI.

Inspired by reNgine authenticated scan feature.
Supports:
  - Cookie-based auth (paste Cookie: header value)
  - Bearer token (Authorization: Bearer <token>)
  - Auto-login via HTML form submission (auto-detect form fields)
  - Basic auth (username:password)

Usage:
    # Option 1: provide pre-captured session cookie
    creds = AuthCredentials(type="cookie", value="session=abc123; csrftoken=xyz")
    mgr = SessionManager(creds)
    headers, cookies = mgr.get_auth_headers()

    # Option 2: auto-login
    creds = AuthCredentials(
        type="auto_login",
        login_url="https://target.com/login",
        username="admin",
        password="password123",
    )
    mgr = SessionManager(creds)
    result = await mgr.auto_login()
    # result.cookies / result.headers are populated after login
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Literal
from urllib.parse import urlencode, urljoin, urlparse

import httpx

log = logging.getLogger(__name__)


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class AuthCredentials:
    """Authentication credentials for a scan session.

    Attributes:
        type:       Auth type — "cookie", "bearer", "basic", "auto_login", "header"
        value:      Pre-captured value (Cookie header string for "cookie",
                    token for "bearer", "user:pass" for "basic",
                    raw header value for "header")
        header_name: Custom header name when type="header" (default: "Authorization")
        login_url:  URL to POST credentials to (required for "auto_login")
        username:   Login username (required for "auto_login" / "basic")
        password:   Login password (required for "auto_login" / "basic")
        proxy_url:  Optional HTTP proxy for login request (e.g. Burp: "http://127.0.0.1:8082")
    """
    type: Literal["cookie", "bearer", "basic", "auto_login", "header"]
    value: str = ""
    header_name: str = "Authorization"
    login_url: str = ""
    username: str = ""
    password: str = ""
    proxy_url: str = ""

    def is_empty(self) -> bool:
        """Return True when no credentials are configured."""
        if self.type in ("cookie", "bearer", "basic", "header"):
            return not self.value
        if self.type == "auto_login":
            return not (self.login_url and self.username)
        return True


@dataclass
class SessionResult:
    """Result of a login attempt."""
    success: bool
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    status_code: int = 0
    error: str = ""
    cookie_header: str = ""   # Flat "name=value; name2=value2" string for Burp


# ── HTML form parser ──────────────────────────────────────────────────────────

class _FormParser(HTMLParser):
    """Minimal HTML form parser to extract <form> action + <input> fields."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": attr.get("action", ""),
                "method": (attr.get("method") or "post").lower(),
                "inputs": {},
            }
        elif tag == "input" and self._current_form is not None:
            name = attr.get("name", "")
            value = attr.get("value", "") or ""
            input_type = (attr.get("type") or "text").lower()
            if name:
                self._current_form["inputs"][name] = {
                    "type": input_type,
                    "value": value,
                }

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _detect_login_form(html: str) -> dict | None:
    """Parse HTML and return the most likely login form dict or None."""
    parser = _FormParser()
    parser.feed(html)

    # Score forms — prefer ones with password fields
    best: dict | None = None
    best_score = -1
    for form in parser.forms:
        score = 0
        inputs = form.get("inputs", {})
        for name, info in inputs.items():
            if info["type"] == "password":
                score += 10
            if any(kw in name.lower() for kw in ("user", "login", "email", "name")):
                score += 5
            if any(kw in name.lower() for kw in ("pass", "pwd", "secret")):
                score += 5
        if score > best_score:
            best_score = score
            best = form

    return best if best_score > 0 else None


def _fill_form(form: dict, username: str, password: str) -> dict[str, str]:
    """Fill login form inputs, substituting username/password into likely fields."""
    filled: dict[str, str] = {}
    for name, info in form.get("inputs", {}).items():
        itype = info["type"]
        if itype == "hidden":
            # Keep CSRF tokens and hidden fields as-is
            filled[name] = info["value"]
        elif itype == "password":
            filled[name] = password
        elif any(kw in name.lower() for kw in ("user", "login", "email", "name")):
            filled[name] = username
        elif itype in ("submit", "button", "image", "reset"):
            # include submit buttons so server sees a real submission
            if info["value"]:
                filled[name] = info["value"]
        else:
            filled[name] = info["value"]
    return filled


# ── Main class ────────────────────────────────────────────────────────────────

class SessionManager:
    """Manages authentication state for an authenticated scan session."""

    def __init__(self, credentials: AuthCredentials) -> None:
        self.credentials = credentials
        self._session_result: SessionResult | None = None

    # ── Static auth (no login needed) ─────────────────────────────────

    def get_auth_headers(self) -> tuple[dict[str, str], dict[str, str]]:
        """Return (extra_headers, cookies) to inject into every request.

        For static auth types (cookie, bearer, basic, header).
        Raises ValueError for auto_login (call auto_login() first).
        """
        creds = self.credentials
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}

        if creds.type == "cookie":
            # Parse "name=value; name2=value2" into a cookies dict
            for part in creds.value.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()

        elif creds.type == "bearer":
            token = creds.value.lstrip("Bearer ").strip()
            headers["Authorization"] = f"Bearer {token}"

        elif creds.type == "basic":
            import base64 as _b64
            if ":" in creds.value:
                encoded = _b64.b64encode(creds.value.encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
            elif creds.username and creds.password:
                raw = f"{creds.username}:{creds.password}"
                encoded = _b64.b64encode(raw.encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"

        elif creds.type == "header":
            headers[creds.header_name] = creds.value

        elif creds.type == "auto_login":
            if self._session_result and self._session_result.success:
                return self._session_result.headers, self._session_result.cookies
            raise ValueError("auto_login credentials require calling auto_login() first")

        return headers, cookies

    # ── Auto-login ────────────────────────────────────────────────────

    async def auto_login(self, proxy_url: str | None = None) -> SessionResult:
        """Perform automatic login by:
        1. GET the login page
        2. Parse the login form
        3. Fill credentials + CSRF tokens
        4. POST the form
        5. Extract session cookies from response

        Returns a SessionResult with success/cookies populated.
        """
        creds = self.credentials
        effective_proxy = proxy_url or creds.proxy_url or None

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=30.0,
                verify=False,  # noqa: S501 — internal test targets may have self-signed certs
                **({"proxy": effective_proxy} if effective_proxy else {}),
            ) as client:

                # Step 1: GET login page
                log.info("[auth] GET login page: %s", creds.login_url)
                get_resp = await client.get(creds.login_url)
                page_html = get_resp.text
                login_cookies = dict(get_resp.cookies)

                # Step 2: Parse login form
                form = _detect_login_form(page_html)
                if not form:
                    log.warning("[auth] No login form found at %s — trying POST to URL directly", creds.login_url)
                    # Fallback: POST username/password directly to the login URL
                    form = {
                        "action": "",
                        "method": "post",
                        "inputs": {
                            "username": {"type": "text", "value": ""},
                            "password": {"type": "password", "value": ""},
                        },
                    }

                # Step 3: Fill form
                form_data = _fill_form(form, creds.username, creds.password)
                log.debug("[auth] Form data (keys): %s", list(form_data.keys()))

                # Step 4: Resolve POST action URL
                action = form.get("action", "") or ""
                if action.startswith("http"):
                    post_url = action
                elif action:
                    post_url = urljoin(creds.login_url, action)
                else:
                    post_url = creds.login_url

                # Step 5: POST login
                log.info("[auth] POST login → %s", post_url)
                post_resp = await client.post(
                    post_url,
                    data=form_data,
                    cookies=login_cookies,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                # Step 6: Extract cookies from all responses in the redirect chain
                all_cookies: dict[str, str] = {}
                all_cookies.update(login_cookies)
                all_cookies.update(dict(post_resp.cookies))

                # Step 7: Detect success — check for session cookies or redirect away from login
                session_indicators = ["session", "token", "auth", "user", "logged", "sid", "jwt"]
                has_session_cookie = any(
                    any(ind in k.lower() for ind in session_indicators)
                    for k in all_cookies
                )
                redirected_away = (
                    post_resp.status_code in (200, 302, 303)
                    and creds.login_url not in str(post_resp.url)
                )
                login_success = has_session_cookie or redirected_away

                if login_success:
                    log.info(
                        "[auth] Auto-login SUCCESS — %d cookies, status=%d",
                        len(all_cookies), post_resp.status_code,
                    )
                else:
                    log.warning(
                        "[auth] Auto-login may have FAILED — status=%d, url=%s, cookies=%s",
                        post_resp.status_code, post_resp.url, list(all_cookies.keys()),
                    )

                cookie_header = "; ".join(f"{k}={v}" for k, v in all_cookies.items())
                result = SessionResult(
                    success=login_success,
                    cookies=all_cookies,
                    headers={},
                    status_code=post_resp.status_code,
                    cookie_header=cookie_header,
                )
                self._session_result = result
                return result

        except Exception as exc:
            log.error("[auth] auto_login failed: %s", exc)
            result = SessionResult(success=False, error=str(exc))
            self._session_result = result
            return result

    def as_cookie_header(self) -> str:
        """Return a flat 'name=value; ...' cookie header string for Burp injection."""
        _, cookies = self.get_auth_headers()
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def as_auth_header(self) -> str | None:
        """Return Authorization header value, or None if not applicable."""
        headers, _ = self.get_auth_headers()
        return headers.get("Authorization") or headers.get(self.credentials.header_name)


# ── Convenience function ──────────────────────────────────────────────────────

async def auto_login(
    login_url: str,
    username: str,
    password: str,
    proxy_url: str | None = None,
) -> SessionResult:
    """Convenience wrapper: auto-login and return SessionResult."""
    creds = AuthCredentials(
        type="auto_login",
        login_url=login_url,
        username=username,
        password=password,
    )
    mgr = SessionManager(creds)
    return await mgr.auto_login(proxy_url=proxy_url)
