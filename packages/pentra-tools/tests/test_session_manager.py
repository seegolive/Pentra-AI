"""Tests for SessionManager — Task 18.6 Authenticated Scan."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_tools.auth.session_manager import (
    AuthCredentials,
    SessionManager,
    SessionResult,
    _detect_login_form,
    _fill_form,
    auto_login,
)


# ── Unit tests: static auth ───────────────────────────────────────────────────

def test_cookie_auth_returns_cookies():
    creds = AuthCredentials(type="cookie", value="session=abc123; csrftoken=xyz456")
    mgr = SessionManager(creds)
    headers, cookies = mgr.get_auth_headers()
    assert cookies == {"session": "abc123", "csrftoken": "xyz456"}
    assert headers == {}


def test_bearer_auth_returns_authorization_header():
    creds = AuthCredentials(type="bearer", value="mytoken123")
    mgr = SessionManager(creds)
    headers, cookies = mgr.get_auth_headers()
    assert headers["Authorization"] == "Bearer mytoken123"
    assert cookies == {}


def test_bearer_auth_strips_existing_prefix():
    creds = AuthCredentials(type="bearer", value="Bearer mytoken123")
    mgr = SessionManager(creds)
    headers, _ = mgr.get_auth_headers()
    assert headers["Authorization"] == "Bearer mytoken123"


def test_basic_auth_encodes_base64():
    import base64
    creds = AuthCredentials(type="basic", value="admin:password123")
    mgr = SessionManager(creds)
    headers, _ = mgr.get_auth_headers()
    expected = base64.b64encode(b"admin:password123").decode()
    assert headers["Authorization"] == f"Basic {expected}"


def test_custom_header_auth():
    creds = AuthCredentials(type="header", value="secret-api-key", header_name="X-API-Key")
    mgr = SessionManager(creds)
    headers, _ = mgr.get_auth_headers()
    assert headers["X-API-Key"] == "secret-api-key"


def test_empty_credentials_is_empty():
    creds = AuthCredentials(type="cookie", value="")
    assert creds.is_empty() is True


def test_non_empty_credentials():
    creds = AuthCredentials(type="cookie", value="session=abc")
    assert creds.is_empty() is False


# ── Unit tests: form detection ────────────────────────────────────────────────

def test_detect_login_form_finds_password_field():
    html = """
    <html><body>
    <form method="POST" action="/login">
        <input type="text" name="username" value="">
        <input type="password" name="password" value="">
        <input type="submit" value="Login">
    </form>
    </body></html>
    """
    form = _detect_login_form(html)
    assert form is not None
    assert "password" in form["inputs"]
    assert form["method"] == "post"
    assert form["action"] == "/login"


def test_detect_login_form_returns_none_for_no_password():
    html = "<form><input type='text' name='q'></form>"
    form = _detect_login_form(html)
    assert form is None


def test_fill_form_fills_username_password():
    form = {
        "action": "/login",
        "method": "post",
        "inputs": {
            "username": {"type": "text", "value": ""},
            "password": {"type": "password", "value": ""},
            "_csrf": {"type": "hidden", "value": "token123"},
        },
    }
    filled = _fill_form(form, "admin", "secret")
    assert filled["username"] == "admin"
    assert filled["password"] == "secret"
    assert filled["_csrf"] == "token123"  # CSRF token preserved


# ── Integration: auto_login ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_auto_login_success():
    """auto_login: simulates successful login returning session cookie."""
    html_page = """
    <html><body>
    <form method="POST" action="/login">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="hidden" name="_token" value="csrf123">
        <input type="submit" value="Login">
    </form>
    </body></html>
    """

    get_response = MagicMock()
    get_response.text = html_page
    get_response.cookies = {}

    post_response = MagicMock()
    post_response.status_code = 302
    post_response.cookies = {"session": "s3cr3t", "user_id": "42"}
    post_response.url = "https://target.com/dashboard"

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=get_response)
    mock_client.post = AsyncMock(return_value=post_response)

    with patch("pentra_tools.auth.session_manager.httpx.AsyncClient", return_value=mock_client):
        result = await auto_login(
            login_url="https://target.com/login",
            username="admin",
            password="password",
        )

    assert result.success is True
    assert "session" in result.cookies
    assert result.cookies["session"] == "s3cr3t"


@pytest.mark.asyncio
async def test_auto_login_failure_returns_error():
    """auto_login: network error returns SessionResult with success=False."""
    creds = AuthCredentials(
        type="auto_login",
        login_url="https://nonexistent.example.com/login",
        username="user",
        password="pass",
    )
    mgr = SessionManager(creds)

    with patch("pentra_tools.auth.session_manager.httpx.AsyncClient") as mock_cls:
        mock_instance = AsyncMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=None)
        mock_instance.get = AsyncMock(side_effect=Exception("Connection refused"))
        mock_cls.return_value = mock_instance

        result = await mgr.auto_login()

    assert result.success is False
    assert result.error != ""


def test_as_cookie_header_format():
    creds = AuthCredentials(type="cookie", value="session=abc; user=bob")
    mgr = SessionManager(creds)
    cookie_str = mgr.as_cookie_header()
    assert "session=abc" in cookie_str
    assert "user=bob" in cookie_str
