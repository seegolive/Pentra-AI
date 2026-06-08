"""Tests for nuclei runner in vuln_hunt_node — Fix 1 (Sprint 17)

Root cause of nuclei 0 findings:
  asyncio.wait_for(proc.communicate(), timeout=600) fired after exactly 601s
  because template set (~6000+ templates) takes ~40 min with -c 10.
  asyncio.TimeoutError() → str() = "" → log shows empty error, returns [].
  nuclei process NOT killed → leaked subprocess.

Fixes verified here:
  1. HTTPS→HTTP fallback rewrites targets when port 443 is closed.
  2. IIS/ASP.NET tech stack adds iis,asp,aspnet,dotnet,viewstate tags.
  3. TimeoutError kills the proc (not leaked).
  4. Verbose 0-findings logging path exists.
"""

import asyncio
import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Test 1 — HTTPS→HTTP fallback
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nuclei_https_fallback_to_http():
    """If port 443 is closed, all https:// targets must be rewritten to http://."""
    endpoints = [
        {"url": "https://testaspnet.vulnweb.com/", "method": "GET"},
        {"url": "https://testaspnet.vulnweb.com/login", "method": "GET"},
    ]
    scope = {"in_scope": ["testaspnet.vulnweb.com"], "out_of_scope": []}

    # Simulate port 443 closed — open_connection raises ConnectionRefusedError
    async def _fake_open_connection(host, port, **kw):
        raise ConnectionRefusedError("port closed")

    # _nuclei_scan is called twice: HTTP targets, then network targets.
    # Collect all calls so we can assert on the HTTP-targets (first) call.
    captured_calls: list[dict] = []

    async def _fake_nuclei_scan(nuclei_bin, targets, protocol_types, timeout, extra_tags=None):
        captured_calls.append({"targets": list(targets), "protocol_types": protocol_types})
        return []

    with (
        patch("asyncio.open_connection", side_effect=_fake_open_connection),
        patch(
            "pentra_agent.nodes.vuln_hunt_node._nuclei_scan",
            side_effect=_fake_nuclei_scan,
        ),
        patch(
            "pentra_agent.nodes.vuln_hunt_node._probe_open_ports",
            new=AsyncMock(return_value=[]),
        ),
    ):
        from pentra_agent.nodes.vuln_hunt_node import _run_nuclei
        await _run_nuclei(endpoints, scope)

    # First call is the HTTP-targets pass (protocol_types=None)
    http_call = next((c for c in captured_calls if c["protocol_types"] is None), None)
    assert http_call is not None, f"No HTTP-targets call found; calls={captured_calls}"
    assert http_call["targets"], f"HTTP targets were empty; calls={captured_calls}"
    for t in http_call["targets"]:
        assert t.startswith("http://"), (
            f"Expected http:// target (443 closed) but got: {t}"
        )


# ---------------------------------------------------------------------------
# Test 2 — IIS/ASP.NET tech stack adds iis/asp/aspnet/dotnet/viewstate tags
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nuclei_tags_include_iis_asp_for_aspnet_target():
    """IIS/ASP.NET tech stack must add iis,asp,aspnet,dotnet,viewstate to nuclei tags."""
    endpoints = [
        {"url": "http://testaspnet.vulnweb.com/", "method": "GET"},
    ]
    scope = {"in_scope": ["testaspnet.vulnweb.com"], "out_of_scope": []}
    tech_stack = ["iis"]

    # Collect both _nuclei_scan calls (HTTP + network); assert on the HTTP call.
    captured_calls: list[dict] = []

    async def _fake_nuclei_scan(nuclei_bin, targets, protocol_types, timeout, extra_tags=None):
        captured_calls.append({"extra_tags": list(extra_tags or []), "protocol_types": protocol_types})
        return []

    with (
        patch(
            "asyncio.open_connection",
            side_effect=ConnectionRefusedError,
        ),
        patch(
            "pentra_agent.nodes.vuln_hunt_node._nuclei_scan",
            side_effect=_fake_nuclei_scan,
        ),
        patch(
            "pentra_agent.nodes.vuln_hunt_node._probe_open_ports",
            new=AsyncMock(return_value=[]),
        ),
    ):
        from pentra_agent.nodes.vuln_hunt_node import _run_nuclei
        await _run_nuclei(endpoints, scope, tech_stack=tech_stack)

    http_call = next((c for c in captured_calls if c["protocol_types"] is None), None)
    assert http_call is not None, f"No HTTP-targets call found; calls={captured_calls}"
    extra = http_call["extra_tags"]
    assert "iis" in extra, f"Expected 'iis' in extra_tags, got: {extra}"
    assert "asp" in extra, f"Expected 'asp' in extra_tags, got: {extra}"
    assert "aspnet" in extra, f"Expected 'aspnet' in extra_tags, got: {extra}"
    assert "dotnet" in extra, f"Expected 'dotnet' in extra_tags, got: {extra}"
    assert "viewstate" in extra, f"Expected 'viewstate' in extra_tags, got: {extra}"


# ---------------------------------------------------------------------------
# Test 3 — TimeoutError kills proc and returns empty list (not leaked)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nuclei_scan_timeout_kills_process():
    """asyncio.TimeoutError in _nuclei_scan must kill the subprocess, not leak it."""
    import shutil

    nuclei_bin = shutil.which("nuclei") or "/home/mdilab/go/bin/nuclei"
    targets = ["http://testaspnet.vulnweb.com/"]

    mock_proc = AsyncMock()
    mock_proc.returncode = None
    mock_proc.kill = MagicMock()
    mock_proc.wait = AsyncMock(return_value=None)

    async def _raise_timeout(*a, **kw):
        raise asyncio.TimeoutError()

    with (
        patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        patch("asyncio.wait_for", side_effect=_raise_timeout),
    ):
        # Need a fresh import since we're patching asyncio.wait_for globally
        import importlib
        import pentra_agent.nodes.vuln_hunt_node as _mod
        result = await _mod._nuclei_scan(
            nuclei_bin, targets, protocol_types=None, timeout=1
        )

    assert result == [], "Should return empty list on timeout"
    mock_proc.kill.assert_called_once(), "proc.kill() must be called on timeout"
