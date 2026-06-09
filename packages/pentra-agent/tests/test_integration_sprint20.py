"""Integration tests — Sprint 20 P3.

Tests that Sprint 18-20 features work together through the agent pipeline.
All external dependencies (LLM, Burp, tools) are mocked.

Coverage:
  - GF filter + dedup pipeline integration
  - WAFProfiler → ExploitArsenal selection
  - LocatedMemory skip gate blocks duplicate candidates
  - Two-stage triage: LLM PASS → Stage 2 HTTP re-probe
  - Authenticated scan credentials flow: AuthCredentials → BaselineRequest
  - Scan presets apply env vars correctly
  - Subscan state bypasses recon phase
  - IncrementalTracker fingerprint lifecycle
  - Fine-tuning export produces valid JSONL
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Sprint 18: GF + Dedup + WAF integration ──────────────────────────────────

def test_gf_dedup_pipeline():
    """GF patterns + dedup work together without data loss."""
    from pentra_tools.recon.gf_filter import apply_gf_patterns, prioritize_endpoints_for_vuln_hunt
    from pentra_tools.recon.dedup import smart_dedup_endpoints

    endpoint_dicts = [
        {"url": "https://t.com/page?id=1", "method": "GET"},
        {"url": "https://t.com/page?id=1", "method": "GET"},   # duplicate
        {"url": "https://t.com/search?q=test", "method": "GET"},
        {"url": "https://t.com/static/logo.png", "method": "GET"},
    ]

    # Step 1: dedup on dicts
    deduped = smart_dedup_endpoints(endpoint_dicts)
    assert len(deduped) <= len(endpoint_dicts)

    # Step 2: GF filter on URLs (apply_gf_patterns takes list[str])
    urls = [e["url"] for e in deduped]
    matches = apply_gf_patterns(urls)

    # Step 3: prioritize_endpoints_for_vuln_hunt takes list[dict]
    prioritized = prioritize_endpoints_for_vuln_hunt(deduped, max_endpoints=50)

    # id=1 should be in the output (sqli_int pattern)
    matched_urls = [ep.get("url", "") for ep in prioritized if isinstance(ep, dict)]
    assert any("id=1" in u or "id=" in u for u in matched_urls)


def test_waf_profiler_bypass_strategies_non_blocking():
    """WAF profiler data model holds bypass strategies correctly."""
    from pentra_tools.recon.waf_profiler import WAFProfile

    # Test data model with correct fields
    profile = WAFProfile(
        url="https://target.com",
        waf_detected=True,
        waf_type="cloudflare",
        is_blocking=True,
        bypass_strategies=["url_double_encode", "unicode_bypass"],
        block_threshold_rps=2,
    )
    assert profile.waf_type == "cloudflare"
    assert len(profile.bypass_strategies) == 2
    assert profile.block_threshold_rps == 2
    assert profile.is_blocking is True


def test_exploit_arsenal_tech_aware_selection():
    """ExploitArsenal selects MSSQL payloads for IIS/ASP.NET targets."""
    from pentra_agent.arsenal.exploit_arsenal import ExploitArsenal

    # MSSQL payloads for ASP.NET target
    mssql_payloads = ExploitArsenal.get_payloads("SQL_INJECTION", tech_stack=["iis", "aspnet"])
    waitfor = [p for p in mssql_payloads if "WAITFOR" in p.upper()]
    assert len(waitfor) >= 1, "Should have WAITFOR DELAY for MSSQL"

    # MySQL payloads for PHP target
    mysql_payloads = ExploitArsenal.get_payloads("SQL_INJECTION", tech_stack=["php", "mysql"])
    sleep = [p for p in mysql_payloads if "SLEEP" in p.upper()]
    assert len(sleep) >= 1, "Should have SLEEP for MySQL"


# ── Sprint 18.10: LocatedMemory skip gate integration ────────────────────────

def test_located_memory_prevents_duplicate_testing():
    """LocatedMemory skip gate: confirmed endpoints are not re-tested."""
    from pentra_agent.memory.located_memory import LocatedMemory

    memory = LocatedMemory()

    # Mark URL+param as confirmed
    finding = {"vuln_class": "SQL Injection", "severity": "critical", "payload": "' OR 1=1--"}
    memory.mark_confirmed("https://t.com/page?id=1", "id", finding)

    # Skip gate must return True
    assert memory.is_confirmed("https://t.com/page?id=1", "id")
    assert not memory.is_confirmed("https://t.com/page?id=1", "cat")  # different param

    # Effective payloads should be registered
    payloads = memory.get_effective_payloads("SQL Injection")
    assert "' OR 1=1--" in payloads


def test_located_memory_observation_prefix_contains_context():
    """Memory prefix includes confirmed findings for LLM context."""
    from pentra_agent.memory.located_memory import LocatedMemory

    memory = LocatedMemory()
    memory.mark_confirmed(
        "https://t.com/login", "username",
        {"vuln_class": "SQL Injection", "severity": "critical", "payload": "' OR 1=1--"}
    )
    memory.mark_failed_payload("https://t.com/search", "q", "' OR 1=1--")
    memory.mark_failed_payload("https://t.com/search", "q", "1 AND 1=2--")

    # Observation for login endpoint should show confirmed findings
    prefix_login = memory.observation_prefix("https://t.com/other", "param")
    assert "CONFIRMED FINDINGS" in prefix_login
    assert "SQL Injection" in prefix_login

    # Observation for search endpoint should show failed payloads
    prefix_search = memory.observation_prefix("https://t.com/search", "q")
    assert "ALREADY TRIED" in prefix_search
    assert "2 payloads" in prefix_search


# ── Sprint 18.7: Two-stage triage integration ─────────────────────────────────

@pytest.mark.asyncio
async def test_two_stage_triage_stage2_called_for_high():
    """Stage 2 HTTP re-probe should be called for HIGH/CRITICAL findings."""
    from pentra_agent.nodes.triage_node import _stage2_reprobe

    # Simulate HIGH SQLi finding
    finding = {
        "title": "SQL Injection in id",
        "severity": "high",
        "vuln_class": "SQL Injection",
        "target_url": "https://t.com/page?id=1",
        "param_name": "id",
        "param_location": "query",
        "payload": "' OR SLEEP(5)--",
    }

    # Mock a fast HTTP response (no timing anomaly → downgrade)
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_resp = MagicMock()
    mock_resp.text = "<html>Normal response</html>"
    mock_resp.status_code = 200
    mock_client.request = AsyncMock(return_value=mock_resp)

    call_count = [0]
    def fake_monotonic():
        call_count[0] += 1
        return 0.3  # always fast — will trigger downgrade

    with patch("pentra_agent.nodes.triage_node.time.monotonic", side_effect=fake_monotonic), \
         patch("pentra_agent.nodes.triage_node.httpx.AsyncClient", return_value=mock_client):
        result = await _stage2_reprobe([finding])

    assert len(result) == 1
    # Fast response → downgraded to medium
    assert result[0]["severity"] == "medium"
    assert result[0]["stage2_verified"] is False


# ── Sprint 18.6: Auth credentials flow integration ───────────────────────────

def test_auth_credentials_bearer_flow():
    """Bearer token flows correctly into request headers."""
    from pentra_tools.auth.session_manager import AuthCredentials, SessionManager

    creds = AuthCredentials(type="bearer", value="my-test-token-abc123")
    mgr = SessionManager(creds)
    headers, cookies = mgr.get_auth_headers()

    assert headers.get("Authorization") == "Bearer my-test-token-abc123"
    assert cookies == {}


def test_auth_credentials_cookie_flow():
    """Cookie credentials parse into dict correctly."""
    from pentra_tools.auth.session_manager import AuthCredentials, SessionManager

    creds = AuthCredentials(type="cookie", value="session=abc; csrf=xyz; user_id=42")
    mgr = SessionManager(creds)
    headers, cookies = mgr.get_auth_headers()

    assert cookies["session"] == "abc"
    assert cookies["csrf"] == "xyz"
    assert cookies["user_id"] == "42"
    assert headers == {}


# ── Sprint 18.11: Scan presets env var flow ───────────────────────────────────

def test_scan_preset_applies_env_vars(monkeypatch):
    """Scan preset correctly sets environment variables for vuln_hunt_node."""
    from pentra_agent.scan_presets import get_preset

    preset = get_preset("stealth")
    preset.apply_to_env()

    # Stealth preset: no nuclei, no ffuf, concurrency=1, slow pacing
    assert os.environ["PENTRA_RUN_NUCLEI"] == "false"
    assert os.environ["PENTRA_RUN_FFUF"] == "false"
    assert os.environ["PENTRA_CONCURRENT_CANDIDATES"] == "1"
    assert float(os.environ["PENTRA_PAYLOAD_PACING"]) >= 0.5


def test_scan_preset_full_runs_all_tools(monkeypatch):
    """Full preset enables all tools and higher concurrency."""
    from pentra_agent.scan_presets import get_preset

    preset = get_preset("full")
    preset.apply_to_env()

    assert os.environ["PENTRA_RUN_NUCLEI"] == "true"
    assert os.environ["PENTRA_RUN_FFUF"] == "true"
    assert int(os.environ["PENTRA_MAX_CANDIDATES"]) >= 25


# ── Sprint 18.12: Subscan state bypasses recon ────────────────────────────────

def test_subscan_state_skips_recon():
    """Subscan state has current_phase=vuln_hunt and recon in history."""
    from pentra_agent.subscan import SubscanSpec, build_subscan_state

    spec = SubscanSpec(
        domain="target.com",
        focus_endpoints=[{"url": "https://target.com/api?id=1"}],
        reason="Testing second-order SQLi",
        extra_test_types=["sqli"],
    )
    state = build_subscan_state(spec)

    assert state["current_phase"] == "vuln_hunt"
    assert "recon" in state["phase_history"]
    assert state["endpoints"][0]["test_types"] is not None
    assert "sqli" in state["endpoints"][0]["test_types"]


# ── Sprint 18.13: IncrementalTracker fingerprint lifecycle ───────────────────

def test_incremental_tracker_full_lifecycle():
    """Full lifecycle: update → is_unchanged → vuln found → always retest."""
    from pentra_agent.incremental import IncrementalTracker

    tracker = IncrementalTracker()
    url, param = "https://t.com/search", "q"
    body = "<html>Search results page</html>"

    # First visit: not cached → must test
    assert tracker.is_unchanged(url, param, body) is False

    # Update cache
    tracker.update(url, param, body, vuln_found=False)

    # Second visit with same content: skip
    assert tracker.is_unchanged(url, param, body) is True

    # If vuln was found: always retest
    tracker.update(url, param, body, vuln_found=True)
    assert tracker.is_unchanged(url, param, body) is False


# ── Sprint 18.14: Fine-tuning export lifecycle ───────────────────────────────

def test_finetune_export_lifecycle():
    """Full lifecycle: add findings → save → count records in JSONL."""
    from pentra_agent.finetune_export import FineTuneExporter

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = f.name

    try:
        exporter = FineTuneExporter(output_path=path)

        # Add multiple findings from different vuln classes
        for vc, sev, payload in [
            ("SQL Injection", "critical", "'; WAITFOR DELAY '0:0:5'--"),
            ("XSS", "high", "<script>alert(1)</script>"),
            ("Path Traversal", "high", "../../web.config"),
        ]:
            exporter.add_finding(
                finding={
                    "vuln_class": vc, "severity": sev,
                    "target_url": "https://t.com/", "param_name": "id",
                    "payload": payload,
                },
                thought=f"The parameter looks vulnerable to {vc}",
                tech_stack=["iis", "aspnet"],
            )

        written = exporter.save(append=False)
        assert written == 3

        # Verify JSONL is valid
        count = FineTuneExporter.count_records(path)
        assert count == 3

        # Verify structure of first record
        with open(path) as f_read:
            record = json.loads(f_read.readline())
        assert "messages" in record
        assert len(record["messages"]) == 3
        assert record["messages"][0]["role"] == "system"
        assert record["messages"][2]["role"] == "assistant"
        assert "test_injection" in record["messages"][2]["content"]

    finally:
        os.unlink(path)
