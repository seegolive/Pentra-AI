"""Tests for Tasks 18.12-18.14: Subscan, Incremental, Fine-tuning."""

from __future__ import annotations

import json
import os
import tempfile
import time
from unittest.mock import patch

import pytest

from pentra_agent.subscan import (
    SubscanSpec,
    build_subscan_state,
    load_subscan_from_report,
    parse_subscan_url,
)
from pentra_agent.incremental import IncrementalTracker
from pentra_agent.finetune_export import FineTuneExporter, FineTuneRecord


# ── Task 18.12: Subscan ───────────────────────────────────────────────────────

def test_parse_subscan_url_sqli_param():
    ep = parse_subscan_url("https://target.com/page?id=1")
    assert ep["url"] == "https://target.com/page?id=1"
    assert "sqli" in ep["test_types"]
    assert "id" in ep["params"]


def test_parse_subscan_url_redirect_param():
    ep = parse_subscan_url("https://target.com/login?next=/dashboard")
    assert "open_redirect" in ep["test_types"] or "ssrf" in ep["test_types"]


def test_parse_subscan_url_file_param():
    ep = parse_subscan_url("https://target.com/view?page=home")
    assert "lfi" in ep["test_types"] or "path_traversal" in ep["test_types"]


def test_build_subscan_state_skips_recon():
    spec = SubscanSpec(
        domain="target.com",
        focus_endpoints=[{"url": "https://target.com/api?id=1"}],
        reason="Re-test after patch",
    )
    state = build_subscan_state(spec)

    assert state["current_phase"] == "vuln_hunt"
    assert "recon" in state["phase_history"]
    assert len(state["endpoints"]) == 1
    assert state["endpoints"][0]["url"] == "https://target.com/api?id=1"
    assert state["auth_credentials"] is None


def test_build_subscan_state_with_auth():
    spec = SubscanSpec(domain="target.com", focus_endpoints=[{"url": "https://target.com/"}])
    auth = {"type": "cookie", "value": "session=abc"}
    state = build_subscan_state(spec, auth_credentials=auth)
    assert state["auth_credentials"] == auth


def test_build_subscan_state_focus_params():
    spec = SubscanSpec(
        domain="target.com",
        focus_endpoints=[{"url": "https://target.com/api?id=1&cat=2"}],
        focus_params=["id"],  # only test id, not cat
    )
    state = build_subscan_state(spec)
    ep = state["endpoints"][0]
    assert "id" in ep["params"]
    assert "cat" not in ep["params"]


def test_build_subscan_state_extra_test_types():
    spec = SubscanSpec(
        domain="target.com",
        focus_endpoints=[{"url": "https://target.com/api?id=1"}],
        extra_test_types=["xxe", "ssrf"],
    )
    state = build_subscan_state(spec)
    test_types = state["endpoints"][0]["test_types"]
    assert "xxe" in test_types
    assert "ssrf" in test_types


def test_load_subscan_from_report():
    report = {
        "findings": [
            {"target_url": "https://t.com/page?id=1", "severity": "high", "param_name": "id"},
            {"target_url": "https://t.com/login", "severity": "info"},  # should be excluded
        ]
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(report, f)
        tmp = f.name

    try:
        endpoints = load_subscan_from_report(tmp, min_severity="medium")
        assert len(endpoints) == 1
        assert endpoints[0]["url"] == "https://t.com/page?id=1"
        assert "id" in endpoints[0]["params"]
    finally:
        os.unlink(tmp)


# ── Task 18.13: Incremental Tracker ──────────────────────────────────────────

def test_incremental_first_visit_not_skipped():
    tracker = IncrementalTracker()
    assert tracker.is_unchanged("https://t.com/", "id", "<html>response</html>") is False


def test_incremental_same_response_skipped():
    tracker = IncrementalTracker()
    body = "<html>stable response</html>"
    tracker.update("https://t.com/page", "id", body)
    assert tracker.is_unchanged("https://t.com/page", "id", body) is True


def test_incremental_changed_response_not_skipped():
    tracker = IncrementalTracker()
    tracker.update("https://t.com/page", "id", "<html>v1</html>")
    assert tracker.is_unchanged("https://t.com/page", "id", "<html>completely different v2</html>") is False


def test_incremental_stale_entry_not_skipped():
    tracker = IncrementalTracker(max_age_hours=0.0001)  # ~0.36s
    body = "<html>stable</html>"
    tracker.update("https://t.com/", "q", body)
    time.sleep(0.5)  # wait for cache to expire
    assert tracker.is_unchanged("https://t.com/", "q", body) is False


def test_incremental_vuln_found_always_retested():
    tracker = IncrementalTracker()
    body = "<html>stable</html>"
    tracker.update("https://t.com/", "id", body, vuln_found=True)
    # Even identical response — always re-test when vuln was found before
    assert tracker.is_unchanged("https://t.com/", "id", body) is False


def test_incremental_persist_and_reload():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        cache_path = f.name

    try:
        t1 = IncrementalTracker(cache_path=cache_path)
        t1.update("https://t.com/", "id", "<html>body</html>")
        t1.save()

        t2 = IncrementalTracker(cache_path=cache_path)
        t2.load()
        assert t2.is_unchanged("https://t.com/", "id", "<html>body</html>") is True
    finally:
        os.unlink(cache_path)


def test_incremental_stats():
    tracker = IncrementalTracker()
    tracker.update("https://t.com/", "id", "<html>body</html>")
    tracker.is_unchanged("https://t.com/", "id", "<html>body</html>")  # hit
    tracker.is_unchanged("https://t.com/", "q", "new")                  # miss
    stats = tracker.stats
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["skip_rate"] == 0.5


# ── Task 18.14: Fine-tuning Export ───────────────────────────────────────────

def test_finetune_record_chat_format():
    record = FineTuneRecord(
        vuln_class="SQL Injection",
        severity="high",
        url="https://t.com/page?id=1",
        param="id",
        payload="' OR SLEEP(5)--",
        thought="The id parameter is numeric and user-controlled — likely SQLi target.",
        action="test_injection",
        observation="URL: https://t.com/page?id=1\nParameter: id\n",
    )
    chat = record.to_chat_jsonl()
    assert len(chat["messages"]) == 3
    assert chat["messages"][0]["role"] == "system"
    assert chat["messages"][1]["role"] == "user"
    assert chat["messages"][2]["role"] == "assistant"
    assert "test_injection" in chat["messages"][2]["content"]
    assert "_metadata" in chat


def test_finetune_exporter_add_and_save():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = f.name

    try:
        exporter = FineTuneExporter(output_path=path)
        exporter.add_finding(
            finding={
                "vuln_class": "SQL Injection", "severity": "high",
                "target_url": "https://t.com/", "param_name": "id",
                "payload": "' OR 1=1--",
            },
            thought="Numeric param on ASP.NET — MSSQL injection likely.",
        )
        written = exporter.save(append=False)
        assert written == 1
        assert FineTuneExporter.count_records(path) == 1
    finally:
        os.unlink(path)


def test_finetune_exporter_skips_no_payload():
    exporter = FineTuneExporter()
    exporter.add_finding(
        finding={"vuln_class": "XSS", "severity": "medium", "target_url": "https://t.com/", "param_name": "q", "payload": ""},
    )
    assert exporter.pending_count == 0  # no payload — not added


def test_finetune_export_from_state():
    state = {
        "findings": [
            {
                "vuln_class": "SQL Injection", "severity": "critical",
                "target_url": "https://t.com/page?id=1", "param_name": "id",
                "payload": "'; WAITFOR DELAY '0:0:5'--",
            },
        ],
        "tech_stack": ["iis", "aspnet"],
        "engagement_id": "test-eng-001",
    }
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = f.name

    try:
        exporter = FineTuneExporter(output_path=path)
        count = exporter.export_from_state(state)
        assert count == 1
        exporter.save(append=False)
        records = FineTuneExporter.count_records(path)
        assert records == 1
    finally:
        os.unlink(path)
