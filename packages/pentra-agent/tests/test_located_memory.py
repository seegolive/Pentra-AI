"""Tests for Located Memory — Task 18.10."""

from __future__ import annotations

import pytest

from pentra_agent.memory.located_memory import LocatedMemory


# ── Core memory operations ────────────────────────────────────────────────────

def test_mark_confirmed_is_detectable():
    mem = LocatedMemory()
    finding = {"vuln_class": "SQL Injection", "severity": "high", "payload": "' OR 1=1--"}
    mem.mark_confirmed("https://target.com/page?id=1", "id", finding)
    assert mem.is_confirmed("https://target.com/page?id=1", "id")
    assert not mem.is_confirmed("https://target.com/other", "id")


def test_mark_exhausted_is_detectable():
    mem = LocatedMemory()
    mem.mark_exhausted("https://target.com/search", "q")
    assert mem.is_exhausted("https://target.com/search", "q")
    assert not mem.is_exhausted("https://target.com/other", "q")


def test_failed_payload_tracking():
    mem = LocatedMemory()
    mem.mark_failed_payload("https://t.com/", "id", "' OR 1=1--")
    assert mem.was_payload_tried("https://t.com/", "id", "' OR 1=1--")
    assert not mem.was_payload_tried("https://t.com/", "id", "other payload")


def test_effective_payloads_stored_on_confirmed():
    mem = LocatedMemory()
    finding = {
        "vuln_class": "SQL Injection",
        "severity": "critical",
        "payload": "'; WAITFOR DELAY '0:0:5'--",
    }
    mem.mark_confirmed("https://t.com/", "id", finding)
    effective = mem.get_effective_payloads("SQL Injection")
    assert "'; WAITFOR DELAY '0:0:5'--" in effective


def test_effective_payloads_empty_for_unknown_class():
    mem = LocatedMemory()
    assert mem.get_effective_payloads("XSS") == []


def test_react_history_bounded_at_15():
    mem = LocatedMemory()
    for i in range(20):
        mem.add_react_step(f"https://t.com/{i}", "id", f"thought {i}", "test_injection")
    assert len(mem.react_history) == 15


def test_observation_prefix_empty_when_no_memory():
    mem = LocatedMemory()
    prefix = mem.observation_prefix("https://target.com/page", "id")
    assert prefix == ""


def test_observation_prefix_shows_confirmed_findings():
    mem = LocatedMemory()
    mem.mark_confirmed(
        "https://t.com/login", "username",
        {"vuln_class": "SQL Injection", "severity": "critical", "payload": "' OR 1=1"},
    )
    prefix = mem.observation_prefix("https://t.com/other", "q")
    assert "CONFIRMED FINDINGS SO FAR" in prefix
    assert "SQL Injection" in prefix
    assert "username" in prefix


def test_observation_prefix_shows_failed_payloads_for_same_candidate():
    mem = LocatedMemory()
    mem.mark_failed_payload("https://t.com/page?id=1", "id", "' OR 1=1--")
    mem.mark_failed_payload("https://t.com/page?id=1", "id", "1 AND 1=2--")
    prefix = mem.observation_prefix("https://t.com/page?id=1", "id")
    assert "ALREADY TRIED" in prefix
    assert "2 payloads" in prefix


def test_observation_prefix_shows_effective_payloads():
    mem = LocatedMemory()
    mem.mark_confirmed(
        "https://t.com/a", "cat",
        {"vuln_class": "SQL Injection", "severity": "high", "payload": "'; WAITFOR DELAY '0:0:5'--"},
    )
    prefix = mem.observation_prefix("https://t.com/b", "id")
    assert "PAYLOADS THAT WORKED" in prefix
    assert "SQL Injection" in prefix


def test_stats_returns_correct_counts():
    mem = LocatedMemory()
    mem.mark_confirmed("https://t.com/a", "id", {"vuln_class": "XSS", "severity": "high", "payload": "<script>"})
    mem.mark_exhausted("https://t.com/b", "q")
    stats = mem.stats
    assert stats["confirmed"] == 1
    assert stats["exhausted"] == 1
    assert "XSS" in stats["effective_payload_classes"]


def test_duplicate_confirmed_not_double_counted():
    """Same URL/param confirmed twice — only one entry in memory."""
    mem = LocatedMemory()
    f1 = {"vuln_class": "SQLi", "severity": "high", "payload": "p1"}
    f2 = {"vuln_class": "SQLi", "severity": "critical", "payload": "p2"}
    mem.mark_confirmed("https://t.com/", "id", f1)
    mem.mark_confirmed("https://t.com/", "id", f2)  # overwrite
    assert len(mem.confirmed) == 1
    assert mem.confirmed[("https://t.com/", "id")] == f2  # last write wins
