"""Tests for Task 17.1 — DO NOT STOP routing logic.

Verifies route_after_triage() correctly:
- Loops back to vuln_hunt when CHAIN_REQUIRED findings exist (round < MAX)
- Stops looping after MAX_ROUNDS=3
- Routes PASS high/critical findings to hitl_exploit
- Routes low/info-only findings to report
"""
import pytest


def test_route_after_triage_chain_required_loops_back():
    """CHAIN_REQUIRED finding with round < 3 must return 'vuln_hunt'."""
    from pentra_agent.graph.builder import route_after_triage

    state = {
        "hunt_rounds": 0,
        "triaged_findings": [
            {
                "title": "IDOR on /api/user",
                "severity": "medium",
                "triage_verdict": "CHAIN_REQUIRED",
                "chain_suggestion": "Chain with Stored XSS for account takeover",
            }
        ],
    }
    assert route_after_triage(state) == "vuln_hunt"


def test_route_after_triage_max_rounds_stops():
    """After hunt_rounds == 3 (MAX_ROUNDS), must NOT return 'vuln_hunt'."""
    from pentra_agent.graph.builder import route_after_triage

    state = {
        "hunt_rounds": 3,
        "triaged_findings": [
            {
                "title": "IDOR on /api/user",
                "severity": "medium",
                "triage_verdict": "CHAIN_REQUIRED",
                "chain_suggestion": "Chain with XSS",
            }
        ],
    }
    result = route_after_triage(state)
    assert result in ("hitl_exploit", "report"), (
        f"Expected 'hitl_exploit' or 'report', got {result!r}"
    )
    assert result != "vuln_hunt"


def test_route_after_triage_no_chain_goes_to_report():
    """Low/info PASS findings with no chaining → 'report'."""
    from pentra_agent.graph.builder import route_after_triage

    state = {
        "hunt_rounds": 0,
        "triaged_findings": [
            {"title": "Server version disclosure", "severity": "low", "triage_verdict": "PASS"}
        ],
    }
    assert route_after_triage(state) == "report"


def test_route_after_triage_high_finding_goes_to_hitl():
    """High severity PASS finding → 'hitl_exploit'."""
    from pentra_agent.graph.builder import route_after_triage

    state = {
        "hunt_rounds": 0,
        "triaged_findings": [
            {"title": "SQLi on login", "severity": "high", "triage_verdict": "PASS"}
        ],
    }
    assert route_after_triage(state) == "hitl_exploit"


def test_route_after_triage_critical_at_max_rounds_goes_to_hitl():
    """Even at max rounds, critical findings must route to hitl_exploit (not report)."""
    from pentra_agent.graph.builder import route_after_triage

    state = {
        "hunt_rounds": 3,
        "triaged_findings": [
            {"title": "RCE via deserialization", "severity": "critical", "triage_verdict": "CHAIN_REQUIRED"}
        ],
    }
    assert route_after_triage(state) == "hitl_exploit"


def test_route_after_triage_empty_findings_goes_to_report():
    """No findings at all → 'report'."""
    from pentra_agent.graph.builder import route_after_triage

    state = {"hunt_rounds": 0, "triaged_findings": []}
    assert route_after_triage(state) == "report"
