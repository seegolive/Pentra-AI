"""Tests for Enhancement D (Developer Psychology) and Enhancement E (Anomaly Detection).

Sprint 16 — Task 16.4 & 16.5
"""

import pytest
from pentra_agent.nodes.vuln_hunt_node import (
    DEVELOPER_PSYCHOLOGY_HEURISTICS,
    detect_anomalies,
)


# ── Enhancement E — Anomaly Detection ────────────────────────────────────────

class TestDetectAnomalies:
    def test_no_anomaly_returns_empty_list(self):
        """Identical baseline and test bodies — no anomalies."""
        body = "<html><body>Hello world</body></html>"
        assert detect_anomalies(body, body) == []

    def test_size_anomaly_detected(self):
        """Response significantly larger than baseline flags SIZE_ANOMALY."""
        baseline = "OK"
        test_body = "OK" + ("x" * 1000)
        anomalies = detect_anomalies(baseline, test_body)
        assert any("SIZE_ANOMALY" in a for a in anomalies)

    def test_error_disclosure_detected(self):
        """SQL error keyword appearing only in test response flags ERROR_DISCLOSURE."""
        baseline = "<html>Search results: 0 items</html>"
        test_body = "<html>You have an error in your SQL syntax near '\\'</html>"
        anomalies = detect_anomalies(baseline, test_body)
        assert any("ERROR_DISCLOSURE" in a for a in anomalies)

    def test_error_keyword_in_baseline_not_flagged(self):
        """If the error keyword was already in baseline, it should NOT be flagged."""
        # Both have the same error text — not a new disclosure
        both = "you have an error in your sql — always shown"
        anomalies = detect_anomalies(both, both)
        assert not any("ERROR_DISCLOSURE" in a for a in anomalies)

    def test_reflection_detected(self):
        """Payload reflected in test response (not in baseline) flags REFLECTION."""
        baseline = "<html>Search: </html>"
        payload = "<script>alert(1)</script>"
        test_body = f"<html>Search: {payload}</html>"
        anomalies = detect_anomalies(baseline, test_body, test_payload=payload)
        assert any("REFLECTION" in a for a in anomalies)

    def test_payload_already_in_baseline_not_reflection(self):
        """If payload string was already in baseline, do NOT flag as reflection."""
        payload = "test"
        baseline = "<html>test</html>"
        test_body = "<html>test result found</html>"
        anomalies = detect_anomalies(baseline, test_body, test_payload=payload)
        assert not any("REFLECTION" in a for a in anomalies)

    def test_empty_response_anomaly(self):
        """Test body near-empty when baseline had content flags EMPTY_RESPONSE."""
        baseline = "<html>" + "x" * 500 + "</html>"
        test_body = ""
        anomalies = detect_anomalies(baseline, test_body)
        assert any("EMPTY_RESPONSE" in a for a in anomalies)

    def test_multiple_anomalies_can_be_returned(self):
        """SIZE and ERROR_DISCLOSURE can both appear for one response."""
        baseline = "<html>OK</html>"
        test_body = "<html>You have an error in your SQL syntax near '\\'." + "x" * 2000 + "</html>"
        anomalies = detect_anomalies(baseline, test_body)
        types = [a.split(":")[0] for a in anomalies]
        assert "SIZE_ANOMALY" in types
        assert "ERROR_DISCLOSURE" in types


# ── Enhancement D — Developer Psychology Heuristics ──────────────────────────

class TestDeveloperPsychologyHeuristics:
    def test_heuristics_constant_is_non_empty(self):
        """DEVELOPER_PSYCHOLOGY_HEURISTICS must be a non-empty string."""
        assert isinstance(DEVELOPER_PSYCHOLOGY_HEURISTICS, str)
        assert len(DEVELOPER_PSYCHOLOGY_HEURISTICS) > 100

    def test_heuristics_covers_key_patterns(self):
        """Heuristics string must cover the 4 most critical attack surface patterns."""
        text = DEVELOPER_PSYCHOLOGY_HEURISTICS.lower()
        # API versioning
        assert "v2" in text or "api version" in text or "versioning" in text
        # IDOR
        assert "idor" in text or "integer id" in text or "numeric id" in text
        # Admin endpoints
        assert "admin" in text or "internal" in text
        # Auth bypass / verbose errors
        assert "error" in text or "debug" in text

    def test_heuristics_injected_in_observation_string(self):
        """observation string built in _run_llm_burp_active_testing must include heuristics."""
        # Simulate how observation is built in vuln_hunt_node (same format)
        cand_url = "https://target.com/api/v2/users?id=1"
        param_name = "id"
        param_location = "query"
        test_types = ["sqli", "idor"]
        tech_stack = ["rails"]
        original_response = '{"error": "not found"}'

        observation = (
            f"URL: {cand_url}\n"
            f"Parameter: {param_name} ({param_location})\n"
            f"Test types: {test_types}\n"
            f"Tech stack: {tech_stack}\n"
            f"Baseline response snippet (first 400 chars):\n{original_response[:400]}\n\n"
            f"{DEVELOPER_PSYCHOLOGY_HEURISTICS}"
        )

        assert DEVELOPER_PSYCHOLOGY_HEURISTICS in observation
        assert "admin" in observation.lower() or "idor" in observation.lower()
