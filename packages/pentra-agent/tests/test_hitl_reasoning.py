from __future__ import annotations

# We test the _build_hitl_analysis() helper directly
from pentra_agent.nodes.hitl_nodes import _build_hitl_analysis


def test_build_hitl_analysis_empty_findings():
    result = _build_hitl_analysis([], waf_info=None, tech_stack=[])
    assert "high_confidence_findings" in result
    assert "risk_flags" in result
    assert "recommendation" in result
    assert result["high_confidence_findings"] == []


def test_build_hitl_analysis_critical_finding():
    findings = [
        {"title": "SQL Injection in /login", "severity": "critical",
         "target_url": "http://t.com/login", "vuln_class": "sqli"},
    ]
    result = _build_hitl_analysis(findings, waf_info=None, tech_stack=[])
    assert len(result["high_confidence_findings"]) == 1
    assert result["high_confidence_findings"][0]["severity"] == "critical"


def test_build_hitl_analysis_waf_adds_risk_flag():
    result = _build_hitl_analysis(
        [],
        waf_info={"waf_type": "cloudflare", "is_blocking": True,
                  "bypass_strategies": [], "safe_rps": 5},
        tech_stack=[],
    )
    assert any("WAF" in flag or "waf" in flag.lower() for flag in result["risk_flags"])


def test_build_hitl_analysis_recommendation_approve_critical():
    findings = [
        {"title": "RCE via deserialization", "severity": "critical",
         "target_url": "http://t.com/api", "vuln_class": "rce"},
        {"title": "Info disclosure", "severity": "low",
         "target_url": "http://t.com/info", "vuln_class": "info"},
    ]
    result = _build_hitl_analysis(findings, waf_info=None, tech_stack=[])
    # Should recommend approving high/critical; can mention skipping low
    rec = result["recommendation"].lower()
    assert "critical" in rec or "rce" in rec or "approve" in rec


def test_build_hitl_analysis_counts_by_severity():
    findings = [
        {"severity": "critical", "title": "A", "target_url": "u", "vuln_class": "sqli"},
        {"severity": "high", "title": "B", "target_url": "u", "vuln_class": "xss"},
        {"severity": "medium", "title": "C", "target_url": "u", "vuln_class": "csrf"},
        {"severity": "low", "title": "D", "target_url": "u", "vuln_class": "info"},
    ]
    result = _build_hitl_analysis(findings, waf_info=None, tech_stack=[])
    assert result["severity_counts"]["critical"] == 1
    assert result["severity_counts"]["high"] == 1
    assert result["severity_counts"]["medium"] == 1
    assert result["severity_counts"]["low"] == 1
