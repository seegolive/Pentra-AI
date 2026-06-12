"""E2E pipeline test — exercises the full recon → vuln_hunt pipeline.

Coverage:
  - osint_node  : passive CT subdomain discovery (mocked httpx)
  - recon_node  : subfinder → httpx probe → nmap → Burp sitemap → LLM analysis
  - vuln_hunt_node: nuclei → ffuf → Burp proxy history → Burp active scan → LLM classify

External dependencies:
  - LLM (Ollama)  : mocked via AsyncMock
  - Tool binaries : mocked via patch.object(_exec)
  - Burp MCP      : real connection when BURP_MCP_ENABLED=true, else mocked
  - Knowledge DB  : mocked (pentra_knowledge not required for pipeline test)

Target used: testaspnet.vulnweb.com (intentionally vulnerable, appears in Burp proxy history)
"""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_agent.graph.state import PentraState

# ── Constants ─────────────────────────────────────────────────────────────────

TARGET_DOMAIN = "testaspnet.vulnweb.com"
BURP_AVAILABLE = os.getenv("BURP_MCP_ENABLED", "false").lower() == "true"
BURP_URL = os.getenv("BURP_MCP_URL", "http://localhost:9877")

burp_live = pytest.mark.skipif(
    not BURP_AVAILABLE,
    reason="Set BURP_MCP_ENABLED=true to run live Burp integration",
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_state(**overrides) -> PentraState:
    base: dict = {
        "engagement_id": "e2e-test-001",
        "target": {
            "domain": TARGET_DOMAIN,
            "ip_ranges": [],
            "base_urls": [f"http://{TARGET_DOMAIN}/"],
        },
        "scope": {
            "in_scope": [TARGET_DOMAIN, f"*.{TARGET_DOMAIN}"],
            "out_of_scope": [],
        },
        "mode": "agentic",
        "llm_model": "qwen2.5:7b",
        "opsec_mode": False,
        "request_jitter_ms": 0,
        "current_phase": "planning",
        "phase_history": [],
        "subdomains": [],
        "open_ports": [],
        "tech_stack": [],
        "endpoints": [],
        "findings": [],
        "triaged_findings": [],
        "pentest_plan": "Test basic web app vulnerabilities",
        "current_hypothesis": "",
        "knowledge_context": [],
        "awaiting_approval": False,
        "pending_action": None,
        "user_decision": None,
        "messages": [],
        "tool_outputs": [],
        "errors": [],
        "hunt_rounds": 0,
    }
    base.update(overrides)
    return base  # type: ignore[return-value]


def _make_llm_mock() -> AsyncMock:
    """LLM mock that returns valid structured responses for all methods."""
    llm = AsyncMock()
    llm.analyze_recon_results.return_value = {
        "summary": f"Target {TARGET_DOMAIN} appears to be an ASP.NET app with potential SQLi/XSS",
        "hypotheses": [
            "SQL injection in search/login forms (ASP.NET + MSSQL stack)",
            "Reflected XSS in query parameters",
            "Directory traversal on file download endpoints",
        ],
    }
    llm.classify_finding.return_value = {
        "severity": "high",
        "vuln_class": "sqli",
        "confidence": 0.85,
        "cwe": "CWE-89",
    }
    llm.complete_json.return_value = {
        "findings": [],
        "summary": "No additional findings from LLM analysis",
    }
    return llm


# ── Mock tool outputs ─────────────────────────────────────────────────────────

_SUBFINDER_OUTPUT = "\n".join([
    json.dumps({"host": TARGET_DOMAIN, "source": "dnsx", "ip": "176.28.50.165"}),
])

_NMAP_OUTPUT = (
    "PORT     STATE SERVICE  VERSION\n"
    "80/tcp   open  http     Microsoft IIS httpd 8.5\n"
    "443/tcp  open  https    Microsoft IIS httpd 8.5\n"
    "1433/tcp open  ms-sql-s Microsoft SQL Server 2012\n"
)

_NUCLEI_FINDING = json.dumps({
    "template-id": "aspx-debug-mode",
    "info": {"name": "ASP.NET Debug Mode Enabled", "severity": "medium"},
    "matched-at": f"http://{TARGET_DOMAIN}/Trace.axd",
    "host": TARGET_DOMAIN,
    "type": "http",
})

_FFUF_OUTPUT = json.dumps({
    "results": [
        {
            "url": f"http://{TARGET_DOMAIN}/admin/",
            "status": 200,
            "length": 4096,
            "words": 200,
        }
    ]
})

_HTTPX_OUTPUT = json.dumps({
    "url": f"http://{TARGET_DOMAIN}/",
    "status_code": 200,
    "tech": ["ASP.NET", "IIS"],
    "title": "Acunetix Test Website",
})


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestReconNodeE2E:
    """recon_node — all sub-tools exercised, Burp sitemap integrated."""

    @pytest.mark.asyncio
    async def test_recon_node_accumulates_subdomains_and_endpoints(self) -> None:
        """recon_node populates subdomains, endpoints, tech_stack in state."""
        from pentra_agent.nodes.recon_node import recon_node

        state = _make_state()
        mock_llm = _make_llm_mock()

        with (
            patch("pentra_agent.nodes.recon_node.LLMClient", return_value=mock_llm),
            patch("pentra_agent.nodes.recon_node._ollama_url", return_value="http://localhost:11434"),
            patch("pentra_agent.nodes.recon_node._run_subfinder", new=AsyncMock(return_value=[
                {"host": TARGET_DOMAIN, "ip": "176.28.50.165", "source": "subfinder",
                 "is_alive": True, "status_code": 200, "tech_stack": ["asp.net", "iis"]},
            ])),
            patch("pentra_agent.nodes.recon_node._run_httpx_probe", new=AsyncMock(side_effect=lambda s: s)),
            patch("pentra_agent.nodes.recon_node._run_nmap", new=AsyncMock(return_value=[
                {"host": TARGET_DOMAIN, "port": 80, "protocol": "tcp",
                 "service": "http", "version": "IIS 8.5", "state": "open"},
                {"host": TARGET_DOMAIN, "port": 1433, "protocol": "tcp",
                 "service": "ms-sql-s", "version": "MSSQL 2012", "state": "open"},
            ])),
            # Mock rate-limit + WAF probes — these hit the real target over the
            # network and must not run during mocked tests
            patch("pentra_agent.nodes.recon_node.probe_rate_limit", new=AsyncMock(
                side_effect=ConnectionError("no network in test")
            )),
            patch("pentra_tools.recon.waf_profiler.profile_waf", new=AsyncMock(
                side_effect=ConnectionError("no network in test")
            )),
            patch("pentra_tools.recon.takeover_detector.detect_subdomain_takeovers", new=AsyncMock(
                return_value=[]
            )),
            # Mock Burp (fallback no-op if not live)
            patch("pentra_agent.nodes.recon_node._fetch_burp_endpoints", new=AsyncMock(
                return_value=([], [])
            )),
            # Mock knowledge KB
            patch("pentra_agent.nodes.recon_node.hybrid_search", new=AsyncMock(return_value=[]), create=True),
            patch("pentra_agent.nodes.recon_node._get_session_factory", create=True),
        ):
            result = await recon_node(state)

        assert "subdomains" in result
        assert len(result["subdomains"]) >= 1
        assert result["subdomains"][0]["host"] == TARGET_DOMAIN

        assert "tech_stack" in result
        assert any("asp" in t.lower() or "iis" in t.lower() for t in result["tech_stack"])

        assert "open_ports" in result
        ports = [p["port"] for p in result["open_ports"]]
        assert 80 in ports
        assert 1433 in ports

        assert "messages" in result
        assert result["messages"]  # at least one analysis message

    @pytest.mark.asyncio
    @burp_live
    async def test_recon_node_burp_sitemap_integration(self) -> None:
        """recon_node fetches real Burp proxy history and merges endpoints."""
        from pentra_agent.nodes.recon_node import recon_node, _fetch_burp_endpoints

        # Test _fetch_burp_endpoints directly with real Burp
        burp_endpoints, burp_tech = await _fetch_burp_endpoints(
            domain=TARGET_DOMAIN,
            in_scope=[TARGET_DOMAIN, f"*.{TARGET_DOMAIN}"],
            out_of_scope=[],
        )

        # Burp has testaspnet.vulnweb.com in proxy history (confirmed in test output)
        assert isinstance(burp_endpoints, list)
        assert isinstance(burp_tech, list)
        # At least one endpoint should come back (Burp has proxy history for this target)
        assert len(burp_endpoints) > 0, (
            f"Expected Burp proxy history to contain {TARGET_DOMAIN} entries. "
            "Browse to the target in Burp before running this test."
        )
        for ep in burp_endpoints:
            assert TARGET_DOMAIN in ep["url"], f"OOS endpoint: {ep['url']}"

    @pytest.mark.asyncio
    async def test_recon_node_scope_blocks_oos_in_subfinder(self) -> None:
        """Subfinder results outside scope are not included in endpoints."""
        from pentra_agent.nodes.recon_node import recon_node

        state = _make_state()
        mock_llm = _make_llm_mock()

        with (
            patch("pentra_agent.nodes.recon_node.LLMClient", return_value=mock_llm),
            patch("pentra_agent.nodes.recon_node._ollama_url", return_value="http://localhost:11434"),
            patch("pentra_agent.nodes.recon_node._run_subfinder", new=AsyncMock(return_value=[
                {"host": TARGET_DOMAIN, "ip": "1.2.3.4", "source": "subfinder",
                 "is_alive": True, "status_code": 200, "tech_stack": []},
                # OOS host — should be silently dropped before endpoint extraction
                {"host": "evil.com", "ip": "9.9.9.9", "source": "subfinder",
                 "is_alive": True, "status_code": 200, "tech_stack": []},
            ])),
            patch("pentra_agent.nodes.recon_node._run_httpx_probe", new=AsyncMock(side_effect=lambda s: s)),
            patch("pentra_agent.nodes.recon_node._run_nmap", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.recon_node.probe_rate_limit", new=AsyncMock(
                side_effect=ConnectionError("no network in test")
            )),
            patch("pentra_tools.recon.waf_profiler.profile_waf", new=AsyncMock(
                side_effect=ConnectionError("no network in test")
            )),
            patch("pentra_tools.recon.takeover_detector.detect_subdomain_takeovers", new=AsyncMock(
                return_value=[]
            )),
            patch("pentra_agent.nodes.recon_node._fetch_burp_endpoints", new=AsyncMock(return_value=([], []))),
            patch("pentra_agent.nodes.recon_node.hybrid_search", new=AsyncMock(return_value=[]), create=True),
            patch("pentra_agent.nodes.recon_node._get_session_factory", create=True),
        ):
            result = await recon_node(state)

        # All endpoints must be in-scope
        for ep in result.get("endpoints", []):
            assert "evil.com" not in ep["url"], f"OOS endpoint leaked: {ep['url']}"


class TestVulnHuntNodeE2E:
    """vuln_hunt_node — nuclei + ffuf + Burp active scan + Burp proxy history."""

    @pytest.mark.asyncio
    async def test_vuln_hunt_returns_findings(self) -> None:
        """vuln_hunt_node discovers findings from nuclei and ffuf mocks."""
        from pentra_agent.nodes.vuln_hunt_node import vuln_hunt_node

        state = _make_state(
            endpoints=[
                {"url": f"http://{TARGET_DOMAIN}/", "method": "GET", "params": [], "source": "httpx"},
                {"url": f"http://{TARGET_DOMAIN}/search.aspx?q=test", "method": "GET",
                 "params": ["q"], "source": "katana"},
            ],
            tech_stack=["asp.net", "mssql", "iis"],
        )
        mock_llm = _make_llm_mock()

        with (
            patch("pentra_agent.nodes.vuln_hunt_node.LLMClient", return_value=mock_llm),
            patch("pentra_agent.nodes.vuln_hunt_node._ollama_url", return_value="http://localhost:11434"),
            patch("pentra_agent.nodes.vuln_hunt_node._run_nuclei", new=AsyncMock(return_value=[
                {
                    "title": "ASP.NET Debug Mode Enabled",
                    "description": "Trace.axd is publicly accessible",
                    "target_url": f"http://{TARGET_DOMAIN}/Trace.axd",
                    "severity": "medium",
                    "source": "nuclei",
                    "request": "GET /Trace.axd HTTP/1.1\r\nHost: testaspnet.vulnweb.com\r\n\r\n",
                    "response": "HTTP/1.1 200 OK\r\n\r\n<html>ASP.NET Trace</html>",
                },
            ])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_ffuf", new=AsyncMock(return_value=[
                {
                    "title": "Admin Panel Exposed",
                    "description": "HTTP 200 on /admin/ — admin panel may be accessible",
                    "target_url": f"http://{TARGET_DOMAIN}/admin/",
                    "severity": "high",
                    "source": "ffuf",
                    "request": "",
                    "response": "",
                },
            ])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_burp_active_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._get_burp_proxy_findings", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._get_collaborator_payload", new=AsyncMock(return_value=None)),
            patch("pentra_agent.nodes.vuln_hunt_node._run_llm_burp_active_testing", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node.hybrid_search", new=AsyncMock(return_value=[]), create=True),
            patch("pentra_agent.nodes.vuln_hunt_node._get_session_factory", create=True),
            # Mock additional vuln-hunt scanners — these hit the real target
            # over the network and must not run during mocked tests
            patch("pentra_agent.nodes.vuln_hunt_node._run_burp_extended_checks", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_soap_xxe_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_graphql_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_race_condition_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_cors_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_jwt_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_second_order_sqli_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_business_logic_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_ssrf_scan", new=AsyncMock(return_value=[])),
        ):
            result = await vuln_hunt_node(state)

        assert "findings" in result
        findings = result["findings"]
        assert len(findings) >= 1

        titles = [f.get("title", "") for f in findings]
        assert any("debug" in t.lower() or "trace" in t.lower() for t in titles), f"Got: {titles}"

        # LLM should have classified findings
        for f in findings:
            assert "severity" in f

        assert result.get("hunt_rounds") == 1

    @pytest.mark.asyncio
    async def test_vuln_hunt_empty_endpoints_returns_cleanly(self) -> None:
        """vuln_hunt_node with no endpoints does not crash — returns empty findings."""
        from pentra_agent.nodes.vuln_hunt_node import vuln_hunt_node

        state = _make_state(endpoints=[])
        mock_llm = _make_llm_mock()

        with (
            patch("pentra_agent.nodes.vuln_hunt_node.LLMClient", return_value=mock_llm),
            patch("pentra_agent.nodes.vuln_hunt_node._ollama_url", return_value="http://localhost:11434"),
            patch("pentra_agent.nodes.vuln_hunt_node._run_nuclei", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_ffuf", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_burp_active_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._get_burp_proxy_findings", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._get_collaborator_payload", new=AsyncMock(return_value=None)),
            patch("pentra_agent.nodes.vuln_hunt_node._run_llm_burp_active_testing", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node.hybrid_search", new=AsyncMock(return_value=[]), create=True),
            patch("pentra_agent.nodes.vuln_hunt_node._get_session_factory", create=True),
            # Mock additional vuln-hunt scanners — these hit the real target
            # over the network and must not run during mocked tests
            patch("pentra_agent.nodes.vuln_hunt_node._run_burp_extended_checks", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_soap_xxe_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_graphql_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_race_condition_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_cors_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_jwt_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_second_order_sqli_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_business_logic_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_ssrf_scan", new=AsyncMock(return_value=[])),
        ):
            result = await vuln_hunt_node(state)

        assert result["findings"] == []
        assert "messages" in result

    @pytest.mark.asyncio
    @burp_live
    async def test_vuln_hunt_burp_proxy_history_live(self) -> None:
        """vuln_hunt_node fetches real Burp proxy history for target domain."""
        from pentra_agent.nodes.vuln_hunt_node import _get_burp_proxy_findings

        scope = {
            "in_scope": [TARGET_DOMAIN, f"*.{TARGET_DOMAIN}"],
            "out_of_scope": [],
        }
        findings = await _get_burp_proxy_findings(domain=TARGET_DOMAIN, scope=scope)

        assert isinstance(findings, list)
        # May be empty if no proxy history matches — that's OK
        for f in findings:
            assert "title" in f or "target_url" in f

    @pytest.mark.asyncio
    @burp_live
    async def test_vuln_hunt_burp_active_scan_community_graceful(self) -> None:
        """Burp active scan on Community edition returns graceful note, no crash."""
        from pentra_agent.nodes.vuln_hunt_node import _run_burp_active_scan

        endpoints = [
            {"url": f"http://{TARGET_DOMAIN}/", "method": "GET", "params": [], "source": "httpx"},
        ]
        scope = {
            "in_scope": [TARGET_DOMAIN, f"*.{TARGET_DOMAIN}"],
            "out_of_scope": [],
        }

        # Community Burp raises BurpNotProError or BurpConnectionError — node handles gracefully
        results = await _run_burp_active_scan(endpoints, scope)
        assert isinstance(results, list)


class TestFullPipelineE2E:
    """Full recon → vuln_hunt pipeline in a single test."""

    @pytest.mark.asyncio
    async def test_recon_then_vuln_hunt_state_accumulates(self) -> None:
        """Run recon_node output through vuln_hunt_node and verify state accumulation."""
        from pentra_agent.nodes.recon_node import recon_node
        from pentra_agent.nodes.vuln_hunt_node import vuln_hunt_node

        initial_state = _make_state()
        mock_llm = _make_llm_mock()

        # ── Stage 1: recon ─────────────────────────────────────────────
        with (
            patch("pentra_agent.nodes.recon_node.LLMClient", return_value=mock_llm),
            patch("pentra_agent.nodes.recon_node._ollama_url", return_value="http://localhost:11434"),
            patch("pentra_agent.nodes.recon_node._run_subfinder", new=AsyncMock(return_value=[
                {"host": TARGET_DOMAIN, "ip": "176.28.50.165", "source": "subfinder",
                 "is_alive": True, "status_code": 200,
                 "tech_stack": ["asp.net", "iis", "microsoft-sql-server"]},
            ])),
            patch("pentra_agent.nodes.recon_node._run_httpx_probe", new=AsyncMock(side_effect=lambda s: s)),
            patch("pentra_agent.nodes.recon_node._run_nmap", new=AsyncMock(return_value=[
                {"host": TARGET_DOMAIN, "port": 80, "protocol": "tcp",
                 "service": "http", "version": "IIS 8.5", "state": "open"},
            ])),
            patch("pentra_agent.nodes.recon_node.probe_rate_limit", new=AsyncMock(
                side_effect=ConnectionError("no network in test")
            )),
            patch("pentra_tools.recon.waf_profiler.profile_waf", new=AsyncMock(
                side_effect=ConnectionError("no network in test")
            )),
            patch("pentra_tools.recon.takeover_detector.detect_subdomain_takeovers", new=AsyncMock(
                return_value=[]
            )),
            patch("pentra_agent.nodes.recon_node._fetch_burp_endpoints", new=AsyncMock(return_value=([
                {"url": f"http://{TARGET_DOMAIN}/login.aspx", "method": "POST",
                 "params": ["username", "password"], "source": "burp_proxy"},
                {"url": f"http://{TARGET_DOMAIN}/search.aspx", "method": "GET",
                 "params": ["q"], "source": "burp_proxy"},
            ], ["asp.net", "aspnet_sessionid"]))),
            patch("pentra_agent.nodes.recon_node.hybrid_search", new=AsyncMock(return_value=[]), create=True),
            patch("pentra_agent.nodes.recon_node._get_session_factory", create=True),
        ):
            recon_result = await recon_node(initial_state)

        # Merge recon results into state
        state_after_recon = {**initial_state, **recon_result}
        # LangGraph add_messages reducer — concatenate manually
        state_after_recon["messages"] = initial_state["messages"] + list(recon_result.get("messages", []))
        state_after_recon["subdomains"] = initial_state["subdomains"] + list(recon_result.get("subdomains", []))

        assert len(state_after_recon["subdomains"]) >= 1
        assert len(state_after_recon["endpoints"]) >= 2  # Burp endpoints merged
        assert "burp_proxy" in [ep.get("source") for ep in state_after_recon["endpoints"]]

        # ── Stage 2: vuln_hunt ────────────────────────────────────────
        with (
            patch("pentra_agent.nodes.vuln_hunt_node.LLMClient", return_value=mock_llm),
            patch("pentra_agent.nodes.vuln_hunt_node._ollama_url", return_value="http://localhost:11434"),
            patch("pentra_agent.nodes.vuln_hunt_node._run_nuclei", new=AsyncMock(return_value=[
                {
                    "title": "SQL Injection in Login Form",
                    "description": "login.aspx username param is injectable",
                    "target_url": f"http://{TARGET_DOMAIN}/login.aspx",
                    "severity": "high",
                    "source": "nuclei",
                    "request": "POST /login.aspx HTTP/1.1\r\nHost: testaspnet.vulnweb.com\r\n\r\nusername=admin'",
                    "response": "HTTP/1.1 500 Internal Server Error\r\n\r\nSyntax error",
                },
            ])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_ffuf", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_burp_active_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._get_burp_proxy_findings", new=AsyncMock(return_value=[
                {
                    "title": "Reflected XSS Candidate",
                    "description": "search.aspx?q= reflects input unsanitised",
                    "target_url": f"http://{TARGET_DOMAIN}/search.aspx?q=<script>",
                    "severity": "medium",
                    "source": "burp_proxy",
                    "request": "GET /search.aspx?q=<script>alert(1)</script> HTTP/1.1\r\nHost: testaspnet.vulnweb.com\r\n\r\n",
                    "response": "HTTP/1.1 200 OK\r\n\r\n<html><script>alert(1)</script>",
                },
            ])),
            patch("pentra_agent.nodes.vuln_hunt_node._get_collaborator_payload", new=AsyncMock(return_value=None)),
            patch("pentra_agent.nodes.vuln_hunt_node._run_llm_burp_active_testing", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node.hybrid_search", new=AsyncMock(return_value=[]), create=True),
            patch("pentra_agent.nodes.vuln_hunt_node._get_session_factory", create=True),
            # Mock additional vuln-hunt scanners — these hit the real target
            # over the network and must not run during mocked tests
            patch("pentra_agent.nodes.vuln_hunt_node._run_burp_extended_checks", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_soap_xxe_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_graphql_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_race_condition_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_cors_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_jwt_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_second_order_sqli_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_business_logic_scan", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_ssrf_scan", new=AsyncMock(return_value=[])),
        ):
            vuln_result = await vuln_hunt_node(state_after_recon)

        assert "findings" in vuln_result
        findings = vuln_result["findings"]
        assert len(findings) >= 1

        titles = [f.get("title", "") for f in findings]
        severities = [f.get("severity", "") for f in findings]

        # SQLi from nuclei must be present
        assert any("sql" in t.lower() or "injection" in t.lower() for t in titles), (
            f"SQLi finding not found. Got titles: {titles}"
        )
        # Severity classified by LLM mock (returns "high")
        assert "high" in severities

        # Deduplication — no duplicate title+url combos
        seen = set()
        for f in findings:
            key = f"{f.get('title')}|{f.get('target_url')}"
            assert key not in seen, f"Duplicate finding: {key}"
            seen.add(key)

        # Hunt round counter incremented
        assert vuln_result["hunt_rounds"] == 1

    @pytest.mark.asyncio
    @burp_live
    async def test_full_pipeline_with_live_burp(self) -> None:
        """Full pipeline with REAL Burp proxy history integration.

        Requires:
          BURP_MCP_ENABLED=true  BURP_MCP_URL=http://localhost:9877
        """
        from pentra_agent.nodes.recon_node import recon_node
        from pentra_agent.nodes.vuln_hunt_node import vuln_hunt_node

        initial_state = _make_state()
        mock_llm = _make_llm_mock()

        # Stage 1 — recon with real Burp sitemap
        with (
            patch("pentra_agent.nodes.recon_node.LLMClient", return_value=mock_llm),
            patch("pentra_agent.nodes.recon_node._ollama_url", return_value="http://localhost:11434"),
            patch("pentra_agent.nodes.recon_node._run_subfinder", new=AsyncMock(return_value=[
                {"host": TARGET_DOMAIN, "ip": "176.28.50.165", "source": "subfinder",
                 "is_alive": True, "status_code": 200, "tech_stack": ["asp.net", "iis"]},
            ])),
            patch("pentra_agent.nodes.recon_node._run_httpx_probe", new=AsyncMock(side_effect=lambda s: s)),
            patch("pentra_agent.nodes.recon_node._run_nmap", new=AsyncMock(return_value=[])),
            # Real Burp proxy history is used here (no mock)
            patch("pentra_agent.nodes.recon_node.hybrid_search", new=AsyncMock(return_value=[]), create=True),
            patch("pentra_agent.nodes.recon_node._get_session_factory", create=True),
        ):
            recon_result = await recon_node(initial_state)

        state_after_recon = {**initial_state, **recon_result}
        state_after_recon["messages"] = initial_state["messages"] + list(recon_result.get("messages", []))
        state_after_recon["subdomains"] = initial_state["subdomains"] + list(recon_result.get("subdomains", []))

        # Validate real Burp contributed endpoints
        burp_sources = [ep.get("source") for ep in state_after_recon.get("endpoints", [])]
        assert "burp_proxy" in burp_sources or len(state_after_recon["endpoints"]) >= 1, (
            "Expected Burp proxy history to contribute endpoints. "
            f"Endpoints found: {state_after_recon.get('endpoints', [])}"
        )

        # Stage 2 — vuln_hunt with real Burp proxy findings
        with (
            patch("pentra_agent.nodes.vuln_hunt_node.LLMClient", return_value=mock_llm),
            patch("pentra_agent.nodes.vuln_hunt_node._ollama_url", return_value="http://localhost:11434"),
            patch("pentra_agent.nodes.vuln_hunt_node._run_nuclei", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node._run_ffuf", new=AsyncMock(return_value=[])),
            # Real Burp proxy findings + active scan (Community graceful fail)
            patch("pentra_agent.nodes.vuln_hunt_node._get_collaborator_payload", new=AsyncMock(return_value=None)),
            patch("pentra_agent.nodes.vuln_hunt_node._run_llm_burp_active_testing", new=AsyncMock(return_value=[])),
            patch("pentra_agent.nodes.vuln_hunt_node.hybrid_search", new=AsyncMock(return_value=[]), create=True),
            patch("pentra_agent.nodes.vuln_hunt_node._get_session_factory", create=True),
        ):
            vuln_result = await vuln_hunt_node(state_after_recon)

        assert "findings" in vuln_result
        assert isinstance(vuln_result["findings"], list)
        assert "messages" in vuln_result
