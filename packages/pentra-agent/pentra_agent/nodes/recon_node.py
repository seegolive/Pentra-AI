"""Recon node — subdomain enum, HTTP probing, port scanning, tech detection.

Execution order:
  1. subfinder → get subdomains
  2. httpx  → alive check + status code + tech stack (from response headers/body)
  3. nmap   → port scan on alive hosts (sample, not all)
  4. LLM    → analyze_recon_results() → hypothesis + knowledge context update

Each tool step degrades gracefully: if a tool is absent or fails, results
from that step are skipped but the pipeline continues.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

from langchain_core.messages import AIMessage

from pentra_agent.graph.state import PentraState
from pentra_agent.llm.client import LLMClient

try:
    from pentra_tools.burp.client import BurpMCPClient
    from pentra_tools.burp.exceptions import BurpConnectionError, BurpNotProError
    _BURP_AVAILABLE = True
except ImportError:
    _BURP_AVAILABLE = False

try:
    from pentra_tools.recon.rate_limit_detector import probe_rate_limit, RateLimitResult as _RLResult
    _RL_AVAILABLE = True
except ImportError:
    _RL_AVAILABLE = False

from pentra_scope import ScopeEnforcer
from pentra_scope.errors import ScopeViolationError

log = logging.getLogger(__name__)


# ── Burp MCP config helper ───────────────────────────────────────────────────

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


async def recon_node(state: PentraState) -> dict:
    """Full recon pipeline: subfinder → httpx → nmap → LLM analysis."""
    domain = state["target"]["domain"]
    in_scope = state["scope"]["in_scope"]
    log.info("[recon_node] Starting recon for %s", domain)

    # ── Compress message history if approaching context limit ─────────────────
    try:
        from pentra_agent.llm.summarizer import maybe_summarize
        from pentra_agent.llm.client import LLMClient as _LLMClient
        await maybe_summarize(
            list(state.get("messages", [])),
            llm=_LLMClient(base_url=_ollama_url(), model=state["llm_model"]),
        )
    except Exception as _sum_exc:
        log.debug("[recon_node] summarizer failed (non-fatal): %s", _sum_exc)

    subdomains: list[dict] = await _run_subfinder(domain, in_scope)
    subdomains = await _run_httpx_probe(subdomains)

    # ── Rate limit + WAF profiling (run concurrently after httpx probe) ──────
    primary_url = f"http://{domain}/"
    rate_limit_info: dict = {"safe_rps": 20, "delay_ms": 0, "is_limited": False, "notes": []}
    waf_info: dict = {"waf_type": None, "is_blocking": False, "bypass_strategies": [], "safe_rps": 20}

    async def _probe_rl() -> None:
        nonlocal rate_limit_info
        if not _RL_AVAILABLE:
            return
        try:
            rl = await probe_rate_limit(primary_url, probe_count=6, probe_interval=0.15)
            rate_limit_info = {
                "safe_rps": rl.safe_rps,
                "delay_ms": rl.recommended_delay_ms,
                "is_limited": rl.is_rate_limited,
                "notes": rl.notes,
            }
            log.info(
                "[recon_node] Rate limit probe: safe_rps=%d delay=%dms is_limited=%s",
                rl.safe_rps, rl.recommended_delay_ms, rl.is_rate_limited,
            )
        except Exception as exc:
            log.warning("[recon_node] Rate limit probe failed (non-fatal): %s", exc)

    async def _probe_waf() -> None:
        nonlocal waf_info
        try:
            from pentra_tools.recon.waf_profiler import profile_waf
            waf = await profile_waf(primary_url)
            waf_info = {
                "waf_type": waf.waf_type,
                "is_blocking": waf.is_blocking,
                "bypass_strategies": waf.bypass_strategies,
                "safe_rps": waf.block_threshold_rps,
            }
            if waf.waf_detected:
                log.info(
                    "[recon_node] WAF detected: %s (blocking=%s) → bypass: %s",
                    waf.waf_type, waf.is_blocking, waf.bypass_strategies[:2],
                )
            else:
                log.info("[recon_node] No WAF detected — normal scan speed")
        except Exception as exc:
            log.warning("[recon_node] WAF profile failed (non-fatal): %s", exc)

    await asyncio.gather(_probe_rl(), _probe_waf())

    ports: list[dict] = await _run_nmap(subdomains)
    tech_stack: list[str] = _extract_tech_stack(subdomains)

    # Defense-in-depth: drop any OOS subdomain before building endpoints
    out_of_scope = state["scope"]["out_of_scope"]
    scoped_subdomains = [
        s for s in subdomains
        if _is_in_scope(s["host"], in_scope)
        and (not out_of_scope or not _is_in_scope(s["host"], out_of_scope))
    ]
    if len(scoped_subdomains) < len(subdomains):
        log.warning(
            "[recon_node] Dropped %d OOS subdomains before endpoint extraction",
            len(subdomains) - len(scoped_subdomains),
        )
    endpoints: list[dict] = _extract_endpoints(scoped_subdomains)

    # ── Fallback: ensure at least one endpoint from the target's base URLs ──
    if not endpoints:
        for base_url in state["target"].get("base_urls", []):
            clean_url = base_url.rstrip("/") + "/"
            endpoints.append({
                "url": clean_url,
                "method": "GET",
                "params": [],
                "source": "target_base_fallback",
            })
        if endpoints:
            log.info(
                "[recon_node] No probed endpoints — falling back to %d base URL(s)",
                len(endpoints),
            )

    # ── Burp sitemap + proxy history (graceful fallback) ───────────────────
    burp_endpoints, burp_tech = await _fetch_burp_endpoints(
        domain=domain,
        in_scope=in_scope,
        out_of_scope=state["scope"]["out_of_scope"],
    )    # Merge Burp endpoints (dedup by url+method)
    existing_keys = {(e["url"], e.get("method", "GET")) for e in endpoints}
    for ep in burp_endpoints:
        if (ep["url"], ep.get("method", "GET")) not in existing_keys:
            endpoints.append(ep)
            existing_keys.add((ep["url"], ep.get("method", "GET")))
    # Merge Burp-detected tech stack
    for t in burp_tech:
        if t not in tech_stack:
            tech_stack.append(t)

    # ── Smart dedup (18.2) then GF prioritization (18.1) ─────────────────────
    try:
        from pentra_tools.recon.dedup import smart_dedup_endpoints
        endpoints = smart_dedup_endpoints(endpoints)
    except Exception as exc:
        log.warning("[recon_node] smart_dedup failed (non-fatal): %s", exc)

    try:
        from pentra_tools.recon.gf_filter import prioritize_endpoints_for_vuln_hunt
        endpoints = prioritize_endpoints_for_vuln_hunt(endpoints, max_endpoints=150)
        gf_matched = [ep for ep in endpoints if ep.get("gf_pattern")]
        log.info(
            "[recon_node] GF patterns: %d/%d endpoints have vuln hints",
            len(gf_matched), len(endpoints),
        )
        if gf_matched:
            log.info(
                "[recon_node] Top GF matches: %s",
                [(ep["url"], ep["gf_pattern"]) for ep in gf_matched[:5]],
            )
    except Exception as exc:
        log.warning("[recon_node] GF prioritization failed (non-fatal): %s", exc)

    knowledge: list[dict] = []
    try:
        from pentra_knowledge.services.search import hybrid_search
        from app.db.base import _get_session_factory

        async with _get_session_factory()() as db:
            records = await hybrid_search(
                query=f"vulnerabilities for {', '.join(tech_stack) or domain}",
                db=db,
                tech_stack=tech_stack if tech_stack else None,
                top_k=8,
                min_quality_score=0.0,
            )
        knowledge = [r.model_dump() for r in records]
    except Exception as exc:
        log.warning("[recon_node] KB query failed: %s", exc)

    llm = LLMClient(base_url=_ollama_url(), model=state["llm_model"])
    analysis: dict = {}
    try:
        analysis = await llm.analyze_recon_results(
            subdomains=subdomains,
            ports=ports,
            tech_stack=tech_stack,
            knowledge_context=knowledge,
        )
    except Exception as exc:
        log.warning("[recon_node] LLM analysis failed: %s", exc)
        analysis = {"summary": "LLM analysis unavailable", "hypotheses": []}

    hypothesis = analysis.get("summary", "")
    summary_msg = (
        f"**Recon Complete** for `{domain}`\n\n"
        f"- Subdomains: {len(subdomains)}\n"
        f"- Alive hosts: {sum(1 for s in subdomains if s.get('is_alive'))}\n"
        f"- Open ports: {len(ports)}\n"
        f"- Tech stack: {', '.join(tech_stack) or 'unknown'}\n"
        f"- Safe RPS: {rate_limit_info['safe_rps']}"
        + (f" ⚠️ rate limited" if rate_limit_info['is_limited'] else "")
        + (f"\n- WAF: {waf_info['waf_type']} (blocking={waf_info['is_blocking']})" if waf_info.get('waf_type') else "")
        + f"\n\n**Analysis:** {hypothesis}"
    )

    # ── Task 20.2: Subdomain takeover detection ───────────────────────────────
    takeover_findings: list[dict] = []
    subdomain_hosts = [s["host"] for s in subdomains if s.get("host")]
    if subdomain_hosts:
        try:
            from pentra_tools.recon.takeover_detector import detect_subdomain_takeovers
            from pentra_scope import ScopeEnforcer

            _scope_enforcer = ScopeEnforcer(
                in_scope=state["scope"].get("in_scope", []),
                out_of_scope=state["scope"].get("out_of_scope", []),
            )
            takeover_findings = await detect_subdomain_takeovers(
                subdomains=subdomain_hosts,
                scope_check_fn=lambda u: True,  # subdomains already scope-checked
            )
            if takeover_findings:
                log.info("[recon_node] Takeover: %d candidate(s) found", len(takeover_findings))
        except Exception as _tk_exc:
            log.debug("[recon_node] Takeover detection failed (non-fatal): %s", _tk_exc)

    return {
        "subdomains": subdomains,
        "open_ports": ports,
        "tech_stack": tech_stack,
        "endpoints": endpoints,
        "current_phase": "recon",
        "phase_history": ["recon"],
        "current_hypothesis": hypothesis,
        "knowledge_context": knowledge,
        "rate_limit_info": rate_limit_info,
        "waf_info": waf_info,
        "findings": takeover_findings,  # early findings from recon (takeover)
        "messages": [AIMessage(content=summary_msg)],
    }


# ── Tool helpers ──────────────────────────────────────────────────────────────

async def _run_subfinder(domain: str, in_scope: list[str]) -> list[dict]:
    """Run subfinder; return list of Subdomain dicts."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-d", domain, "-all", "-silent", "-json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        results: list[dict] = []
        for line in stdout.decode().splitlines():
            try:
                obj = json.loads(line)
                host: str = obj.get("host", "")
                if _is_in_scope(host, in_scope):
                    results.append({
                        "host": host,
                        "ip": None,
                        "source": obj.get("source", "subfinder"),
                        "is_alive": False,
                        "status_code": None,
                        "tech_stack": [],
                    })
            except (json.JSONDecodeError, KeyError):
                continue
        # If subfinder ran OK but found no subdomains (e.g. leaf subdomain), add the
        # target domain itself so httpx probe and nuclei have at least one entry.
        if not results:
            log.info("[recon_node] subfinder found 0 subdomains — adding domain itself as fallback")
            results = [{"host": domain, "ip": None, "source": "subfinder_fallback", "is_alive": False, "status_code": None, "tech_stack": []}]
        log.info("[recon_node] subfinder found %d subdomains", len(results))
        return results
    except FileNotFoundError:
        log.warning("[recon_node] subfinder not found — skipping")
        return [{"host": domain, "ip": None, "source": "manual", "is_alive": False, "status_code": None, "tech_stack": []}]
    except Exception as exc:
        log.warning("[recon_node] subfinder error: %s", exc)
        return [{"host": domain, "ip": None, "source": "error_fallback", "is_alive": False, "status_code": None, "tech_stack": []}]


async def _run_httpx_probe(subdomains: list[dict]) -> list[dict]:
    """Probe each subdomain with httpx for alive status + tech detection."""
    if not subdomains:
        return subdomains
    try:
        import httpx as _httpx

        burp_proxy = _get_burp_proxy()
        proxy_kwargs = {"proxy": burp_proxy} if burp_proxy else {}
        if burp_proxy:
            log.info("[recon_node] httpx probe routing through Burp proxy: %s", burp_proxy)

        async def probe_one(sub: dict) -> dict:
            for scheme in ("https", "http"):
                url = f"{scheme}://{sub['host']}"
                try:
                    async with _httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False, **proxy_kwargs) as client:
                        resp = await client.get(url)
                        sub["is_alive"] = True
                        sub["status_code"] = resp.status_code
                        sub["tech_stack"] = _detect_tech_from_headers(dict(resp.headers))
                        sub["_scheme"] = scheme  # remember which scheme worked
                        return sub
                except Exception:
                    continue
            return sub

        tasks = [probe_one(s) for s in subdomains[:50]]  # cap at 50
        return list(await asyncio.gather(*tasks, return_exceptions=False))
    except ImportError:
        log.warning("[recon_node] httpx not available — skipping probe")
        return subdomains


async def _run_nmap(subdomains: list[dict]) -> list[dict]:
    """Quick nmap scan on top alive hosts; returns list of Port dicts."""
    alive = [s for s in subdomains if s.get("is_alive")][:10]
    if not alive:
        return []
    try:
        targets = [s["host"] for s in alive]
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-T4", "--open", "-oX", "-",
            "--top-ports", "1000",
            *targets,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        return _parse_nmap_xml(stdout.decode())
    except FileNotFoundError:
        log.warning("[recon_node] nmap not found — skipping port scan")
        return []
    except Exception as exc:
        log.warning("[recon_node] nmap error: %s", exc)
        return []


def _parse_nmap_xml(xml: str) -> list[dict]:
    """Parse nmap XML output into list of Port dicts."""
    try:
        import xml.etree.ElementTree as ET  # noqa: N814

        root = ET.fromstring(xml)
        ports: list[dict] = []
        for host_el in root.findall(".//host"):
            addr_el = host_el.find(".//address[@addrtype='ipv4']")
            hostname_el = host_el.find(".//hostname")
            host_str = (
                hostname_el.attrib.get("name") if hostname_el is not None
                else (addr_el.attrib.get("addr") if addr_el is not None else "unknown")
            )
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.attrib.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                ports.append({
                    "host": host_str,
                    "port": int(port_el.attrib.get("portid", 0)),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "service": service_el.attrib.get("name", "") if service_el is not None else "",
                    "version": service_el.attrib.get("version") if service_el is not None else None,
                    "state": "open",
                })
        return ports
    except Exception as exc:
        log.warning("[recon_node] nmap XML parse error: %s", exc)
        return []


def _detect_tech_from_headers(headers: dict) -> list[str]:
    """Heuristic tech detection from HTTP response headers."""
    tech: list[str] = []
    server = headers.get("server", "").lower()
    x_powered = headers.get("x-powered-by", "").lower()
    for keyword, label in [
        ("nginx", "nginx"), ("apache", "apache"), ("iis", "iis"),
        ("php", "php"), ("ruby", "ruby on rails"), ("django", "django"),
        ("express", "express"), ("next.js", "nextjs"), ("wordpress", "wordpress"),
        ("cloudflare", "cloudflare"),
    ]:
        if keyword in server or keyword in x_powered:
            tech.append(label)
    return tech


def _extract_tech_stack(subdomains: list[dict]) -> list[str]:
    """Deduplicate tech stack across all subdomains."""
    seen: set[str] = set()
    result: list[str] = []
    for sub in subdomains:
        for t in sub.get("tech_stack", []):
            if t not in seen:
                seen.add(t)
                result.append(t)
    return result


def _extract_endpoints(subdomains: list[dict]) -> list[dict]:
    """Build basic endpoint list from subdomains (root path).

    Includes all subdomains regardless of is_alive status — alive hosts get
    the probed scheme; unreachable hosts default to https so that active
    scanners (nuclei, ffuf) can still attempt them.
    """
    endpoints: list[dict] = []
    for sub in subdomains:
        if sub.get("is_alive"):
            # Use the scheme that actually worked during probe; fall back to https
            scheme = sub.get("_scheme", "https" if sub.get("status_code") else "http")
            source = "httpx_probe"
        else:
            scheme = "https"
            source = "subdomain_enum"
        endpoints.append({
            "url": f"{scheme}://{sub['host']}/",
            "method": "GET",
            "params": [],
            "source": source,
        })
    return endpoints


def _is_in_scope(host: str, in_scope: list[str]) -> bool:
    """Check if host is within scope (simple subdomain match)."""
    if not in_scope:
        return True
    for scope_entry in in_scope:
        scope_entry = scope_entry.lstrip("*.")
        if host == scope_entry or host.endswith(f".{scope_entry}"):
            return True
    return False


def _ollama_url() -> str:
    return os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/") + "/v1"


async def _burp_startup_sequence(
    client: "BurpMCPClient",
    in_scope: list[str],
    out_of_scope: list[str],
) -> dict:
    """Run Burp Pro setup for a new engagement session.

    1. Auto-approve each in-scope target (persist do_intercept=false + scope in .burp file).
    2. Sync in/out-of-scope URLs to Burp project scope (runtime scope object).
    3. Disable proxy intercept runtime state.

    Returns a status dict for logging.  Never raises — failures are non-fatal.
    """
    from pentra_tools.burp.auto_approve import ensure_target_approved

    status: dict = {}

    # ── Step 1: Auto-approve each in-scope domain (persists to .burp project file) ──
    # Fixes "null Timed Out" in Logger++ caused by:
    #   - proxy.intercept_client_requests.do_intercept = true (persists across restarts)
    #   - Target domain not pre-approved in Burp scope
    approved_count = 0
    for domain in in_scope:
        try:
            ok = await ensure_target_approved(client, domain)
            if ok:
                approved_count += 1
        except Exception as exc:
            log.warning("[recon_node] auto_approve failed for %s (non-fatal): %s", domain, exc)
    status["auto_approved"] = approved_count
    if approved_count:
        log.info("[recon_node] Auto-approved %d target(s) in Burp (intercept persisted OFF)", approved_count)

    # ── Step 2: Sync scope to Burp project scope (runtime scope object) ──────────
    try:
        await client.set_project_scope(
            in_scope_urls=in_scope,
            out_of_scope_urls=out_of_scope,
        )
        status["scope_synced"] = True
        log.info("[recon_node] Burp scope synced: %d in-scope, %d out-of-scope", len(in_scope), len(out_of_scope))
    except Exception as exc:
        log.warning("[recon_node] Burp scope sync failed (non-fatal): %s", exc)
        status["scope_synced"] = False

    # ── Step 3: Disable proxy intercept at runtime (belt-and-suspenders) ─────────
    try:
        await client.set_proxy_intercept_state(enabled=False)
        status["intercept_disabled"] = True
        log.info("[recon_node] Burp proxy intercept disabled for automated scanning")
    except Exception as exc:
        log.warning("[recon_node] Burp intercept disable failed (non-fatal): %s", exc)
        status["intercept_disabled"] = False

    return status


async def _fetch_burp_endpoints(    domain: str,
    in_scope: list[str],
    out_of_scope: list[str],
) -> tuple[list[dict], list[str]]:
    """Pull sitemap + proxy history from Burp MCP; extract endpoints + tech.

    Returns (endpoints, tech_stack). Both lists are empty if Burp is not
    reachable or the integration is not configured.
    """
    burp_url, burp_enabled = _get_burp_config()
    if not burp_url:
        log.info(
            "[recon_node] BURP_MCP_URL not set — Burp sitemap disabled. "
            "Set BURP_MCP_URL=http://127.0.0.1:9876 in .env to enable."
        )
        return [], []
    if not burp_enabled:
        log.info("[recon_node] BURP_MCP_ENABLED=false — Burp disabled.")
        return [], []
    if not _BURP_AVAILABLE:
        log.warning("[recon_node] pentra-tools Burp module not available — skipping")
        return [], []

    # Scope check before touching Burp
    enforcer = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)
    try:
        enforcer.validate_or_raise(domain)
    except ScopeViolationError as exc:
        log.warning("[recon_node] Burp fetch skipped — scope violation: %s", exc)
        return [], []

    client = BurpMCPClient(base_url=burp_url)

    if not await client.health_check():
        log.info("[recon_node] Burp MCP not reachable — skipping sitemap fetch")
        return [], []

    async with client.managed_session():
        # ── Burp startup sequence (scope sync + intercept disable) ───────────────
        await _burp_startup_sequence(client, in_scope=in_scope, out_of_scope=out_of_scope)

        endpoints: list[dict] = []
        tech: list[str] = []

        # ── Sitemap (unique URLs already deduplicated by BurpMCPClient) ──────────
        try:
            sitemap = await client.get_sitemap(url_prefix=f"https://{domain}")
            for entry in sitemap:
                try:
                    enforcer.validate_or_raise(entry.url)
                except ScopeViolationError:
                    continue
                endpoints.append({
                    "url": entry.url,
                    "method": entry.method,
                    "params": [],
                    "source": "burp_sitemap",
                })
            log.info("[recon_node] Burp sitemap: %d entries for %s", len(sitemap), domain)
        except (BurpConnectionError, Exception) as exc:
            log.warning("[recon_node] Burp sitemap error: %s", exc)

        # ── Proxy history (last 200 requests for the domain) ─────────────────────
        try:
            import re as _re
            escaped = _re.escape(domain)
            history = await client.get_proxy_history(filter_regex=escaped, limit=200)
            for entry in history:
                try:
                    enforcer.validate_or_raise(entry.url)
                except ScopeViolationError:
                    continue
                # Deduplicate against sitemap entries
                key = (entry.url, entry.method.upper())
                if not any(e["url"] == key[0] and e.get("method", "GET") == key[1] for e in endpoints):
                    endpoints.append({
                        "url": entry.url,
                        "method": entry.method.upper(),
                        "params": [],
                        "source": "burp_proxy",
                    })
                # Detect tech from response headers
                for header_key, header_val in entry.response_headers.items():
                    combined = f"{header_key}: {header_val}".lower()
                    for keyword, label in [
                        ("x-powered-by: php", "php"),
                        ("x-powered-by: asp", "asp.net"),
                        ("server: nginx", "nginx"),
                        ("server: apache", "apache"),
                        ("x-generator: wordpress", "wordpress"),
                        ("x-drupal", "drupal"),
                        ("laravel_session", "laravel"),
                        ("x-rails", "ruby on rails"),
                    ]:
                        if keyword in combined and label not in tech:
                            tech.append(label)
            log.info("[recon_node] Burp proxy history: %d unique endpoints", len(history))
        except (BurpConnectionError, Exception) as exc:
            log.warning("[recon_node] Burp proxy history error: %s", exc)

        # ── Organizer items (requests saved manually by researcher) ──────────────
        try:
            import re as _re_org
            # Use regex-filtered fetch to get only items relevant to this domain
            _org_regex = _re_org.escape(domain)
            try:
                organizer_items = await client.get_organizer_items_regex(
                    filter_regex=_org_regex, limit=20
                )
            except Exception:
                organizer_items = await client.get_organizer_items(limit=20)
            if organizer_items:
                log.info("[recon_node] Burp Organizer: %d saved items", len(organizer_items))
                enforcer_obj = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)
                for item in organizer_items:
                    if not item.url:
                        continue
                    try:
                        enforcer_obj.validate_or_raise(item.url)
                    except ScopeViolationError:
                        continue
                    key = (item.url, item.method.upper())
                    if not any(e["url"] == key[0] and e.get("method", "GET") == key[1] for e in endpoints):
                        endpoints.append({
                            "url": item.url,
                            "method": item.method.upper(),
                            "params": [],
                            "source": "burp_organizer",
                            "notes": item.notes,
                        })
        except (BurpConnectionError, Exception) as exc:
            log.warning("[recon_node] Burp Organizer fetch error: %s", exc)

        return endpoints, tech
