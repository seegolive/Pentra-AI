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


async def recon_node(state: PentraState) -> dict:
    """Full recon pipeline: subfinder → httpx → nmap → LLM analysis."""
    domain = state["target"]["domain"]
    in_scope = state["scope"]["in_scope"]
    log.info("[recon_node] Starting recon for %s", domain)

    subdomains: list[dict] = await _run_subfinder(domain, in_scope)
    subdomains = await _run_httpx_probe(subdomains)
    ports: list[dict] = await _run_nmap(subdomains)
    tech_stack: list[str] = _extract_tech_stack(subdomains)
    endpoints: list[dict] = _extract_endpoints(subdomains)

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
    )
    # Merge Burp endpoints (dedup by url+method)
    existing_keys = {(e["url"], e.get("method", "GET")) for e in endpoints}
    for ep in burp_endpoints:
        if (ep["url"], ep.get("method", "GET")) not in existing_keys:
            endpoints.append(ep)
            existing_keys.add((ep["url"], ep.get("method", "GET")))
    # Merge Burp-detected tech stack
    for t in burp_tech:
        if t not in tech_stack:
            tech_stack.append(t)

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
                min_quality_score=0.4,
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
        f"- Tech stack: {', '.join(tech_stack) or 'unknown'}\n\n"
        f"**Analysis:** {hypothesis}"
    )

    return {
        "subdomains": subdomains,
        "open_ports": ports,
        "tech_stack": tech_stack,
        "endpoints": endpoints,
        "current_phase": "recon",
        "phase_history": ["recon"],
        "current_hypothesis": hypothesis,
        "knowledge_context": knowledge,
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
        log.info("[recon_node] subfinder found %d subdomains", len(results))
        return results
    except FileNotFoundError:
        log.warning("[recon_node] subfinder not found — skipping")
        return [{"host": domain, "ip": None, "source": "manual", "is_alive": False, "status_code": None, "tech_stack": []}]
    except Exception as exc:
        log.warning("[recon_node] subfinder error: %s", exc)
        return []


async def _run_httpx_probe(subdomains: list[dict]) -> list[dict]:
    """Probe each subdomain with httpx for alive status + tech detection."""
    if not subdomains:
        return subdomains
    try:
        import httpx as _httpx

        async def probe_one(sub: dict) -> dict:
            for scheme in ("https", "http"):
                url = f"{scheme}://{sub['host']}"
                try:
                    async with _httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
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


async def _fetch_burp_endpoints(
    domain: str,
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

    return endpoints, tech
