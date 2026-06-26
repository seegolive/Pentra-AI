# packages/pentra-agent/pentra_agent/nodes/osint_node.py

"""
OSINT Node — passive information gathering sebelum recon teknis.
Posisi di graph: START → osint → plan → recon → ...

Sources:
1. crt.sh  — subdomain via certificate transparency (free, no API key)
2. H1 program lookup — apakah target punya bug bounty program?
3. Shodan summary  — port/service summary (requires SHODAN_API_KEY, optional)
"""

from __future__ import annotations

import asyncio
import logging
import os

import httpx
from langchain_core.messages import AIMessage

from pentra_agent.graph.state import PentraState

log = logging.getLogger(__name__)


async def osint_node(state: PentraState) -> dict:
    """Passive OSINT sebelum recon aktif.

    Tidak ada traffic ke target — semua passive sources.
    Graceful: jika semua sources gagal, tetap return dict kosong tanpa crash.
    """
    domain = state["target"]["domain"]
    results: dict = {}
    messages: list = []

    log.info("[osint_node] Starting passive OSINT for %s", domain)

    # Run all OSINT sources in parallel with a hard 30-second wall-clock cap.
    shodan_key = os.getenv("SHODAN_API_KEY")
    tasks = [
        _query_crt_sh(domain),
        _lookup_h1_program(domain),
        _query_shodan(domain, shodan_key) if shodan_key else asyncio.sleep(0, result=None),
        _run_dorking(domain),
        _run_email_osint(domain),
    ]
    try:
        ct_subdomains, h1_program, shodan_data, dorking, email_osint = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=60.0,
        )
    except asyncio.TimeoutError:
        log.warning("[osint_node] OSINT timed out after 60s — using partial results")
        ct_subdomains, h1_program, shodan_data, dorking, email_osint = [], None, None, {}, {}

    # Normalize exceptions from gather to empty/None
    if isinstance(ct_subdomains, Exception): ct_subdomains = []
    if isinstance(h1_program, Exception): h1_program = None
    if isinstance(shodan_data, Exception): shodan_data = None
    if isinstance(dorking, Exception): dorking = {}
    if isinstance(email_osint, Exception): email_osint = {}

    if ct_subdomains:
        results["ct_subdomains"] = ct_subdomains
        log.info("[osint_node] crt.sh: %d subdomains via certificate transparency", len(ct_subdomains))
    if h1_program:
        results["h1_program"] = h1_program
        log.info("[osint_node] H1 program found: %s", h1_program.get("name", "unknown"))
    if shodan_data:
        results["shodan"] = shodan_data
        log.info("[osint_node] Shodan: %d ports, org=%s", len(shodan_data.get("ports", [])), shodan_data.get("org", "unknown"))
    if dorking:
        results["dorking"] = dorking
        log.info("[osint_node] Dorking: %d high-risk URLs", len(dorking.get("high_risk_urls", [])))
    if email_osint:
        results["email_osint"] = email_osint
        log.info("[osint_node] Email OSINT: %d emails, %d critical",
                 len(email_osint.get("emails", [])), len(email_osint.get("critical_emails", [])))

    # ── Summary message ──────────────────────────────────────────────────────
    summary_parts = [f"OSINT complete for {domain}:"]

    if ct_subdomains:
        summary_parts.append(
            f"- {len(ct_subdomains)} subdomains via certificate transparency"
        )
        interesting = [
            s for s in ct_subdomains
            if any(kw in s.lower() for kw in ["admin", "api", "dev", "staging", "test", "internal"])
        ]
        if interesting:
            summary_parts.append(f"  Interesting: {', '.join(interesting[:5])}")

    if h1_program:
        summary_parts.append(
            f"- Bug bounty program: {h1_program.get('name')} "
            f"({'active' if h1_program.get('active') else 'inactive'})"
        )
        if h1_program.get("bounty_range"):
            summary_parts.append(f"  Bounty: {h1_program['bounty_range']}")

    if dorking:
        high_risk = dorking.get("high_risk_urls", [])
        summary_parts.append(f"- Dorking: {len(high_risk)} high-risk URLs")
        if high_risk:
            summary_parts.append(f"  Examples: {', '.join(high_risk[:3])}")

    if email_osint:
        emails = email_osint.get("emails", [])
        critical = email_osint.get("critical_emails", [])
        summary_parts.append(f"- Email OSINT: {len(emails)} email(s) found")
        if critical:
            summary_parts.append(f"  Critical breached emails: {', '.join(critical[:3])}")

    if not results:
        summary_parts.append("- No significant OSINT data found (passive only)")

    messages.append(AIMessage(content="\n".join(summary_parts)))

    # Broadcast OSINT summary to live feed
    try:
        from app.api.ws import ws_manager
        from datetime import datetime, UTC
        await ws_manager.broadcast(state["engagement_id"], {
            "type": "RECON_UPDATE",
            "phase": "osint",
            "subdomains_found": len(ct_subdomains),
            "alive_count": 0,
            "message": "\n".join(summary_parts[:4]),
            "timestamp": datetime.now(UTC).isoformat(),
        })
    except Exception:
        pass

    return {
        "osint_results": results,
        "messages": messages,
        # Seed subdomains with CT data before active recon
        "subdomains": [
            {"host": s, "source": "crt.sh", "is_alive": False}
            for s in ct_subdomains
        ] if ct_subdomains else [],
    }


# ── Source helpers ────────────────────────────────────────────────────────────

async def _query_crt_sh(domain: str) -> list[str]:
    """Query crt.sh for subdomains via certificate transparency.

    Free, no API key, fully passive.  Returns empty list on any error.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json"},
            )
            if r.status_code != 200:
                return []

            data = r.json()
            subdomains: set[str] = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n and domain in n and n != domain:
                        subdomains.add(n)

            return sorted(subdomains)[:100]

    except Exception as exc:
        log.warning("[osint_node] crt.sh query failed: %s", exc)
        return []


async def _lookup_h1_program(domain: str) -> dict | None:
    """Check if the domain has an active bug bounty program on HackerOne.

    Uses the H1 public program search endpoint (no auth required).
    Returns None on any error or if no match is found.
    """
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                "https://hackerone.com/programs/search",
                params={"q": root, "sort": "relevance", "limit": 5},
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (compatible; PentraAI/1.0)",
                },
            )
            if r.status_code != 200:
                return None

            data = r.json()
            results_list = data.get("results", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            for prog in results_list:
                prog_handle = prog.get("handle", "").lower()
                if root.replace(".", "") in prog_handle or prog_handle in root:
                    return {
                        "name": prog.get("name"),
                        "handle": prog.get("handle"),
                        "active": True,
                        "url": f"https://hackerone.com/{prog.get('handle')}",
                        "bounty_range": prog.get("meta", {}).get("reward_range"),
                        "in_scope": [],
                    }

    except Exception as exc:
        log.debug("[osint_node] H1 lookup failed: %s", exc)

    return None


async def _query_shodan(domain: str, api_key: str) -> dict | None:
    """Query Shodan DNS resolve + host info.  Requires a valid API key.

    Returns None on any error.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            dns_r = await client.get(
                "https://api.shodan.io/dns/resolve",
                params={"hostnames": domain, "key": api_key},
            )
            if dns_r.status_code != 200:
                return None

            ip = dns_r.json().get(domain)
            if not ip:
                return None

            host_r = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key},
            )
            if host_r.status_code != 200:
                return None

            data = host_r.json()
            return {
                "ip": ip,
                "org": data.get("org"),
                "isp": data.get("isp"),
                "country": data.get("country_name"),
                "ports": data.get("ports", []),
                "tags": data.get("tags", []),
                "vulns": list(data.get("vulns", {}).keys())[:10],
                "last_update": data.get("last_update"),
            }

    except Exception as exc:
        log.debug("[osint_node] Shodan query failed: %s", exc)
        return None


async def _run_dorking(domain: str) -> dict:
    """Run passive security dorking when the optional dependency is available."""
    try:
        from pentra_tools.osint.dorking import DorkScanner

        scanner = DorkScanner(delay_between_dorks=2.0, max_results_per_dork=5)
        result = await asyncio.wait_for(scanner.run_dorks(domain), timeout=20.0)
        if result.total_results == 0 and not result.high_risk_urls:
            return {}
        return {
            "high_risk_urls": result.high_risk_urls,
            "login_pages": result.login_pages,
            "admin_panels": result.admin_panels,
            "sensitive_files": result.sensitive_files,
            "api_endpoints": result.api_endpoints,
            "total_results": result.total_results,
        }
    except asyncio.TimeoutError:
        log.warning("[osint_node] dorking timed out after 120s")
        return {}
    except Exception as exc:
        log.warning("[osint_node] dorking failed (non-fatal): %s", exc)
        return {}


async def _run_email_osint(domain: str) -> dict:
    """Run email enumeration and optional HIBP breach checks."""
    try:
        from pentra_tools.osint.email_osint import EmailOSINT

        hunter_key = os.getenv("HUNTER_API_KEY")
        hibp_key = os.getenv("HIBP_API_KEY")
        result = await asyncio.wait_for(
            EmailOSINT().run(
                domain,
                hunter_api_key=hunter_key,
                hibp_api_key=hibp_key,
                check_breaches=bool(hibp_key),
            ),
            timeout=20.0,
        )
        if not result.emails and not result.critical_emails:
            return {}
        return {
            "emails": result.emails,
            "critical_emails": result.critical_emails,
            "breach_results": {
                email: {
                    "breached": breach.breached,
                    "breach_count": breach.breach_count,
                    "breaches": breach.breaches,
                    "has_passwords": breach.has_passwords,
                    "severity": breach.severity,
                }
                for email, breach in result.breach_results.items()
            },
        }
    except asyncio.TimeoutError:
        log.warning("[osint_node] email OSINT timed out after 120s")
        return {}
    except Exception as exc:
        log.warning("[osint_node] email OSINT failed (non-fatal): %s", exc)
        return {}
