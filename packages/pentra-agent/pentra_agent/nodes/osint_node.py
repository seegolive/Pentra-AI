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

    # ── 1. Certificate Transparency (crt.sh) ────────────────────────────────
    ct_subdomains = await _query_crt_sh(domain)
    if ct_subdomains:
        results["ct_subdomains"] = ct_subdomains
        log.info(
            "[osint_node] crt.sh: %d subdomains via certificate transparency",
            len(ct_subdomains),
        )

    # ── 2. H1 Bug Bounty Program Lookup ─────────────────────────────────────
    h1_program = await _lookup_h1_program(domain)
    if h1_program:
        results["h1_program"] = h1_program
        log.info(
            "[osint_node] H1 program found: %s (scope: %d items)",
            h1_program.get("name", "unknown"),
            len(h1_program.get("in_scope", [])),
        )

    # ── 3. Shodan Summary (optional — requires SHODAN_API_KEY) ──────────────
    shodan_key = os.getenv("SHODAN_API_KEY")
    if shodan_key:
        shodan_data = await _query_shodan(domain, shodan_key)
        if shodan_data:
            results["shodan"] = shodan_data
            log.info(
                "[osint_node] Shodan: %d ports, org=%s",
                len(shodan_data.get("ports", [])),
                shodan_data.get("org", "unknown"),
            )
    else:
        log.debug("[osint_node] SHODAN_API_KEY not set — skipping Shodan")

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

    if not results:
        summary_parts.append("- No significant OSINT data found (passive only)")

    messages.append(AIMessage(content="\n".join(summary_parts)))

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
