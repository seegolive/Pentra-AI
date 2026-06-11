#!/usr/bin/env python3
"""
live_scan.py — Live E2E scan runner for Pentra AI
Runs recon_node → vuln_hunt_node against a real target WITHOUT mocks.

Usage:
    cd /home/mdilab/projects/Pentra-AI/apps/api
    uv run python ../../scripts/live_scan.py --domain testaspnet.vulnweb.com

Requires:
    - Burp Suite Pro running with MCP on localhost:9877
    - Ollama running with qwen2.5:32b or qwen2.5:7b
    - subfinder, nuclei, ffuf, nmap, httpx on PATH
    - PostgreSQL running (for audit log)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import uuid
from datetime import datetime

# ── Env defaults (override with BURP_MCP_URL=... etc.) ───────────────────────
os.environ.setdefault("BURP_MCP_URL", "http://localhost:9877")
os.environ.setdefault("BURP_MCP_ENABLED", "true")
os.environ.setdefault("BURP_PROXY_URL", "http://localhost:8082")
os.environ.setdefault("OLLAMA_URL", "http://localhost:11434")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://pentra:pentra@localhost:5432/pentra")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("live_scan")

# Reduce noise from underlying libraries
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("mcp").setLevel(logging.WARNING)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _banner(text: str) -> None:
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}\n")


def _print_findings(findings: list[dict]) -> None:
    if not findings:
        print("  [!] No findings discovered.\n")
        return
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_f = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5))
    print(f"  Total: {len(sorted_f)} findings\n")
    for i, f in enumerate(sorted_f, 1):
        sev = f.get("severity", "?").upper()
        title = f.get("title", "Unknown")
        url = f.get("target_url", f.get("url", "?"))
        vuln_class = f.get("vuln_class", "")
        source = f.get("source", "?")
        confidence = f.get("confidence", "")
        print(f"  [{i:02d}] [{sev}] {title}")
        print(f"        URL:     {url}")
        print(f"        Class:   {vuln_class}  |  Source: {source}  |  Confidence: {confidence}")
        desc = f.get("description", "")
        if desc:
            snippet = desc[:200].replace("\n", " ")
            print(f"        Detail:  {snippet}...")
        print()


def _build_initial_state(domain: str, engagement_id: str, mode: str, auth_credentials: dict | None = None, extra_endpoints: list | None = None) -> dict:
    seeded = []
    if extra_endpoints:
        base = f"http://{domain}" if not domain.startswith("http") else domain
        for url in extra_endpoints:
            full = url if url.startswith("http") else f"{base.rstrip('/')}/{url.lstrip('/')}"
            seeded.append({"url": full, "method": "GET", "status": 200, "source": "manual"})
    return {
        "engagement_id": engagement_id,
        "target": {"domain": domain},
        "scope": {
            "in_scope": [domain],
            "out_of_scope": [],
        },
        "mode": mode,
        "current_phase": "init",
        "phase_history": [],
        "subdomains": [],
        "endpoints": seeded,
        "tech_stack": [],
        "findings": [],
        "triaged_findings": [],
        "messages": [],
        "awaiting_approval": False,
        "knowledge_context": [],
        "tool_outputs": [],
        "hunt_rounds": 0,
        "llm_model": os.getenv("OLLAMA_MODEL_DEFAULT", "qwen2.5:32b"),
        "pentest_plan": (
            f"Black-box pentest of {domain}. "
            "Focus on: SQL injection, XSS, IDOR, path traversal, auth bypass, "
            "SSRF, file inclusion, command injection. "
            "Use Burp Collaborator for OOB detection where possible."
        ),
        "auth_credentials": auth_credentials,
    }


async def run_live_scan(domain: str, mode: str = "agentic", auth_credentials: dict | None = None, extra_endpoints: list | None = None) -> None:
    """Run full recon → vuln_hunt pipeline live against target domain."""
    # Late imports so env vars are already set
    from pentra_agent.nodes.recon_node import recon_node
    from pentra_agent.nodes.vuln_hunt_node import vuln_hunt_node

    engagement_id = str(uuid.uuid4())

    _banner(f"PENTRA AI — LIVE SCAN")
    print(f"  Target:       {domain}")
    print(f"  Engagement:   {engagement_id}")
    print(f"  Mode:         {mode}")
    print(f"  Burp MCP:     {os.environ['BURP_MCP_URL']}")
    print(f"  Ollama:       {os.environ['OLLAMA_URL']}")
    print(f"  LLM model:    {os.getenv('OLLAMA_MODEL_DEFAULT', 'qwen2.5:32b')}")
    if auth_credentials:
        print(f"  Auth:         {auth_credentials['type']}")
    print(f"  Started:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    state = _build_initial_state(domain, engagement_id, mode, auth_credentials=auth_credentials, extra_endpoints=extra_endpoints)
    seeded = state.get("endpoints", [])  # save before recon overwrites
    if extra_endpoints:
        print(f"  Extra URLs:   {len(extra_endpoints)} seeded into initial state")

    # ── Phase 1: RECON ────────────────────────────────────────────────────────
    _banner("PHASE 1: RECON  (subfinder → httpx → nmap → Burp sitemap → LLM)")
    t0 = asyncio.get_event_loop().time()
    try:
        recon_update = await recon_node(state)
    except Exception as exc:
        log.error("recon_node failed: %s", exc, exc_info=True)
        print(f"\n[FATAL] Recon phase failed: {exc}")
        return

    elapsed = asyncio.get_event_loop().time() - t0
    state = {**state, **recon_update}

    # Merge extra_endpoints back (recon_node overwrites endpoints key)
    if extra_endpoints:
        existing_urls = {e.get("url") for e in state.get("endpoints", [])}
        for ep in seeded:
            if ep["url"] not in existing_urls:
                state["endpoints"].append(ep)
                existing_urls.add(ep["url"])
        log.info("[live_scan] Merged %d seeded endpoints → total %d", len(seeded), len(state["endpoints"]))

    subdomains = state.get("subdomains", [])
    endpoints = state.get("endpoints", [])
    tech_stack = state.get("tech_stack", [])
    print(f"  Elapsed:      {elapsed:.1f}s")
    print(f"  Subdomains:   {len(subdomains)}")
    print(f"  Endpoints:    {len(endpoints)}")
    print(f"  Tech stack:   {', '.join(tech_stack) if tech_stack else '(none detected)'}")

    if subdomains:
        print("\n  Discovered subdomains:")
        for s in subdomains[:20]:
            alive = "✓" if s.get("alive") else "·"
            print(f"    [{alive}] {s.get('host', s)}")

    if endpoints:
        print("\n  Discovered endpoints (first 20):")
        for ep in endpoints[:20]:
            print(f"    {ep.get('method','GET'):7} {ep.get('url', ep)}")

    # ── Phase 2: VULN HUNT ────────────────────────────────────────────────────
    _banner("PHASE 2: VULN HUNT  (nuclei → ffuf → Burp Pro scanner → LLM exploit testing)")
    t1 = asyncio.get_event_loop().time()
    try:
        hunt_update = await vuln_hunt_node(state)
    except Exception as exc:
        log.error("vuln_hunt_node failed: %s", exc, exc_info=True)
        print(f"\n[FATAL] Vuln hunt phase failed: {exc}")
        state_so_far = {**state}
        partial_findings = state_so_far.get("findings", [])
        if partial_findings:
            _banner("PARTIAL FINDINGS (before failure)")
            _print_findings(partial_findings)
        return

    elapsed = asyncio.get_event_loop().time() - t1
    state = {**state, **hunt_update}
    findings = state.get("findings", [])

    print(f"  Elapsed:      {elapsed:.1f}s")
    print(f"  Raw findings: {len(state.get('tool_outputs', []))} Collaborator payload(s)")

    # ── Results ───────────────────────────────────────────────────────────────
    _banner(f"VULNERABILITY FINDINGS for {domain}")
    _print_findings(findings)

    # Burp scanner issues (from tool_outputs / Collaborator)
    tool_outputs = state.get("tool_outputs", [])
    if tool_outputs:
        print("\n  Collaborator / Tool outputs:")
        for to in tool_outputs:
            print(f"    {json.dumps(to, indent=2)[:300]}")

    # LLM summary message
    msgs = hunt_update.get("messages", [])
    if msgs:
        print("\n  LLM Summary:")
        print("  " + "-" * 60)
        for msg in msgs[-1:]:
            content = getattr(msg, "content", str(msg))
            print(content)
        print()

    # Save JSON report
    report_path = f"/tmp/pentra_scan_{domain.replace('.','_')}_{engagement_id[:8]}.json"
    report = {
        "engagement_id": engagement_id,
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "subdomains": subdomains,
        "endpoints": endpoints,
        "tech_stack": tech_stack,
        "findings": findings,
        "tool_outputs": tool_outputs,
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  Full JSON report saved: {report_path}")

    # Summary stats
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    med  = sum(1 for f in findings if f.get("severity") == "medium")
    low  = sum(1 for f in findings if f.get("severity") == "low")
    print(f"\n  SEVERITY SUMMARY: CRITICAL={crit}  HIGH={high}  MEDIUM={med}  LOW={low}")
    _banner("SCAN COMPLETE")


def main() -> None:
    parser = argparse.ArgumentParser(description="Pentra AI live scan runner")
    parser.add_argument("--domain", default="testaspnet.vulnweb.com",
                        help="Target domain (must be in-scope / intentionally vulnerable)")
    parser.add_argument("--mode", default="agentic", choices=["agentic", "semi_auto"],
                        help="Agent mode")

    # ── Scan Engine Presets (Task 18.11) ──────────────────────────────────────
    parser.add_argument(
        "--preset",
        default=None,
        choices=["full", "fast", "stealth", "quick", "authenticated", "pentra-ft"],
        help=(
            "Scan engine preset — controls which tools run, concurrency, and pacing. "
            "full: max coverage (~40-60 min) | fast: speed over depth (~10-15 min) | "
            "stealth: low-noise passive only (~60-90 min) | quick: smoke test (~5-8 min) | "
            "authenticated: full with auth support | pentra-ft: LoRA fine-tuned LLM"
        ),
    )

    # ── Authenticated scan options (Task 18.6) ────────────────────────────────
    auth_group = parser.add_argument_group("Authenticated scan (optional)")
    auth_group.add_argument("--auth-cookie",
                            help='Pre-captured session cookie string. E.g. "session=abc; csrf=xyz"')
    auth_group.add_argument("--auth-bearer",
                            help="Bearer token (without 'Bearer ' prefix)")
    auth_group.add_argument("--auth-header",
                            help="Custom auth header value (combined with --auth-header-name)")
    auth_group.add_argument("--auth-header-name", default="Authorization",
                            help="Custom header name when using --auth-header (default: Authorization)")
    auth_group.add_argument("--auth-user",
                            help="Username for auto-login")
    auth_group.add_argument("--auth-pass",
                            help="Password for auto-login")
    auth_group.add_argument("--auth-login-url",
                            help="Login URL for auto-login (required with --auth-user/--auth-pass)")
    auth_group.add_argument("--auth-basic",
                            help='HTTP Basic auth as "user:password"')

    parser.add_argument(
        "--extra-endpoints",
        nargs="+",
        metavar="URL",
        help="Extra URLs to seed into initial state (bypasses recon for known paths)",
    )

    args = parser.parse_args()

    # Build auth_credentials dict
    auth_credentials: dict | None = None
    if args.auth_cookie:
        auth_credentials = {"type": "cookie", "value": args.auth_cookie}
    elif args.auth_bearer:
        auth_credentials = {"type": "bearer", "value": args.auth_bearer}
    elif args.auth_basic:
        auth_credentials = {"type": "basic", "value": args.auth_basic}
    elif args.auth_header:
        auth_credentials = {
            "type": "header",
            "value": args.auth_header,
            "header_name": args.auth_header_name,
        }
    elif args.auth_user and args.auth_pass:
        if not args.auth_login_url:
            parser.error("--auth-login-url is required when using --auth-user/--auth-pass")
        auth_credentials = {
            "type": "auto_login",
            "login_url": args.auth_login_url,
            "username": args.auth_user,
            "password": args.auth_pass,
        }

    if auth_credentials:
        print(f"\n  Auth mode:    {auth_credentials['type']}")

    # Apply preset before launching scan (writes env vars read by vuln_hunt_node)
    if args.preset:
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../packages/pentra-agent"))
        try:
            from pentra_agent.scan_presets import get_preset
            preset = get_preset(args.preset)
            preset.apply_to_env()
            print(f"  Preset:       {args.preset} — {preset.description[:60]}...")
        except ImportError:
            print(f"  [WARNING] Could not load scan presets — using defaults")

    asyncio.run(run_live_scan(args.domain, args.mode, auth_credentials=auth_credentials, extra_endpoints=args.extra_endpoints))


if __name__ == "__main__":
    main()
