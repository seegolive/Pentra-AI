"""Burp Suite auto-approval — ensure target is in scope and intercept is OFF.

Eliminates the need for manual Burp UI action before each scan.

Findings from MCP investigation (2026-06-19):
  - set_proxy_intercept_state(False)  → changes runtime state ✅, NOT persisted to .burp file
  - set_project_options with proxy.intercept_client_requests.do_intercept=false → ignored by Burp MCP ❌
  - "null Timed Out" in Logger++ → caused by target WAF/DDoS blocking scanner traffic, NOT intercept

What this module DOES:
  1. Add domain to target.scope.include in project options (via set_project_scope)
  2. Disable proxy intercept immediately via set_proxy_intercept_state(False)
  3. Set target scope in Burp project options

What Burp MCP CANNOT do (Burp limitation):
  - Persist do_intercept=false to project file (field is ignored by set_project_options)
  - Workaround: set_proxy_intercept_state(False) is called every scan start, which is sufficient

Called once per engagement from _burp_startup_sequence() in recon_node.py.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pentra_tools.burp.client import BurpMCPClient

log = logging.getLogger(__name__)


async def ensure_target_approved(client: "BurpMCPClient", domain: str) -> bool:
    """Approve a target domain in Burp and disable proxy intercept.

    Steps:
      1. Add domain to Burp project scope (target.scope.include)
      2. Disable proxy intercept via set_proxy_intercept_state(False)

    Note: Burp MCP does not support persisting do_intercept=false via set_project_options.
    The set_proxy_intercept_state(False) call handles the runtime state which is
    sufficient — it's called at the start of every scan in _burp_startup_sequence().

    Args:
        client: Connected BurpMCPClient instance.
        domain: Target domain, e.g. "www.pupuk-indonesia.com"

    Returns:
        True if all steps succeeded, False if any step failed (non-fatal).
    """
    ok = True

    # ── Step 1: Add to Burp project scope ────────────────────────────────────
    # This persists in the .burp project file so the domain is pre-approved
    # for all Burp tools (scanner, repeater, active scan, etc.)
    try:
        # Read current scope to preserve existing in-scope entries
        current = await client.get_project_options()
        scope = current.get("target", {}).get("scope", {})
        existing_include = scope.get("include", [])

        existing_hosts = {entry.get("host", "") for entry in existing_include}
        if domain not in existing_hosts:
            # Use set_project_scope which properly formats the scope object
            all_hosts = list(existing_hosts | {domain})
            await client.set_project_scope(
                in_scope_urls=all_hosts,
                out_of_scope_urls=[],
            )
            log.info("[auto_approve] Added %s to Burp target scope", domain)
        else:
            log.debug("[auto_approve] %s already in Burp scope", domain)

    except Exception as exc:
        log.warning("[auto_approve] scope update failed (non-fatal): %s", exc)
        ok = False

    # ── Step 2: Disable proxy intercept (runtime — immediate effect) ──────────
    # Prevents intercepted requests from hanging indefinitely in the proxy queue.
    # Note: this does NOT persist across Burp restarts (MCP limitation).
    # It's called every scan start so this is sufficient.
    try:
        await client.set_proxy_intercept_state(False)
        log.info("[auto_approve] Proxy intercept disabled for %s", domain)
    except Exception as exc:
        log.warning("[auto_approve] intercept disable failed (non-fatal): %s", exc)
        ok = False

    return ok
