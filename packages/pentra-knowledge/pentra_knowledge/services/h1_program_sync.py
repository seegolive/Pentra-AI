"""Task 5.4 — HackerOne program scope sync.

Fetches in-scope and out-of-scope asset lists from a public HackerOne
bug bounty program and converts them to Pentra AI engagement scope format.

Only public programs are supported (no auth required).
Respects HackerOne's rate limit: max 3 req/min per the public GraphQL API.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

H1_GRAPHQL_URL = "https://hackerone.com/graphql"

_PROGRAM_SCOPE_QUERY = """
query ProgramScope($handle: String!) {
  team(handle: $handle) {
    name
    url
    structured_scopes(first: 200) {
      nodes {
        asset_identifier
        asset_type
        eligible_for_bounty
        eligible_for_submission
        instruction
      }
    }
  }
}
"""

# Map H1 asset types → whether to include in IP/domain scope
_DOMAIN_TYPES = {"URL", "DOMAIN", "WILDCARD"}
_IP_TYPES = {"IP_ADDRESS", "CIDR"}
_SKIP_TYPES = {"OTHER", "HARDWARE", "SOURCE_CODE", "DOWNLOADABLE_EXECUTABLES", "GOOGLE_PLAY_APP", "OTHER_APK", "APPLE_STORE_APP"}


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class H1ScopeItem(BaseModel):
    asset_identifier: str
    asset_type: str
    eligible_for_bounty: bool = True
    instruction: str | None = None


class H1ProgramScope(BaseModel):
    program_name: str = ""
    program_url: str = ""
    in_scope: list[H1ScopeItem] = Field(default_factory=list)
    out_of_scope: list[H1ScopeItem] = Field(default_factory=list)


class EngagementScope(BaseModel):
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)  # non-domain assets as notes


# ── Service ───────────────────────────────────────────────────────────────────

class H1ProgramSync:
    """Import scope from a public HackerOne bug bounty program."""

    _HEADERS = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Security Research - Pentra AI)",
        "Accept": "application/json",
    }

    async def fetch_program_scope(self, program_handle: str) -> H1ProgramScope:
        """
        Fetch structured scope from a public H1 program.

        Args:
            program_handle: The program handle (slug), e.g. "shopify" or "hackerone".

        Returns:
            H1ProgramScope with in_scope and out_of_scope items.

        Raises:
            ValueError: If the program is not found or has no structured scope.
            httpx.HTTPError: On network failure.
        """
        handle = program_handle.strip().lower()

        payload: dict[str, Any] = {
            "query": _PROGRAM_SCOPE_QUERY,
            "variables": {"handle": handle},
        }

        async with httpx.AsyncClient(timeout=15, headers=self._HEADERS) as client:
            response = await client.post(H1_GRAPHQL_URL, json=payload)

        if response.status_code != 200:
            raise ValueError(
                f"H1 GraphQL returned HTTP {response.status_code} for handle '{handle}'"
            )

        data = response.json()

        if "errors" in data:
            msgs = [e.get("message", "") for e in data["errors"]]
            raise ValueError(f"H1 GraphQL errors: {'; '.join(msgs)}")

        team = (data.get("data") or {}).get("team")
        if not team:
            raise ValueError(
                f"Program '{handle}' not found on HackerOne or is not public."
            )

        # New H1 schema: structured_scopes with eligible_for_submission flag
        # Old schema: structured_scope_versions with in_scope/out_of_scope lists
        all_nodes = team.get("structured_scopes", {}).get("nodes") or []

        if all_nodes:
            in_scope_raw = [
                {k: v for k, v in n.items() if k != "eligible_for_submission"}
                for n in all_nodes if n.get("eligible_for_submission", True)
            ]
            out_of_scope_raw = [
                {k: v for k, v in n.items() if k != "eligible_for_submission"}
                for n in all_nodes if not n.get("eligible_for_submission", True)
            ]
        else:
            # Fallback to legacy structured_scope_versions
            versions = team.get("structured_scope_versions", {}).get("nodes") or []
            if not versions:
                raise ValueError(
                    f"Program '{handle}' has no structured scope data published."
                )
            latest = versions[-1]
            in_scope_raw = latest.get("in_scope") or []
            out_of_scope_raw = latest.get("out_of_scope") or []

        in_scope = [H1ScopeItem(**item) for item in in_scope_raw]
        out_of_scope = [H1ScopeItem(**item) for item in out_of_scope_raw]

        return H1ProgramScope(
            program_name=team.get("name", handle),
            program_url=team.get("url", f"https://hackerone.com/{handle}"),
            in_scope=in_scope,
            out_of_scope=out_of_scope,
        )

    def convert_to_engagement_scope(self, h1_scope: H1ProgramScope) -> EngagementScope:
        """
        Convert an H1ProgramScope into a Pentra AI EngagementScope.

        Domain / wildcard / IP targets go into in_scope / out_of_scope lists.
        Other asset types (mobile apps, hardware, etc.) are added as notes
        so the operator can review them manually.
        """
        in_scope: list[str] = []
        out_of_scope: list[str] = []
        notes: list[str] = []

        for item in h1_scope.in_scope:
            identifier = item.asset_identifier.strip()
            if not identifier:
                continue
            if item.asset_type in _DOMAIN_TYPES or item.asset_type in _IP_TYPES:
                in_scope.append(identifier)
            elif item.asset_type not in _SKIP_TYPES:
                notes.append(f"[IN-SCOPE] {item.asset_type}: {identifier}")

        for item in h1_scope.out_of_scope:
            identifier = item.asset_identifier.strip()
            if not identifier:
                continue
            if item.asset_type in _DOMAIN_TYPES or item.asset_type in _IP_TYPES:
                out_of_scope.append(identifier)
            elif item.asset_type not in _SKIP_TYPES:
                notes.append(f"[OUT-OF-SCOPE] {item.asset_type}: {identifier}")

        return EngagementScope(
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            notes=notes,
        )
