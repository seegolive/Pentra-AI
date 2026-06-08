"""Import BugHunter hunt-* skill patterns into the Pentra AI Knowledge Base.

Fetches hunt-*.md skills from Claude-BugHunter on GitHub and injects each one
as a curated KB record via POST /api/v1/knowledge/inject.

Usage:
    # Pass token as CLI arg (non-interactive — for scripting)
    uv run python scripts/import_bughunter_patterns.py --token <TOKEN>

    # Limit to specific skills
    uv run python scripts/import_bughunter_patterns.py --token <TOKEN> --skills sqli xss ssrf

    # Custom API URL
    uv run python scripts/import_bughunter_patterns.py --token <TOKEN> --api-url http://localhost:8001
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import NamedTuple

import httpx

# ── Skill registry ────────────────────────────────────────────────────────────

class Skill(NamedTuple):
    file: str           # filename on GitHub (without .md)
    vuln_class: str     # maps to pentra_shared VulnClass values
    severity: str = "high"

SKILLS: list[Skill] = [
    Skill("hunt-sqli",              "SQL_INJECTION",            "critical"),
    Skill("hunt-xss",               "XSS",                      "high"),
    Skill("hunt-ssrf",              "SSRF",                     "critical"),
    Skill("hunt-idor",              "IDOR",                     "high"),
    Skill("hunt-xxe",               "XXE",                      "high"),
    Skill("hunt-jwt",               "JWT_VULNERABILITY",        "high"),
    Skill("hunt-oauth",             "OAUTH_MISCONFIGURATION",   "high"),
    Skill("hunt-graphql",           "GRAPHQL",                  "medium"),
    Skill("hunt-ssti",              "SSTI",                     "critical"),
    Skill("hunt-rce",               "RCE",                      "critical"),
    Skill("hunt-file-upload",       "PATH_TRAVERSAL",           "high"),
    Skill("hunt-business-logic",    "BUSINESS_LOGIC",           "high"),
    Skill("hunt-race-conditions",   "RACE_CONDITION",           "high"),
    Skill("hunt-api-misconfig",     "MISCONFIGURATION",         "medium"),
    Skill("hunt-auth-bypass",       "BROKEN_AUTH",              "critical"),
    Skill("hunt-cache-poison",      "CACHE_POISONING",          "high"),
    Skill("hunt-http-smuggling",    "HTTP_SMUGGLING",           "high"),
    Skill("hunt-ato",               "ACCOUNT_TAKEOVER",         "critical"),
    Skill("hunt-mfa-bypass",        "AUTH_BYPASS",              "high"),
    Skill("hunt-pii-leak",          "INFORMATION_DISCLOSURE",   "medium"),
]

SKILL_INDEX: dict[str, Skill] = {s.file.removeprefix("hunt-"): s for s in SKILLS}

GITHUB_RAW_BASE = (
    "https://raw.githubusercontent.com/elementalsouls/Claude-BugHunter/main/skills"
)
# Each skill is a directory containing SKILL.md (not a flat .md file)
_SKILL_FILENAME = "SKILL.md"

# Max raw_text length accepted by the API schema
_MAX_TEXT_LEN = 18000


# ── Core fetch + inject ───────────────────────────────────────────────────────

async def fetch_skill_content(client: httpx.AsyncClient, skill: Skill) -> str | None:
    """Fetch raw Markdown content of a skill SKILL.md from GitHub."""
    url = f"{GITHUB_RAW_BASE}/{skill.file}/{_SKILL_FILENAME}"
    try:
        resp = await client.get(url, timeout=30)
        if resp.status_code == 200:
            return resp.text
        print(f"  ⚠  HTTP {resp.status_code} for {skill.file}", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"  ⚠  fetch error for {skill.file}: {exc}", file=sys.stderr)
        return None


def _extract_key_insight(content: str) -> str:
    """Pull first non-empty paragraph from Markdown as the key_insight."""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped[:900]
    return ""


async def inject_skill(
    client: httpx.AsyncClient,
    api_url: str,
    token: str,
    skill: Skill,
    content: str,
) -> bool:
    """POST the skill content to /api/v1/knowledge/inject."""
    payload = {
        "title": f"BugHunter Pattern: {skill.file}",
        "vuln_class": skill.vuln_class,
        "severity": skill.severity,
        "source": "bughunter",
        "raw_text": content[:_MAX_TEXT_LEN],
        "key_insight": _extract_key_insight(content),
        "technique": f"BugHunter {skill.file} detection & exploitation pattern",
        "tech_stack": [],
        "tags": ["bughunter", "curated", "detection-pattern"],
        "url": f"https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/{skill.file}/{_SKILL_FILENAME}",
    }

    try:
        resp = await client.post(
            f"{api_url}/api/v1/knowledge/inject",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            msg = data.get("message", "")
            icon = "✅" if "created" in msg else "♻️ "
            print(f"  {icon}  {skill.file} ({skill.vuln_class}) — {msg}")
            return True
        else:
            print(
                f"  ❌  {skill.file}: inject failed HTTP {resp.status_code} — {resp.text[:200]}",
                file=sys.stderr,
            )
            return False
    except Exception as exc:
        print(f"  ❌  {skill.file}: {exc}", file=sys.stderr)
        return False


async def process_skill(
    client: httpx.AsyncClient,
    api_url: str,
    token: str,
    skill: Skill,
) -> bool:
    content = await fetch_skill_content(client, skill)
    if content is None:
        return False
    return await inject_skill(client, api_url, token, skill, content)


# ── Qdrant verification ───────────────────────────────────────────────────────

async def get_kb_stats(api_url: str, token: str) -> dict | None:
    """Fetch KB stats from admin endpoint."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{api_url}/api/v1/admin/stats",
                headers={"Authorization": f"Bearer {token}"},
            )
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        print(f"  ⚠  stats fetch failed: {exc}", file=sys.stderr)
    return None


# ── Main ──────────────────────────────────────────────────────────────────────

async def main(api_url: str, token: str, skill_names: list[str] | None) -> int:
    # Resolve skill list
    if skill_names:
        skills_to_import: list[Skill] = []
        for name in skill_names:
            key = name.removeprefix("hunt-")
            if key not in SKILL_INDEX:
                print(f"Unknown skill '{name}'. Valid: {', '.join(SKILL_INDEX)}", file=sys.stderr)
                return 1
            skills_to_import.append(SKILL_INDEX[key])
    else:
        skills_to_import = list(SKILLS)

    print(f"\n📚 Pentra AI — BugHunter Pattern Importer")
    print(f"   API: {api_url}")
    print(f"   Skills to import: {len(skills_to_import)}\n")

    # Snapshot KB count before import
    before = await get_kb_stats(api_url, token)
    if before:
        print(f"   KB records BEFORE: {before.get('total_records', '?')}\n")

    ok = fail = 0
    async with httpx.AsyncClient() as client:
        for skill in skills_to_import:
            success = await process_skill(client, api_url, token, skill)
            if success:
                ok += 1
            else:
                fail += 1

    print(f"\n{'─'*50}")
    print(f"   Imported: {ok}  |  Failed: {fail}  |  Total: {len(skills_to_import)}")

    # Snapshot KB count after import
    after = await get_kb_stats(api_url, token)
    if after:
        delta = after.get("total_records", 0) - (before or {}).get("total_records", 0)
        print(f"   KB records AFTER:  {after.get('total_records', '?')}  (+{delta} new)")

    return 0 if fail == 0 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import BugHunter hunt-* skill patterns into Pentra AI KB"
    )
    parser.add_argument(
        "--token",
        required=True,
        help="Bearer token from POST /api/v1/auth/login",
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8001",
        help="Pentra AI API base URL (default: http://localhost:8001)",
    )
    parser.add_argument(
        "--skills",
        nargs="+",
        metavar="SKILL",
        help=(
            "Import only specific skills by short name (e.g. sqli xss ssrf). "
            "Omit to import all 20."
        ),
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    sys.exit(asyncio.run(main(args.api_url, args.token, args.skills)))
