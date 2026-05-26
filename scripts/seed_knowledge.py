#!/usr/bin/env python3
"""Seed the Pentra AI Knowledge Base from a HackerOne public disclosures CSV.

Downloads the reddelexc/hackerone-reports dataset (or reads a local file),
extracts structured intelligence via Ollama LLM, generates BGE-M3 embeddings,
and stores everything in PostgreSQL + Qdrant.

Usage:
    # Download from GitHub and process all records
    uv run python scripts/seed_knowledge.py

    # Use a local CSV file
    uv run python scripts/seed_knowledge.py --source h1_csv --path data/h1_reports.csv

    # Test with first 100 records, skip Qdrant embedding
    uv run python scripts/seed_knowledge.py --limit 100 --skip-embed

    # Dry-run — parse + LLM extract but do not write to DB
    uv run python scripts/seed_knowledge.py --limit 20 --dry-run

    # Skip LLM extraction (fast load, minimal metadata)
    uv run python scripts/seed_knowledge.py --skip-llm --batch-size 200
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx

# ── Monorepo path bootstrap ────────────────────────────────────────────────────
# Allows `python scripts/seed_knowledge.py` from the repo root without
# needing `uv run` or an explicit PYTHONPATH.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "pentra-knowledge"))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "pentra-shared"))

from pentra_knowledge.config import get_settings  # noqa: E402
from pentra_knowledge.db.base import Base, _get_session_factory  # noqa: E402
from pentra_knowledge.db.repository import KnowledgeRepository  # noqa: E402
from pentra_knowledge.services.embedding import build_embedding_text, embed  # noqa: E402
from pentra_knowledge.services.search import (  # noqa: E402
    ensure_collection_exists,
    upsert_to_qdrant,
)
from pentra_shared.types import Severity, VulnClass  # noqa: E402

try:
    from tqdm import tqdm as _tqdm

    def progress(iterable, **kwargs):  # type: ignore[no-untyped-def]
        return _tqdm(iterable, **kwargs)

except ImportError:  # tqdm not installed in minimal env

    def progress(iterable, total=None, desc="", **kwargs):  # type: ignore[no-untyped-def]
        print(f"  {desc} ({total or '?'} items)", flush=True)
        return iterable


# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("seed_knowledge")

# ── Dataset source ─────────────────────────────────────────────────────────────
H1_CSV_GITHUB_URL = (
    "https://raw.githubusercontent.com/reddelexc/hackerone-reports"
    "/master/data.csv"
)

# ── VulnClass mapping ──────────────────────────────────────────────────────────
_H1_TYPE_TO_VULN_CLASS: dict[str, VulnClass] = {
    # Access Control
    "idor": VulnClass.IDOR,
    "insecure direct object reference": VulnClass.IDOR,
    "broken object level authorization": VulnClass.BOLA,
    "bola": VulnClass.BOLA,
    "broken function level authorization": VulnClass.BFLA,
    "bfla": VulnClass.BFLA,
    "privilege escalation": VulnClass.PRIVILEGE_ESCALATION,
    # Injection
    "sql injection": VulnClass.SQLI,
    "sqli": VulnClass.SQLI,
    "blind sql injection": VulnClass.SQLI,
    "boolean-based sql injection": VulnClass.SQLI,
    "cross-site scripting (xss)": VulnClass.XSS_REFLECTED,
    "cross-site scripting": VulnClass.XSS_REFLECTED,
    "xss": VulnClass.XSS_REFLECTED,
    "stored xss": VulnClass.XSS_STORED,
    "persistent xss": VulnClass.XSS_STORED,
    "reflected xss": VulnClass.XSS_REFLECTED,
    "dom xss": VulnClass.XSS_DOM,
    "dom-based xss": VulnClass.XSS_DOM,
    "mutation xss": VulnClass.MXSS,
    "mxss": VulnClass.MXSS,
    "xml external entity injection": VulnClass.XXE,
    "xml external entity (xxe) injection": VulnClass.XXE,
    "xxe": VulnClass.XXE,
    "server side template injection": VulnClass.SSTI,
    "server-side template injection": VulnClass.SSTI,
    "ssti": VulnClass.SSTI,
    "command injection": VulnClass.CMDI,
    "os command injection": VulnClass.CMDI,
    "code injection": VulnClass.CMDI,
    "shell injection": VulnClass.CMDI,
    # Auth
    "authentication bypass": VulnClass.AUTH_BYPASS,
    "auth bypass": VulnClass.AUTH_BYPASS,
    "open redirect": VulnClass.AUTH_BYPASS,
    "oauth misconfiguration": VulnClass.OAUTH_MISCONFIG,
    "oauth": VulnClass.OAUTH_MISCONFIG,
    "jwt": VulnClass.JWT_ISSUES,
    "jwt issues": VulnClass.JWT_ISSUES,
    "insecure session management": VulnClass.SESSION,
    "session fixation": VulnClass.SESSION,
    "session hijacking": VulnClass.SESSION,
    # Server-side
    "server-side request forgery (ssrf)": VulnClass.SSRF,
    "server-side request forgery": VulnClass.SSRF,
    "ssrf": VulnClass.SSRF,
    "remote code execution": VulnClass.RCE,
    "rce": VulnClass.RCE,
    "code execution": VulnClass.RCE,
    "arbitrary code execution": VulnClass.RCE,
    "path traversal": VulnClass.PATH_TRAVERSAL,
    "directory traversal": VulnClass.PATH_TRAVERSAL,
    "local file inclusion": VulnClass.PATH_TRAVERSAL,
    "lfi": VulnClass.PATH_TRAVERSAL,
    "insecure deserialization": VulnClass.DESERIALIZATION,
    "deserialization": VulnClass.DESERIALIZATION,
    # Business Logic
    "mass assignment": VulnClass.MASS_ASSIGNMENT,
    "race condition": VulnClass.RACE_CONDITION,
    "business logic": VulnClass.WORKFLOW_BYPASS,
    "business logic errors": VulnClass.WORKFLOW_BYPASS,
    "workflow bypass": VulnClass.WORKFLOW_BYPASS,
    "parameter pollution": VulnClass.PARAM_POLLUTION,
    "http parameter pollution": VulnClass.PARAM_POLLUTION,
    # Info Disclosure
    "information disclosure": VulnClass.PII_EXPOSURE,
    "sensitive data exposure": VulnClass.PII_EXPOSURE,
    "pii exposure": VulnClass.PII_EXPOSURE,
    "api key exposure": VulnClass.API_KEY_LEAK,
    "api key leak": VulnClass.API_KEY_LEAK,
    "debug information": VulnClass.DEBUG_INFO,
    "source code disclosure": VulnClass.SOURCE_CODE,
    # Infrastructure
    "subdomain takeover": VulnClass.SUBDOMAIN_TAKEOVER,
    "cors misconfiguration": VulnClass.CORS,
    "cors": VulnClass.CORS,
    "cache poisoning": VulnClass.CACHE_POISONING,
    "web cache poisoning": VulnClass.CACHE_POISONING,
    "cloud misconfiguration": VulnClass.CLOUD_MISCONFIG,
    "s3 misconfiguration": VulnClass.CLOUD_MISCONFIG,
    # GraphQL
    "graphql introspection": VulnClass.INTROSPECTION,
    "graphql": VulnClass.INTROSPECTION,
    # Cryptography
    "weak cryptography": VulnClass.WEAK_ALGO,
    "timing attack": VulnClass.TIMING_ATTACK,
    "padding oracle": VulnClass.PADDING_ORACLE,
    # Availability / DoS
    "denial of service": VulnClass.DOS,
    "dos": VulnClass.DOS,
    "ddos": VulnClass.DOS,
    "resource exhaustion": VulnClass.DOS,
    "rate limiting": VulnClass.DOS,
    "application-level dos": VulnClass.DOS,
    "economic denial of service": VulnClass.DOS,
    "economic dos": VulnClass.DOS,
    "regular expression dos": VulnClass.DOS,
    "redos": VulnClass.DOS,
    # Redirect
    "open redirect": VulnClass.OPEN_REDIRECT,
    "url redirection": VulnClass.OPEN_REDIRECT,
    # Memory Safety
    "buffer overflow": VulnClass.BUFFER_OVERFLOW,
    "stack overflow": VulnClass.BUFFER_OVERFLOW,
    "heap overflow": VulnClass.BUFFER_OVERFLOW,
    "off-by-one": VulnClass.BUFFER_OVERFLOW,
    "use after free": VulnClass.USE_AFTER_FREE,
    "use-after-free": VulnClass.USE_AFTER_FREE,
    "double free": VulnClass.USE_AFTER_FREE,
    "double-free": VulnClass.USE_AFTER_FREE,
    "integer overflow": VulnClass.INTEGER_OVERFLOW,
    "integer underflow": VulnClass.INTEGER_OVERFLOW,
}

_H1_SEVERITY_TO_ENUM: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.INFO,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "n/a": Severity.INFO,
}


_TITLE_KEYWORD_MAP: list[tuple[str, VulnClass]] = [
    # ordered most-specific first so early matches win
    ("denial of service", VulnClass.DOS),
    (" dos ", VulnClass.DOS),
    ("resource exhaustion", VulnClass.DOS),
    ("rate limit", VulnClass.DOS),
    ("double-free", VulnClass.USE_AFTER_FREE),
    ("double free", VulnClass.USE_AFTER_FREE),
    ("use-after-free", VulnClass.USE_AFTER_FREE),
    ("use after free", VulnClass.USE_AFTER_FREE),
    ("buffer overflow", VulnClass.BUFFER_OVERFLOW),
    ("off-by-one", VulnClass.BUFFER_OVERFLOW),
    ("integer overflow", VulnClass.INTEGER_OVERFLOW),
    ("open redirect", VulnClass.OPEN_REDIRECT),
    ("sql injection", VulnClass.SQLI),
    ("sqli", VulnClass.SQLI),
    ("xss", VulnClass.XSS_REFLECTED),
    ("cross-site scripting", VulnClass.XSS_REFLECTED),
    ("ssrf", VulnClass.SSRF),
    ("remote code", VulnClass.RCE),
    ("path traversal", VulnClass.PATH_TRAVERSAL),
    ("directory traversal", VulnClass.PATH_TRAVERSAL),
    ("file inclusion", VulnClass.PATH_TRAVERSAL),
    ("command injection", VulnClass.CMDI),
    ("ssti", VulnClass.SSTI),
    ("template injection", VulnClass.SSTI),
    ("xxe", VulnClass.XXE),
    ("xml external", VulnClass.XXE),
    ("deserialization", VulnClass.DESERIALIZATION),
    ("race condition", VulnClass.RACE_CONDITION),
    ("idor", VulnClass.IDOR),
    ("insecure direct", VulnClass.IDOR),
    ("authentication bypass", VulnClass.AUTH_BYPASS),
    ("auth bypass", VulnClass.AUTH_BYPASS),
    ("subdomain takeover", VulnClass.SUBDOMAIN_TAKEOVER),
    ("cache poisoning", VulnClass.CACHE_POISONING),
    ("cors", VulnClass.CORS),
    ("information disclosure", VulnClass.PII_EXPOSURE),
    ("sensitive data", VulnClass.PII_EXPOSURE),
    ("graphql", VulnClass.INTROSPECTION),
    ("privilege escalation", VulnClass.PRIVILEGE_ESCALATION),
    ("mass assignment", VulnClass.MASS_ASSIGNMENT),
]


def _map_vuln_class(raw: str, title: str = "") -> VulnClass:
    key = raw.lower().strip()
    if key in _H1_TYPE_TO_VULN_CLASS:
        return _H1_TYPE_TO_VULN_CLASS[key]
    for pattern, vuln in _H1_TYPE_TO_VULN_CLASS.items():
        if pattern in key or key in pattern:
            return vuln
    # Fall back to title keyword scan when CSV type is unrecognised
    title_lower = title.lower()
    for keyword, vuln in _TITLE_KEYWORD_MAP:
        if keyword in title_lower:
            return vuln
    return VulnClass.WORKFLOW_BYPASS  # safe fallback — better than IDOR


def _map_severity(raw: str) -> Severity:
    return _H1_SEVERITY_TO_ENUM.get(raw.lower().strip(), Severity.INFO)


# ── LLM extraction prompt ──────────────────────────────────────────────────────
_SYSTEM_PROMPT = (
    "/no_think\n"
    "You are a security researcher extracting structured threat intelligence "
    "from HackerOne bug bounty disclosures. "
    "Return ONLY a valid JSON object — no explanation, no markdown fences, no thinking."
)

_USER_PROMPT_TMPL = """\
Analyze this HackerOne report and extract security intelligence.

Report metadata:
  Title: {title}
  Vulnerability type: {vuln_type}
  Severity: {severity}
  Program: {program}
  Bounty paid: ${bounty}

Extract the following JSON object:
{{
  "vuln_class":        "one of: idor, bola, bfla, sqli, xss_reflected, xss_stored, xss_dom, xxe, ssti, cmdi, ssrf, rce, path_traversal, deserialization, auth_bypass, mass_assignment, race_condition, dos, open_redirect, cors, subdomain_takeover, oauth_misconfig, session, pii_exposure, api_key_leak, debug_info, privilege_escalation, workflow_bypass, cloud_misconfig, cache_poisoning, buffer_overflow, use_after_free, integer_overflow, introspection, batch_abuse, weak_algo, timing_attack",
  "tech_stack":        ["technologies involved, e.g. Ruby on Rails, AWS S3"],
  "platform_type":     ["one or more of: web, api, mobile, cloud, network"],
  "endpoint_pattern":  "generalised URL e.g. /api/v1/users/{{id}}",
  "http_method":       ["HTTP methods: GET, POST, PUT, DELETE, PATCH"],
  "auth_required":     true,
  "attack_technique":  "1-2 sentences: HOW the bug was exploited",
  "attack_steps":      ["step 1", "step 2", "step 3"],
  "payload_pattern":   "concrete payload or request snippet, e.g. ?id=1 OR 1=1 or <script>alert(1)</script> or {\"alias1\": mutation, \"alias2\": mutation}",
  "indicators":        ["observable signal that this bug may exist"],
  "prerequisites":     ["condition that must be true for bug to exist"],
  "what_tools_missed": "why automated scanners (Burp/Nuclei) missed this",
  "impact":            "impact if exploited",
  "impact_category":   ["one or more of: account_takeover, data_exfil, rce, dos, information_disclosure, privilege_escalation"],
  "key_insight":       "the aha moment — 1-3 sentences, what made this non-obvious",
  "unique_factor":     "what made this hard to find"
}}"""

# Fields that must not be empty after LLM extraction fallback
_REQUIRED_LLM_FIELDS = {
    "attack_technique",
    "key_insight",
    "indicators",
}


def _repair_truncated_json(raw: str) -> dict:
    """Attempt to recover a valid JSON object from a truncated LLM response.

    Strategy: walk backwards from the end, trying to close open structures
    so json.loads succeeds.  Returns {} if no valid object can be salvaged.
    """
    # First try as-is
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try truncating at the last \n before a known field delimiter pattern.
    # E.g. if last line is half-written, drop it and close the object.
    lines = raw.rstrip().split("\n")
    for i in range(len(lines), 0, -1):
        candidate = "\n".join(lines[:i])
        # Strip trailing comma / partial field
        candidate = candidate.rstrip().rstrip(",")
        # Close any open array/object
        for close in ["}}", "}", "]}", "\"}"]:
            try:
                return json.loads(candidate + close)
            except json.JSONDecodeError:
                continue
    return {}


async def _llm_extract(
    row: dict[str, Any],
    client: httpx.AsyncClient,
    model: str,
    semaphore: asyncio.Semaphore,
    title: str,
) -> dict[str, Any]:
    """Call Ollama to extract structured fields from one CSV row.

    Protected by ``semaphore`` to limit concurrent LLM calls.
    Retries once on empty / truncated response before falling back to {}.
    Returns an empty dict on total failure — callers apply defaults.
    """
    async with semaphore:
        prompt = _USER_PROMPT_TMPL.format(
            title=title,
            vuln_type=row.get("vuln_type") or row.get("type") or row.get("weakness") or "Unknown",
            severity=row.get("severity", row.get("severity_rating", "unknown")),
            program=row.get("program", row.get("team", "")),
            bounty=row.get("bounty", row.get("bounty_amount", "0")) or "0",
        )

        for attempt in range(2):  # 1 retry on empty / parse failure
            try:
                response = await client.post(
                    "/api/chat",
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": _SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        "stream": False,
                        "options": {"temperature": 0.1, "num_predict": 3000},
                    },
                )
                response.raise_for_status()
                raw_content: str = response.json()["message"]["content"].strip()

                # Strip qwen3 <think>...</think> blocks before parsing
                import re as _re
                raw_content = _re.sub(r"<think>.*?</think>", "", raw_content, flags=_re.DOTALL).strip()

                # Strip optional markdown code fences
                if raw_content.startswith("```"):
                    parts = raw_content.split("```")
                    raw_content = parts[1].lstrip("json").strip() if len(parts) >= 2 else ""

                if not raw_content:
                    if attempt == 0:
                        log.debug("Empty LLM response for '%s', retrying", title[:60])
                        continue
                    break

                result = _repair_truncated_json(raw_content)
                if result:
                    return result
                if attempt == 0:
                    log.debug("JSON parse failed for '%s', retrying", title[:60])
                    continue

            except Exception as exc:
                if attempt == 0:
                    log.debug("LLM call failed for '%s': %s — retrying", title[:60], exc)
                    continue
                log.warning("LLM extraction failed for '%s': %s", title[:60], exc)
                return {}

        log.warning("LLM extraction failed for '%s' after retries", title[:60])
        return {}


# ── Date parsing ───────────────────────────────────────────────────────────────
_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S+00:00",
    "%Y-%m-%d",
    "%Y/%m/%d",
)


def _utcnow() -> datetime:
    """Return a timezone-naive UTC datetime.

    asyncpg 0.31 raises 'can't subtract offset-naive and offset-aware datetimes'
    when receiving timezone-aware datetimes for TIMESTAMPTZ columns.
    Passing naive UTC datetimes is the safe workaround.
    """
    return datetime.utcnow()  # noqa: DTZ003


def _parse_date(raw: str) -> datetime:
    for fmt in _DATE_FORMATS:
        try:
            # Return naive UTC — asyncpg 0.31 requires naive datetimes for TIMESTAMPTZ
            return datetime.strptime(raw, fmt).replace(tzinfo=None)
        except ValueError:
            continue
    return _utcnow()


# ── Record builder ─────────────────────────────────────────────────────────────
def _coerce_list(value: Any, default: list) -> list:
    """Return value if it is already a list, else return default."""
    return value if isinstance(value, list) else default


def _extract_source_id(row: dict[str, Any]) -> str:
    """Derive a stable source_id from the report link or id column.

    Handles both formats:
    - Explicit ``id`` column: "1234567"
    - ``link`` column: "hackerone.com/reports/1234567" or full URL
    """
    explicit = str(row.get("id", "")).strip()
    if explicit:
        return explicit
    link = str(row.get("link", row.get("url", ""))).strip()
    if link:
        # Extract the numeric report ID from the trailing path segment
        return link.rstrip("/").rsplit("/", 1)[-1]
    # Last resort: hash the title so duplicates are still detected
    import hashlib
    return hashlib.md5(str(row.get("title", "")).encode()).hexdigest()[:16]  # noqa: S324


def _build_source_url(row: dict[str, Any]) -> str | None:
    """Build a full HTTPS URL from ``link`` or ``url`` column."""
    raw = str(row.get("url", row.get("link", ""))).strip()
    if not raw:
        return None
    if raw.startswith("http"):
        return raw
    return "https://" + raw


def _build_record_dict(
    row: dict[str, Any],
    llm: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Merge a CSV row + LLM extraction into a flat dict for KnowledgeRepository.

    Any field absent from llm falls back to a sensible default derived from
    the CSV columns so the record is always fully populated.

    Supports both the reddelexc CSV column layout (program, title, link,
    upvotes, bounty, vuln_type) and extended layouts that include id,
    severity, disclosed_at, etc.
    """
    source_id = _extract_source_id(row)
    title = str(row.get("title", "")).strip()[:500]
    program = str(row.get("program", row.get("team", "unknown"))).strip()[:200]
    # severity is absent in the base reddelexc CSV — default to INFO
    raw_severity = str(row.get("severity", row.get("severity_rating", "info"))).strip()
    # vuln_type is the column name in the base CSV; fallback to type/weakness
    raw_type = str(
        row.get("vuln_type") or row.get("type") or row.get("weakness") or ""
    ).strip()

    bounty_raw = str(row.get("bounty", row.get("bounty_amount", "")) or "").replace(",", "")
    try:
        bounty_usd: int | None = int(float(bounty_raw)) if bounty_raw else None
    except ValueError:
        bounty_usd = None

    disclosed_raw = str(row.get("disclosed_at", row.get("created_at", ""))).strip()
    ingested_at = _parse_date(disclosed_raw) if disclosed_raw else now

    vuln_class = _map_vuln_class(raw_type, title=title)
    # Let LLM correct the classification (higher fidelity than CSV type string)
    if llm.get("vuln_class"):
        try:
            vuln_class = VulnClass(str(llm["vuln_class"]).lower().strip())
        except ValueError:
            pass  # keep CSV-derived / title-inferred class
    severity = _map_severity(raw_severity)

    def _get(key: str, default: Any = "") -> Any:
        return llm.get(key, default)

    # Defaults used when LLM returns nothing
    fallback_technique = f"{raw_type or 'Vulnerability'} discovered in {program}."
    fallback_insight = (
        f"{raw_type or 'Security issue'} found in {program} "
        f"({'$' + str(bounty_usd) if bounty_usd else 'no bounty reported'})."
    )

    attack_technique = str(_get("attack_technique") or fallback_technique)
    key_insight = str(_get("key_insight") or fallback_insight)
    indicators = _coerce_list(_get("indicators"), [f"{vuln_class.value} pattern"])
    payload_pattern = str(_get("payload_pattern") or "") or None

    full_text = "\n".join(filter(None, [
        title,
        raw_type or vuln_class.value,
        attack_technique,
        key_insight,
        str(_get("unique_factor") or ""),
        str(_get("impact") or ""),
        str(_get("endpoint_pattern") or ""),
        " ".join(_coerce_list(_get("attack_steps"), [])),
        " ".join(indicators),
        " ".join(_coerce_list(_get("tech_stack"), [])),
        " ".join(_coerce_list(_get("prerequisites"), [])),
        payload_pattern or "",
    ])).strip()

    return {
        "id": uuid4(),
        "source": "hackerone",
        "source_id": source_id,
        "source_url": _build_source_url(row),
        "ingested_at": ingested_at,
        "updated_at": now,
        "title": title,
        "vuln_class": vuln_class.value,
        "vuln_subclass": str(_get("vuln_subclass") or raw_type)[:200],
        "severity": severity.value,
        "cvss_score": None,
        "cvss_vector": None,
        "cve_id": None,
        "program": program,
        "tech_stack": _coerce_list(_get("tech_stack"), []),
        "platform_type": _coerce_list(_get("platform_type"), ["web"]),
        "endpoint_pattern": str(_get("endpoint_pattern") or "")[:500],
        "http_method": _coerce_list(_get("http_method"), ["GET"]),
        "auth_required": bool(_get("auth_required", True)),
        "attack_technique": attack_technique,
        "attack_steps": _coerce_list(_get("attack_steps"), []),
        "payload_pattern": payload_pattern,
        "indicators": indicators,
        "prerequisites": _coerce_list(_get("prerequisites"), []),
        "what_tools_missed": str(_get("what_tools_missed") or "") or None,
        "chained_with": [],
        "impact": str(_get("impact") or ""),
        "impact_category": _coerce_list(_get("impact_category"), []),
        "bounty_usd": bounty_usd,
        "key_insight": key_insight,
        "unique_factor": str(_get("unique_factor") or ""),
        "pentra_tags": [vuln_class.value, program.lower().replace(" ", "_")],
        "embedding_model": "bge-m3",
        "embedding_version": 1,
        "is_embedded": False,
        "full_text": full_text,
    }


# ── CSV source loading ─────────────────────────────────────────────────────────
async def _load_csv(path: str | None, *, timeout: float = 120.0) -> list[dict[str, Any]]:
    """Return all rows from a local CSV file or download from GitHub."""
    if path:
        log.info("Reading CSV from %s", path)
        with open(path, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
    else:
        log.info("Downloading H1 dataset from GitHub …")
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(H1_CSV_GITHUB_URL)
            response.raise_for_status()
            reader = csv.DictReader(io.StringIO(response.text))
            rows = list(reader)

    log.info("Loaded %d rows from CSV", len(rows))
    return rows


# ── Embedding pipeline ─────────────────────────────────────────────────────────
async def _embed_to_qdrant(
    record_id: UUID,
    full_text: str,
    payload: dict[str, Any],
    semaphore: asyncio.Semaphore,
) -> tuple[UUID, bool]:
    """Embed one record and upsert to Qdrant.

    Does NOT touch PostgreSQL — that is done separately so we never
    share an AsyncSession across concurrent coroutines.
    Returns (record_id, success).
    """
    async with semaphore:
        try:
            result = await embed(full_text)
            await upsert_to_qdrant(
                record_id=record_id,
                dense=result.dense,
                sparse=result.sparse,
                payload=payload,
            )
            return record_id, True
        except Exception as exc:
            log.warning("Embedding failed for %s: %s", record_id, exc)
            return record_id, False


# ── Main batch processing pipeline ────────────────────────────────────────────
async def run_seed(
    path: str | None,
    *,
    limit: int | None,
    batch_size: int,
    dry_run: bool,
    skip_llm: bool,
    skip_embed: bool,
    llm_concurrency: int,
    embed_concurrency: int,
) -> None:
    settings = get_settings()

    # Load CSV
    rows = await _load_csv(path)
    if limit:
        rows = rows[:limit]

    total = len(rows)
    log.info(
        "Processing %d records | batch=%d | skip_llm=%s | skip_embed=%s | dry_run=%s",
        total, batch_size, skip_llm, skip_embed, dry_run,
    )

    # Ensure Qdrant collection exists (idempotent)
    if not dry_run and not skip_embed:
        try:
            await ensure_collection_exists()
            log.info("Qdrant collection '%s' ready", settings.qdrant_collection_knowledge)
        except Exception as exc:
            log.warning("Qdrant not reachable — embedding will be skipped: %s", exc)
            skip_embed = True

    # Reusable HTTP client for Ollama
    ollama_client = httpx.AsyncClient(
        base_url=settings.ollama_url,
        timeout=90.0,
    )
    llm_sem = asyncio.Semaphore(llm_concurrency)
    embed_sem = asyncio.Semaphore(embed_concurrency)

    # Statistics
    stats = {
        "inserted": 0,
        "skipped_dup": 0,
        "embedded": 0,
        "llm_failed": 0,
        "errors": 0,
    }
    errors: list[tuple[str, str]] = []  # (source_id, error message)

    # DB session factory (used per batch to avoid holding a long-lived connection)
    session_factory = _get_session_factory()

    batches = [rows[i : i + batch_size] for i in range(0, total, batch_size)]
    now = _utcnow()

    for batch_idx, batch in enumerate(
        progress(batches, total=len(batches), desc="Batches", unit="batch"), start=1
    ):
        log.info("Batch %d/%d — %d records", batch_idx, len(batches), len(batch))

        # ── Step 1: LLM extraction (parallel within batch) ────────────────
        if skip_llm:
            llm_results = [{} for _ in batch]
        else:
            llm_tasks = [
                _llm_extract(
                    row=row,
                    client=ollama_client,
                    model=settings.ollama_model_fast,
                    semaphore=llm_sem,
                    title=str(row.get("title", ""))[:80],
                )
                for row in batch
            ]
            llm_results = await asyncio.gather(*llm_tasks)
            failed_llm = sum(1 for r in llm_results if not r)
            stats["llm_failed"] += failed_llm
            if failed_llm:
                log.debug("  %d/%d records used default values (LLM failed)", failed_llm, len(batch))

        # ── Step 2: Build record dicts ────────────────────────────────────
        record_dicts = [
            _build_record_dict(row, llm, now)
            for row, llm in zip(batch, llm_results)
        ]

        if dry_run:
            for rd in record_dicts:
                log.debug(
                    "  [dry-run] %s | %s | %s",
                    rd["source_id"], rd["vuln_class"], rd["title"][:60],
                )
            stats["inserted"] += len(record_dicts)
            continue

        # ── Step 3: PostgreSQL insertion ──────────────────────────────────
        inserted_this_batch: list[dict[str, Any]] = []

        async with session_factory() as db:
            repo = KnowledgeRepository(db)

            for rd in record_dicts:
                source_id: str = rd["source_id"]
                if not source_id:
                    log.warning("Row missing 'id' field — skipping")
                    stats["errors"] += 1
                    continue

                try:
                    if await repo.exists_by_source_id(source_id):
                        stats["skipped_dup"] += 1
                        continue

                    await repo.create(rd)
                    inserted_this_batch.append(rd)
                    stats["inserted"] += 1

                except Exception as exc:
                    msg = f"{type(exc).__name__}: {exc}"
                    log.error("  DB insert failed for '%s': %s", source_id, msg)
                    errors.append((source_id, msg))
                    stats["errors"] += 1

            # Commit the whole batch at once
            try:
                await db.commit()
            except Exception as exc:
                log.error("Batch commit failed: %s", exc)
                await db.rollback()
                stats["errors"] += len(inserted_this_batch)
                stats["inserted"] -= len(inserted_this_batch)
                inserted_this_batch.clear()

        # ── Step 4: Embedding + Qdrant (parallel within batch) ────────────
        # NOTE: Qdrant upserts run concurrently (limited by embed_sem).
        # PostgreSQL mark_embedded runs sequentially afterwards in a fresh
        # session to avoid sharing an AsyncSession across coroutines.
        if not skip_embed and inserted_this_batch:
            embed_tasks = [
                _embed_to_qdrant(
                    record_id=rd["id"],
                    full_text=rd["full_text"] or "",
                    payload={
                        "vuln_class": rd["vuln_class"],
                        "severity": rd["severity"],
                        "tech_stack": rd["tech_stack"],
                        "source": rd["source"],
                        "program": rd["program"],
                        "title": rd["title"],
                        "key_insight": rd["key_insight"],
                        "attack_technique": rd["attack_technique"],
                        "endpoint_pattern": rd["endpoint_pattern"],
                        "source_url": rd["source_url"],
                        "bounty_usd": rd["bounty_usd"],
                        "impact_category": rd["impact_category"],
                    },
                    semaphore=embed_sem,
                )
                for rd in inserted_this_batch
            ]
            embed_results: list[tuple[UUID, bool]] = await asyncio.gather(*embed_tasks)
            embedded_ids = [rid for rid, ok in embed_results if ok]
            stats["embedded"] += len(embedded_ids)

            # Mark successfully embedded records in PostgreSQL (sequential)
            if embedded_ids:
                async with session_factory() as db:
                    repo = KnowledgeRepository(db)
                    for record_id in embedded_ids:
                        await repo.mark_embedded(
                            record_id,
                            model=settings.ollama_model_embedding,
                            version=1,
                        )
                    try:
                        await db.commit()
                    except Exception as exc:
                        log.error("Embed-flag commit failed: %s", exc)
                        await db.rollback()

        # Rate-limit between batches to be gentle on Ollama
        if not skip_llm and batch_idx < len(batches):
            await asyncio.sleep(0.5)

    await ollama_client.aclose()

    # ── Final report ──────────────────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("SEED COMPLETE")
    print("─" * 60)
    print(f"  Total CSV rows    : {total}")
    print(f"  Inserted (PG)     : {stats['inserted']}")
    print(f"  Skipped (dup)     : {stats['skipped_dup']}")
    print(f"  Embedded (Qdrant) : {stats['embedded']}")
    print(f"  LLM fallbacks     : {stats['llm_failed']}")
    print(f"  Errors            : {stats['errors']}")

    if errors:
        print("\nFailed records (source_id → error):")
        for sid, err in errors[:20]:  # cap to 20 lines
            print(f"  {sid:>12}  {err[:80]}")
        if len(errors) > 20:
            print(f"  … and {len(errors) - 20} more")


# ── CLI ────────────────────────────────────────────────────────────────────────
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed Pentra AI Knowledge Base from HackerOne CSV",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source",
        default="h1_csv",
        choices=["h1_csv"],
        help="Data source type (only h1_csv supported in Phase 1)",
    )
    parser.add_argument(
        "--path",
        default=None,
        metavar="FILE",
        help="Path to local CSV file. If omitted, downloads from GitHub.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Stop after N records (useful for testing)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        metavar="N",
        help="Records per batch (50 recommended to avoid Ollama timeouts)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse + extract but do NOT write to PostgreSQL or Qdrant",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Skip LLM extraction; use default values for intelligence fields",
    )
    parser.add_argument(
        "--skip-embed",
        action="store_true",
        help="Skip BGE-M3 embedding; records saved to PostgreSQL only",
    )
    parser.add_argument(
        "--llm-concurrency",
        type=int,
        default=4,
        metavar="N",
        help="Max concurrent Ollama LLM calls per batch",
    )
    parser.add_argument(
        "--embed-concurrency",
        type=int,
        default=2,
        metavar="N",
        help="Max concurrent BGE-M3 embedding calls per batch",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging",
    )
    return parser.parse_args()


async def main() -> None:
    args = _parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    t0 = time.monotonic()

    await run_seed(
        path=args.path,
        limit=args.limit,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
        skip_llm=args.skip_llm,
        skip_embed=args.skip_embed,
        llm_concurrency=args.llm_concurrency,
        embed_concurrency=args.embed_concurrency,
    )

    elapsed = time.monotonic() - t0
    print(f"\nElapsed: {elapsed:.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
