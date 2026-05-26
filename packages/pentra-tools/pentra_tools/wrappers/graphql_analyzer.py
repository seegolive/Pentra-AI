"""Task 5.3 — GraphQL attack surface analyzer.

Identifies common GraphQL vulnerabilities without sending destructive payloads:
  1. Introspection enabled (schema exposure)
  2. Query depth bypass (nested query DoS)
  3. Batch query abuse (rate-limit bypass)
  4. Field suggestion leakage (information disclosure)
  5. Alias-based query flooding
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from pentra_tools.base import AsyncToolWrapper, RateLimiter, ToolResult


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class GraphQLTestResult:
    test_name: str
    is_vulnerable: bool
    severity: str           # critical / high / medium / low / info
    detail: str
    request_body: dict = field(default_factory=dict)
    response_snippet: str = ""


# ── Queries used in tests ─────────────────────────────────────────────────────

_INTROSPECTION_QUERY = {
    "query": "{ __schema { queryType { name } types { name } } }"
}

# Deeply nested query — 7 levels — tests depth limiting
_DEPTH_QUERY = {
    "query": (
        "{ a { b { c { d { e { f { g { __typename } } } } } } } }"
    )
}

# Batch: 50 identical simple queries in one request
_BATCH_QUERY = [{"query": "{ __typename }"}] * 50

# Typo-ed field to trigger suggestion ("Did you mean…?")
_SUGGESTION_QUERY = {
    "query": "{ usr { id } }"   # likely typo of "user" — triggers suggestion
}

# 10 aliased queries in one request to test alias rate limiting
_ALIAS_FLOOD_QUERY = {
    "query": " ".join(
        f"q{i}: __typename" for i in range(10)
    ).join(["{ ", " }"])
}


# ── Wrapper ───────────────────────────────────────────────────────────────────

class GraphQLAnalyzer(AsyncToolWrapper):
    """
    Analyze attack surface of a GraphQL endpoint.

    Only sends non-destructive read queries (no mutations, no data modification).
    IS_DESTRUCTIVE = False — no HITL approval required.
    """

    name = "graphql_analyzer"
    description = (
        "Detect common GraphQL misconfigurations: introspection, depth bypass, "
        "batching abuse, field suggestion leakage, alias flooding."
    )
    timeout = 60
    IS_DESTRUCTIVE = False

    rate_limiter = RateLimiter(max_calls=5, period=10.0)  # 5 req / 10 s

    async def run(
        self,
        target: str,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> ToolResult:
        """
        Analyse the GraphQL endpoint at *target*.

        Args:
            target:  Full URL of the GraphQL endpoint (e.g. https://api.example.com/graphql)
            headers: Optional extra HTTP headers (Authorization, cookies, etc.)
        """
        self.scope.validate_or_raise(target)

        t0 = time.monotonic()
        test_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if headers:
            test_headers.update(headers)

        tests = [
            self._test_introspection(target, test_headers),
            self._test_depth(target, test_headers),
            self._test_batching(target, test_headers),
            self._test_field_suggestion(target, test_headers),
            self._test_alias_flood(target, test_headers),
        ]

        results: list[GraphQLTestResult] = []
        for coro in tests:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            result = await coro
            results.append(result)

        vulnerabilities = [r for r in results if r.is_vulnerable]
        duration = time.monotonic() - t0

        return ToolResult(
            tool=self.name,
            success=True,
            data={
                "vulnerabilities": [
                    {
                        "test": r.test_name,
                        "severity": r.severity,
                        "detail": r.detail,
                        "response_snippet": r.response_snippet,
                    }
                    for r in vulnerabilities
                ],
                "all_tests": [
                    {
                        "test": r.test_name,
                        "is_vulnerable": r.is_vulnerable,
                        "severity": r.severity,
                        "detail": r.detail,
                    }
                    for r in results
                ],
                "vuln_count": len(vulnerabilities),
            },
            raw="\n".join(
                f"[{'VULN' if r.is_vulnerable else 'OK'}] {r.test_name}: {r.detail}"
                for r in results
            ),
            target=target,
            command=["graphql_analyzer", target],
            duration_seconds=duration,
        )

    # ── Individual tests ──────────────────────────────────────────────────────

    async def _post(
        self, url: str, body: Any, headers: dict
    ) -> tuple[int, str]:
        """POST JSON to the endpoint and return (status_code, response_text)."""
        try:
            async with httpx.AsyncClient(
                timeout=15,
                follow_redirects=True,
                verify=False,  # noqa: S501 — security research context
            ) as client:
                response = await client.post(url, json=body, headers=headers)
            return response.status_code, response.text[:2000]
        except httpx.HTTPError as exc:
            return 0, str(exc)

    async def _test_introspection(
        self, url: str, headers: dict
    ) -> GraphQLTestResult:
        """Check if schema introspection is enabled."""
        status, body = await self._post(url, _INTROSPECTION_QUERY, headers)
        is_vulnerable = status == 200 and "__schema" in body

        return GraphQLTestResult(
            test_name="introspection_enabled",
            is_vulnerable=is_vulnerable,
            severity="medium" if is_vulnerable else "info",
            detail=(
                "GraphQL introspection is enabled — full schema is publicly exposed."
                if is_vulnerable
                else "Introspection is disabled or returned an error."
            ),
            request_body=_INTROSPECTION_QUERY,
            response_snippet=body[:300],
        )

    async def _test_depth(
        self, url: str, headers: dict
    ) -> GraphQLTestResult:
        """Send a 7-level nested query; a 200 suggests no depth limit."""
        status, body = await self._post(url, _DEPTH_QUERY, headers)
        # Vulnerable if server returns 200 and no depth-limit error
        depth_error_indicators = [
            "depth", "exceeds", "max", "limit", "too deep", "complexity"
        ]
        has_error = any(ind in body.lower() for ind in depth_error_indicators)
        is_vulnerable = status == 200 and "errors" not in body and not has_error

        return GraphQLTestResult(
            test_name="query_depth_bypass",
            is_vulnerable=is_vulnerable,
            severity="low" if is_vulnerable else "info",
            detail=(
                "No query depth limit detected — deeply nested queries may cause DoS."
                if is_vulnerable
                else "Server enforces or rejects deep queries."
            ),
            request_body=_DEPTH_QUERY,
            response_snippet=body[:300],
        )

    async def _test_batching(
        self, url: str, headers: dict
    ) -> GraphQLTestResult:
        """Send 50 batched queries; success indicates batching is enabled."""
        status, body = await self._post(url, _BATCH_QUERY, headers)
        # Batching is enabled if 200 and response is a JSON array
        is_vulnerable = (
            status == 200
            and body.lstrip().startswith("[")
        )

        return GraphQLTestResult(
            test_name="batch_query_abuse",
            is_vulnerable=is_vulnerable,
            severity="medium" if is_vulnerable else "info",
            detail=(
                "GraphQL query batching is enabled — can be used to bypass rate limits."
                if is_vulnerable
                else "Batching not accepted or returned an error."
            ),
            request_body={"type": "array", "length": len(_BATCH_QUERY)},
            response_snippet=body[:300],
        )

    async def _test_field_suggestion(
        self, url: str, headers: dict
    ) -> GraphQLTestResult:
        """Send a typo-ed field; suggestion messages leak valid field names."""
        status, body = await self._post(url, _SUGGESTION_QUERY, headers)
        is_vulnerable = (
            status == 200
            and "did you mean" in body.lower()
        )

        return GraphQLTestResult(
            test_name="field_suggestion_leakage",
            is_vulnerable=is_vulnerable,
            severity="low" if is_vulnerable else "info",
            detail=(
                'Field suggestion leakage — server returns "Did you mean...?" hints '
                "that disclose valid field names."
                if is_vulnerable
                else "Field suggestions are disabled or field did not match."
            ),
            request_body=_SUGGESTION_QUERY,
            response_snippet=body[:300],
        )

    async def _test_alias_flood(
        self, url: str, headers: dict
    ) -> GraphQLTestResult:
        """Send 10 aliased fields in one query; unlimited aliases = DoS risk."""
        status, body = await self._post(url, _ALIAS_FLOOD_QUERY, headers)
        alias_error_indicators = ["alias", "limit", "max", "exceed", "too many"]
        has_error = (
            "errors" in body.lower()
            and any(ind in body.lower() for ind in alias_error_indicators)
        )
        is_vulnerable = status == 200 and not has_error and "q9" in body

        return GraphQLTestResult(
            test_name="alias_flooding",
            is_vulnerable=is_vulnerable,
            severity="low" if is_vulnerable else "info",
            detail=(
                "No alias limit detected — alias-based query flooding may cause DoS."
                if is_vulnerable
                else "Aliases are limited or query was rejected."
            ),
            request_body=_ALIAS_FLOOD_QUERY,
            response_snippet=body[:300],
        )
