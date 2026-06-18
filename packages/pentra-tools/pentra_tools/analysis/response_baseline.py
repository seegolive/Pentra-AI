"""
Behavioral response baseline for anomaly detection.
Establishes a normal response fingerprint, then scores deviations.
"""
from __future__ import annotations
import re
import time
import statistics
from dataclasses import dataclass, field
from typing import Optional
import httpx


DB_ERROR_PATTERNS = [
    # MSSQL
    r"microsoft.*sql.*server", r"unclosed quotation mark after",
    r"incorrect syntax near", r"conversion failed when converting",
    r"procedure or function.*expects parameter",
    # MySQL
    r"you have an error in your sql syntax",
    r"warning.*mysql_", r"mysql_fetch_array\(\)",
    r"supplied argument is not a valid mysql",
    # PostgreSQL
    r"pg_query\(\):", r"psql.*error", r"unterminated quoted string",
    r"pg_exec\(\) query failed",
    # Oracle
    r"ora-[0-9]{5}", r"oracle.*driver", r"quoted string not properly terminated",
    # Generic SQL errors
    r"sql syntax.*error", r"database error occurred",
    r"odbc.*error", r"jdbc.*error",
    r"\bsyntax error\b.*\bnear\b",
]

ERROR_PAGE_PATTERNS = [
    r"<title>.*error.*</title>",
    r"500.*internal server error",
    r"404.*not found",
    r"403.*forbidden",
    r"application error",
    r"stack trace",
    r"at System\.",
]


@dataclass
class ResponseProfile:
    status_code: int
    content_length: int
    response_time_ms: float
    has_db_error: bool
    has_error_page: bool
    content_hash: int

    @classmethod
    def from_response(cls, response: httpx.Response, elapsed_ms: float) -> "ResponseProfile":
        text = response.text or ""
        return cls(
            status_code=response.status_code,
            content_length=len(response.content),
            response_time_ms=elapsed_ms,
            has_db_error=_has_db_error(text),
            has_error_page=_has_error_page(text),
            content_hash=hash(text[:500]),
        )


@dataclass
class AnomalyScore:
    score: int
    confirmed: bool
    evidence: list[str] = field(default_factory=list)

    THRESHOLD = 40

    def __post_init__(self):
        self.confirmed = self.score >= self.THRESHOLD


class ResponseBaseline:
    """
    Establish behavioral baseline for a URL+param combination,
    then detect anomalies in test responses.
    """

    BASELINE_REQUESTS = 3
    TIMING_MULTIPLIER = 3.0
    LENGTH_DELTA = 200

    def __init__(self):
        self._baselines: dict[str, ResponseProfile] = {}

    async def establish(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        normal_value: str = "1",
    ) -> ResponseProfile:
        """
        Send BASELINE_REQUESTS requests with normal value, build average profile.
        Stores result keyed by f"{url}:{param}".
        """
        profiles = []
        for _ in range(self.BASELINE_REQUESTS):
            start = time.monotonic()
            try:
                response = await client.get(url, params={param: normal_value})
                elapsed_ms = (time.monotonic() - start) * 1000
                profiles.append(ResponseProfile.from_response(response, elapsed_ms))
            except Exception:
                pass

        if not profiles:
            baseline = ResponseProfile(
                status_code=200,
                content_length=0,
                response_time_ms=1000.0,
                has_db_error=False,
                has_error_page=False,
                content_hash=0,
            )
        else:
            baseline = ResponseProfile(
                status_code=profiles[0].status_code,
                content_length=int(statistics.mean(p.content_length for p in profiles)),
                response_time_ms=statistics.mean(p.response_time_ms for p in profiles),
                has_db_error=any(p.has_db_error for p in profiles),
                has_error_page=any(p.has_error_page for p in profiles),
                content_hash=profiles[0].content_hash,
            )

        key = f"{url}:{param}"
        self._baselines[key] = baseline
        return baseline

    def is_anomalous(
        self,
        url: str,
        param: str,
        test_response: httpx.Response,
        test_elapsed_ms: float,
    ) -> AnomalyScore:
        """
        Score how anomalous a test response is vs the established baseline.
        Returns AnomalyScore with .confirmed = True if score >= THRESHOLD.
        """
        key = f"{url}:{param}"
        baseline = self._baselines.get(key)

        if baseline is None:
            return AnomalyScore(score=0, confirmed=False,
                                evidence=["No baseline established for this endpoint"])

        score = 0
        evidence = []
        test_text = test_response.text or ""
        test_length = len(test_response.content)

        if _has_db_error(test_text) and not baseline.has_db_error:
            score += 50
            evidence.append("Database error string found in response (not in baseline)")

        if test_elapsed_ms > baseline.response_time_ms * self.TIMING_MULTIPLIER:
            score += 40
            evidence.append(
                f"Response time {test_elapsed_ms:.0f}ms vs baseline "
                f"{baseline.response_time_ms:.0f}ms "
                f"({test_elapsed_ms / baseline.response_time_ms:.1f}× slower)"
            )

        length_delta = abs(test_length - baseline.content_length)
        if length_delta > self.LENGTH_DELTA:
            score += 30
            evidence.append(
                f"Content length changed by {length_delta} bytes "
                f"(baseline: {baseline.content_length}, test: {test_length})"
            )

        if test_response.status_code != baseline.status_code:
            score += 25
            evidence.append(
                f"Status code changed: {baseline.status_code} → {test_response.status_code}"
            )

        if _has_error_page(test_text) and not baseline.has_error_page:
            score += 20
            evidence.append("Error page detected (not present in baseline)")

        if hash(test_text[:500]) != baseline.content_hash and length_delta < self.LENGTH_DELTA:
            score += 15
            evidence.append("Response content changed significantly")

        score = min(score, 100)

        return AnomalyScore(score=score, confirmed=score >= AnomalyScore.THRESHOLD, evidence=evidence)


    def establish_from_strings(
        self,
        url: str,
        param: str,
        body: str,
        status_code: int = 200,
        elapsed_ms: float = 200.0,
    ) -> ResponseProfile:
        """
        Build a baseline profile from existing string data (no HTTP requests needed).
        Used when the caller already has the baseline response body.
        """
        profile = ResponseProfile(
            status_code=status_code,
            content_length=len(body.encode("utf-8", errors="replace")),
            response_time_ms=elapsed_ms,
            has_db_error=_has_db_error(body),
            has_error_page=_has_error_page(body),
            content_hash=hash(body[:500]),
        )
        key = f"{url}:{param}"
        self._baselines[key] = profile
        return profile

    def score_from_strings(
        self,
        url: str,
        param: str,
        test_body: str,
        test_status_code: int = 200,
        test_elapsed_ms: float = 200.0,
    ) -> AnomalyScore:
        """
        Score a test response given as strings (no httpx.Response object needed).
        Used when the caller manages requests directly (e.g. via Burp MCP or _direct_request).
        """
        key = f"{url}:{param}"
        baseline = self._baselines.get(key)

        if baseline is None:
            return AnomalyScore(score=0, confirmed=False,
                                evidence=["No baseline established for this endpoint"])

        score = 0
        evidence = []
        test_length = len(test_body.encode("utf-8", errors="replace"))

        if _has_db_error(test_body) and not baseline.has_db_error:
            score += 50
            evidence.append("Database error string found in response (not in baseline)")

        if baseline.response_time_ms > 0 and test_elapsed_ms > baseline.response_time_ms * self.TIMING_MULTIPLIER:
            score += 40
            evidence.append(
                f"Response time {test_elapsed_ms:.0f}ms vs baseline "
                f"{baseline.response_time_ms:.0f}ms "
                f"({test_elapsed_ms / baseline.response_time_ms:.1f}× slower)"
            )

        length_delta = abs(test_length - baseline.content_length)
        if length_delta > self.LENGTH_DELTA:
            score += 30
            evidence.append(
                f"Content length changed by {length_delta} bytes "
                f"(baseline: {baseline.content_length}, test: {test_length})"
            )

        if test_status_code != baseline.status_code:
            score += 25
            evidence.append(
                f"Status code changed: {baseline.status_code} → {test_status_code}"
            )

        if _has_error_page(test_body) and not baseline.has_error_page:
            score += 20
            evidence.append("Error page detected (not present in baseline)")

        if hash(test_body[:500]) != baseline.content_hash and length_delta < self.LENGTH_DELTA:
            score += 15
            evidence.append("Response content changed significantly")

        score = min(score, 100)
        return AnomalyScore(score=score, confirmed=score >= AnomalyScore.THRESHOLD, evidence=evidence)


def _has_db_error(text: str) -> bool:
    """Check if response text contains database error patterns."""
    lower = text.lower()
    return any(re.search(pattern, lower) for pattern in DB_ERROR_PATTERNS)


def _has_error_page(text: str) -> bool:
    """Check if response appears to be an error page."""
    lower = text.lower()
    return any(re.search(pattern, lower) for pattern in ERROR_PAGE_PATTERNS)
