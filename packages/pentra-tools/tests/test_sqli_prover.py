"""Tests for SQLiProver — 15 tests covering all proof techniques."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from pentra_tools.scanners.sqli_prover import SQLiProver, ProofResult, PROOF_MARKER


# ── Helpers ───────────────────────────────────────────────────────────────────

def _response(body: bytes = b"OK", status: int = 200) -> httpx.Response:
    return httpx.Response(status_code=status, content=body)


def _make_client(*responses) -> AsyncMock:
    """Return mock httpx.AsyncClient where .get() returns responses in sequence."""
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.side_effect = list(responses)
    return client


# ── Boolean Differential ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_boolean_differential_confirmed():
    prover = SQLiProver(timeout=5.0)
    # baseline=100 bytes, true≈100, false≈500 → differential confirmed
    client = _make_client(
        _response(b"x" * 100),   # baseline
        _response(b"x" * 98),    # true condition ≈ baseline
        _response(b"x" * 500),   # false condition ≠ baseline
    )
    result = await prover.prove(client, "http://t.com/q", "id")
    assert result.confirmed
    assert result.proof_type == "boolean_differential"
    assert result.confidence == 90


@pytest.mark.asyncio
async def test_boolean_differential_not_confirmed():
    prover = SQLiProver(timeout=5.0)
    # All responses same size — no differential
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = _response(b"x" * 100)
    # Override _error_based and _time_differential to return unconfirmed quickly
    with (
        patch.object(prover, "_error_based", return_value=ProofResult(
            confirmed=False, proof_type="unconfirmed", confidence=0,
            evidence="not confirmed", request_count=0)),
        patch.object(prover, "_time_differential", return_value=ProofResult(
            confirmed=False, proof_type="unconfirmed", confidence=0,
            evidence="not confirmed", request_count=0)),
    ):
        result = await prover.prove(client, "http://t.com/q", "id")
    assert not result.confirmed


# ── Error-Based ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_error_based_mssql_confirmed():
    prover = SQLiProver(timeout=5.0)
    prover._request_count = 99  # simulate after boolean

    err_text = "conversion failed when converting varchar to int"
    client = _make_client(_response(err_text.encode()))
    result = await prover._error_based(client, "http://t.com/q", "id", db_type="mssql")

    assert result.confirmed
    assert result.proof_type == "error_based"
    assert result.confidence == 95


@pytest.mark.asyncio
async def test_error_based_mysql_confirmed():
    prover = SQLiProver(timeout=5.0)
    err_text = "xpath syntax error: extractvalue error"
    client = _make_client(_response(err_text.encode()))
    result = await prover._error_based(client, "http://t.com/q", "id", db_type="mysql")
    assert result.confirmed


@pytest.mark.asyncio
async def test_error_based_no_match():
    prover = SQLiProver(timeout=5.0)
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = _response(b"OK page loaded")
    result = await prover._error_based(client, "http://t.com/q", "id", db_type="generic")
    assert not result.confirmed
    assert result.proof_type == "unconfirmed"


# ── Time Differential ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_time_differential_5s_confirmed():
    prover = SQLiProver(timeout=10.0)
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = _response(b"OK")

    with patch("pentra_tools.scanners.sqli_prover.time.monotonic",
               side_effect=[0, 5.2, 0, 0.08]):
        result = await prover._time_differential(client, "http://t.com/q", "id", db_type="mssql")

    assert result.confirmed
    assert result.proof_type == "time_differential"


@pytest.mark.asyncio
async def test_time_differential_0s_not_confirmed():
    prover = SQLiProver(timeout=10.0)
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = _response(b"OK")

    with patch("pentra_tools.scanners.sqli_prover.time.monotonic",
               side_effect=[0, 0.1, 0, 0.09]):
        result = await prover._time_differential(client, "http://t.com/q", "id", db_type="mssql")

    assert not result.confirmed
    assert result.proof_type == "time_differential"


@pytest.mark.asyncio
async def test_time_differential_timeout_still_confirms():
    prover = SQLiProver(timeout=5.0)
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.side_effect = httpx.TimeoutException("timed out")

    result = await prover._time_differential(client, "http://t.com/q", "id", db_type="mysql")
    assert result.confirmed
    assert result.confidence == 70


# ── prove() orchestration ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_prove_tries_boolean_first():
    prover = SQLiProver(timeout=5.0)
    # boolean differential confirms immediately
    client = _make_client(
        _response(b"x" * 100),
        _response(b"x" * 98),
        _response(b"x" * 500),
    )
    result = await prover.prove(client, "http://t.com/q", "id", db_type="mssql")
    assert result.proof_type == "boolean_differential"


@pytest.mark.asyncio
async def test_prove_falls_through_to_time():
    prover = SQLiProver(timeout=5.0)
    with (
        patch.object(prover, "_boolean_differential", return_value=ProofResult(
            confirmed=False, proof_type="unconfirmed", confidence=0,
            evidence="no diff", request_count=0)),
        patch.object(prover, "_error_based", return_value=ProofResult(
            confirmed=False, proof_type="unconfirmed", confidence=0,
            evidence="no error", request_count=0)),
        patch.object(prover, "_time_differential", return_value=ProofResult(
            confirmed=True, proof_type="time_differential", confidence=85,
            evidence="time diff ok", request_count=2)),
    ):
        result = await prover.prove(AsyncMock(), "http://t.com/q", "id")

    assert result.proof_type == "time_differential"
    assert result.confirmed


@pytest.mark.asyncio
async def test_prove_returns_unconfirmed_if_all_fail():
    prover = SQLiProver(timeout=5.0)
    with (
        patch.object(prover, "_boolean_differential", return_value=ProofResult(
            confirmed=False, proof_type="unconfirmed", confidence=0,
            evidence="no diff", request_count=0)),
        patch.object(prover, "_error_based", return_value=ProofResult(
            confirmed=False, proof_type="unconfirmed", confidence=0,
            evidence="no error", request_count=0)),
        patch.object(prover, "_time_differential", return_value=ProofResult(
            confirmed=False, proof_type="time_differential", confidence=10,
            evidence="inconclusive", request_count=2)),
    ):
        result = await prover.prove(AsyncMock(), "http://t.com/q", "id")

    assert not result.confirmed


# ── Additional assertions ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_request_count_tracked():
    prover = SQLiProver(timeout=5.0)
    client = _make_client(
        _response(b"x" * 100),
        _response(b"x" * 100),
        _response(b"x" * 100),
    )
    with (
        patch.object(prover, "_error_based", return_value=ProofResult(
            confirmed=False, proof_type="unconfirmed", confidence=0,
            evidence="no error", request_count=0)),
        patch.object(prover, "_time_differential", return_value=ProofResult(
            confirmed=False, proof_type="unconfirmed", confidence=0,
            evidence="no diff", request_count=2)),
    ):
        result = await prover.prove(client, "http://t.com/q", "id")

    # request_count is tracked across all techniques — at least 2
    assert result.request_count >= 2


@pytest.mark.asyncio
async def test_db_type_preserved_in_result():
    prover = SQLiProver(timeout=5.0)
    with (
        patch.object(prover, "_boolean_differential", return_value=ProofResult(
            confirmed=True, proof_type="boolean_differential", confidence=90,
            evidence="confirmed", request_count=3)),
    ):
        result = await prover.prove(AsyncMock(), "http://t.com/q", "id", db_type="mssql")

    assert result.db_type == "mssql"


@pytest.mark.asyncio
async def test_false_positive_slow_network_not_confirmed():
    """A 1000ms response is NOT ~5000ms — must not be confirmed as time-based SQLi."""
    prover = SQLiProver(timeout=10.0)
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get.return_value = _response(b"OK")

    with patch("pentra_tools.scanners.sqli_prover.time.monotonic",
               side_effect=[0, 1.0, 0, 0.9]):  # 100ms difference — not ~5s
        result = await prover._time_differential(client, "http://t.com/q", "id", db_type="generic")

    assert not result.confirmed


@pytest.mark.asyncio
async def test_proof_result_evidence_not_empty():
    prover = SQLiProver(timeout=5.0)
    client = _make_client(
        _response(b"x" * 100),
        _response(b"x" * 98),
        _response(b"x" * 500),
    )
    result = await prover.prove(client, "http://t.com/q", "id")
    assert result.evidence  # never empty string
    assert len(result.evidence) > 0
