"""Tests for ResponseBaseline — 15 tests covering all scoring dimensions."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pentra_tools.analysis.response_baseline import (
    ResponseBaseline,
    ResponseProfile,
    AnomalyScore,
    _has_db_error,
    _has_error_page,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_response(status=200, body=b"Hello World", text="Hello World"):
    resp = MagicMock()
    resp.status_code = status
    resp.content = body
    resp.text = text
    return resp


def _build_profile(status=200, length=100, time_ms=50.0,
                   db_error=False, error_page=False, content_hash=12345):
    return ResponseProfile(
        status_code=status,
        content_length=length,
        response_time_ms=time_ms,
        has_db_error=db_error,
        has_error_page=error_page,
        content_hash=content_hash,
    )


# ── establish() ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_establish_creates_baseline():
    baseline = ResponseBaseline()
    client = AsyncMock()
    client.get.return_value = _mock_response()

    profile = await baseline.establish(client, "http://t.com/q", "id")

    assert isinstance(profile, ResponseProfile)
    assert profile.status_code == 200
    assert "http://t.com/q:id" in baseline._baselines


@pytest.mark.asyncio
async def test_establish_averages_timing():
    baseline = ResponseBaseline()
    client = AsyncMock()
    client.get.return_value = _mock_response()

    with patch("pentra_tools.analysis.response_baseline.time.monotonic",
               side_effect=[0, 0.05, 0, 0.10, 0, 0.15]):
        profile = await baseline.establish(client, "http://t.com/q", "id")

    # Average of 50ms, 100ms, 150ms = 100ms
    assert 90 <= profile.response_time_ms <= 110


@pytest.mark.asyncio
async def test_establish_fallback_on_all_failures():
    baseline = ResponseBaseline()
    client = AsyncMock()
    client.get.side_effect = Exception("connection refused")

    profile = await baseline.establish(client, "http://t.com/q", "id")

    # Fallback profile
    assert profile.status_code == 200
    assert profile.content_length == 0
    assert profile.response_time_ms == 1000.0


# ── is_anomalous() scoring ────────────────────────────────────────────────────

def test_is_anomalous_db_error_detected():
    bl = ResponseBaseline()
    bl._baselines["http://t.com:id"] = _build_profile(db_error=False)

    resp = _mock_response(body=b"x" * 100, text="you have an error in your sql syntax here")
    score = bl.is_anomalous("http://t.com", "id", resp, test_elapsed_ms=50.0)

    assert score.score >= 50
    assert score.confirmed
    assert any("Database error" in e for e in score.evidence)


def test_is_anomalous_timing_anomaly():
    bl = ResponseBaseline()
    bl._baselines["http://t.com:id"] = _build_profile(time_ms=100.0, length=100)

    resp = _mock_response(body=b"x" * 100, text="x" * 100)
    score = bl.is_anomalous("http://t.com", "id", resp, test_elapsed_ms=5000.0)

    assert score.score >= 40
    assert score.confirmed
    assert any("Response time" in e for e in score.evidence)


def test_is_anomalous_content_length_delta():
    bl = ResponseBaseline()
    bl._baselines["http://t.com:id"] = _build_profile(length=100)

    big_body = b"x" * 500
    resp = _mock_response(body=big_body, text="x" * 500)
    score = bl.is_anomalous("http://t.com", "id", resp, test_elapsed_ms=50.0)

    assert score.score >= 30
    assert any("Content length" in e for e in score.evidence)


def test_is_anomalous_status_code_change():
    bl = ResponseBaseline()
    bl._baselines["http://t.com:id"] = _build_profile(status=200, length=100)

    resp = _mock_response(status=500, body=b"x" * 100, text="x" * 100)
    score = bl.is_anomalous("http://t.com", "id", resp, test_elapsed_ms=50.0)

    assert score.score >= 25
    assert any("Status code" in e for e in score.evidence)


def test_is_anomalous_error_page():
    bl = ResponseBaseline()
    bl._baselines["http://t.com:id"] = _build_profile(error_page=False, length=50)

    resp = _mock_response(body=b"x" * 50, text="500 internal server error")
    score = bl.is_anomalous("http://t.com", "id", resp, test_elapsed_ms=50.0)

    assert any("Error page" in e for e in score.evidence)


def test_is_anomalous_content_hash_change():
    bl = ResponseBaseline()
    bl._baselines["http://t.com:id"] = _build_profile(length=100, content_hash=99999)

    # same length but different content
    resp = _mock_response(body=b"y" * 100, text="y" * 100)
    score = bl.is_anomalous("http://t.com", "id", resp, test_elapsed_ms=50.0)

    assert any("content changed" in e.lower() for e in score.evidence)


def test_threshold_39_not_confirmed():
    bl = ResponseBaseline()
    bl._baselines["http://t.com:id"] = _build_profile(
        status=200, length=100, time_ms=50.0, content_hash=hash("y" * 100)
    )

    resp = _mock_response(body=b"y" * 100, text="y" * 100)
    score = bl.is_anomalous("http://t.com", "id", resp, test_elapsed_ms=50.0)

    assert score.score < 40 or not score.confirmed or score.score == 0


def test_threshold_40_confirmed():
    score = AnomalyScore(score=40, confirmed=False)
    assert score.confirmed


# ── DB error patterns ─────────────────────────────────────────────────────────

def test_db_error_patterns_mssql():
    assert _has_db_error("Microsoft SQL Server Error: incorrect syntax near")


def test_db_error_patterns_mysql():
    assert _has_db_error("Warning: mysql_fetch_array() expects parameter")


def test_db_error_patterns_postgresql():
    assert _has_db_error("pg_query(): Query failed: ERROR: unterminated quoted string")


def test_db_error_patterns_oracle():
    assert _has_db_error("ORA-00907: missing right parenthesis")
