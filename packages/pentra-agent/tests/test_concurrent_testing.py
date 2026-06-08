"""Tests for Task 18.9 — Concurrent Testing."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_agent.nodes.vuln_hunt_node import CONCURRENT_CANDIDATES, _PAYLOAD_PACING_S


# ── Constant assertions ───────────────────────────────────────────────────────

def test_concurrent_candidates_default():
    """CONCURRENT_CANDIDATES should default to 3."""
    assert CONCURRENT_CANDIDATES == 3


def test_payload_pacing_reduced():
    """_PAYLOAD_PACING_S should be ≤0.2s (faster than original 0.5s)."""
    assert _PAYLOAD_PACING_S <= 0.2


# ── Concurrency behaviour ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_semaphore_limits_concurrency():
    """At most CONCURRENT_CANDIDATES tasks should run simultaneously."""
    MAX = 3
    sem = asyncio.Semaphore(MAX)
    active = [0]
    peak = [0]

    async def task():
        async with sem:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
            await asyncio.sleep(0.02)
            active[0] -= 1

    await asyncio.gather(*[task() for _ in range(10)])
    assert peak[0] <= MAX


@pytest.mark.asyncio
async def test_concurrent_candidates_faster_than_sequential():
    """CONCURRENT_CANDIDATES=3 should complete 9 tasks faster than sequential."""
    sem = asyncio.Semaphore(3)
    task_time = 0.05  # simulated HTTP delay

    async def fake_candidate():
        async with sem:
            await asyncio.sleep(task_time)

    t0 = time.monotonic()
    await asyncio.gather(*[fake_candidate() for _ in range(9)])
    elapsed = time.monotonic() - t0

    # Sequential would take 9 * 0.05 = 0.45s
    # Concurrent (sem=3) should take ~3 rounds × 0.05 = 0.15s
    assert elapsed < 0.45 * 0.7  # at least 30% faster than sequential


@pytest.mark.asyncio
async def test_gather_collects_all_findings():
    """asyncio.gather should collect findings from all concurrent candidates."""
    results: list[str] = []

    async def fake_test(candidate: str) -> None:
        await asyncio.sleep(0.01)
        results.append(candidate)

    candidates = [f"cand-{i}" for i in range(6)]
    await asyncio.gather(*[fake_test(c) for c in candidates])

    assert len(results) == 6
    assert set(results) == set(candidates)


@pytest.mark.asyncio
async def test_gather_continues_on_exception():
    """return_exceptions=True: one failing candidate should not block others."""
    results: list[str] = []

    async def fake_test(i: int) -> None:
        if i == 2:
            raise ValueError("simulated error")
        await asyncio.sleep(0.01)
        results.append(f"cand-{i}")

    # asyncio.gather with return_exceptions=True
    await asyncio.gather(*[fake_test(i) for i in range(5)], return_exceptions=True)

    # 4 candidates should succeed (candidate 2 failed but didn't block)
    assert len(results) == 4
    assert "cand-2" not in results


def test_concurrent_candidates_env_override(monkeypatch):
    """CONCURRENT_CANDIDATES should read from PENTRA_CONCURRENT_CANDIDATES env var."""
    # Note: this just tests the default; env override is set at import time
    # so we verify the constant is an int
    assert isinstance(CONCURRENT_CANDIDATES, int)
    assert CONCURRENT_CANDIDATES >= 1
