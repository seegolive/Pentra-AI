"""Tests for Scan Engine Presets — Task 18.11."""

from __future__ import annotations

import os
import pytest

from pentra_agent.scan_presets import (
    ScanPreset,
    PRESETS,
    get_preset,
    list_presets,
)


# ── Preset registry ───────────────────────────────────────────────────────────

def test_all_builtin_presets_exist():
    for name in ("full", "fast", "stealth", "quick", "authenticated"):
        assert name in PRESETS


def test_get_preset_returns_correct_object():
    preset = get_preset("fast")
    assert preset.name == "fast"
    assert isinstance(preset, ScanPreset)


def test_get_preset_raises_for_unknown():
    with pytest.raises(ValueError, match="Unknown preset"):
        get_preset("nonexistent")


def test_list_presets_returns_all():
    presets = list_presets()
    assert len(presets) == len(PRESETS)
    names = [p["name"] for p in presets]
    assert "full" in names
    assert "stealth" in names


# ── Preset values ─────────────────────────────────────────────────────────────

def test_fast_preset_skips_ffuf_and_soap():
    p = get_preset("fast")
    assert p.run_ffuf is False
    assert p.run_soap_xxe is False
    assert p.concurrent_candidates >= 4  # faster


def test_stealth_preset_disables_loud_tools():
    p = get_preset("stealth")
    assert p.run_nuclei is False
    assert p.run_ffuf is False
    assert p.run_burp_scan is False
    assert p.concurrent_candidates == 1  # no concurrency
    assert p.payload_pacing_s >= 0.5  # slow pacing


def test_quick_preset_minimal():
    p = get_preset("quick")
    assert p.max_candidates <= 12
    assert p.max_payloads_per_candidate <= 2
    assert p.run_nuclei is False


def test_full_preset_runs_all_tools():
    p = get_preset("full")
    assert p.run_nuclei is True
    assert p.run_ffuf is True
    assert p.run_burp_scan is True
    assert p.run_soap_xxe is True
    assert p.run_csrf_check is True


def test_authenticated_preset_has_high_payload_cap():
    p = get_preset("authenticated")
    assert p.max_payloads_per_candidate >= 6  # more IDOR variants


# ── apply_to_env ──────────────────────────────────────────────────────────────

def test_apply_to_env_sets_env_vars(monkeypatch):
    """apply_to_env() writes correct env vars readable by vuln_hunt_node."""
    preset = get_preset("fast")
    preset.apply_to_env()

    assert os.environ["PENTRA_CONCURRENT_CANDIDATES"] == str(preset.concurrent_candidates)
    assert os.environ["PENTRA_RUN_FFUF"] == "false"
    assert os.environ["PENTRA_RUN_NUCLEI"] == "true"
    assert os.environ["PENTRA_MAX_CANDIDATES"] == str(preset.max_candidates)


def test_stealth_apply_to_env_disables_tools(monkeypatch):
    preset = get_preset("stealth")
    preset.apply_to_env()
    assert os.environ["PENTRA_RUN_NUCLEI"] == "false"
    assert os.environ["PENTRA_RUN_FFUF"] == "false"
    assert os.environ["PENTRA_CONCURRENT_CANDIDATES"] == "1"


# ── as_dict ───────────────────────────────────────────────────────────────────

def test_as_dict_schema():
    d = get_preset("full").as_dict()
    assert "name" in d
    assert "description" in d
    assert "concurrent_candidates" in d
    assert "run_nuclei" in d
    assert "max_candidates" in d
