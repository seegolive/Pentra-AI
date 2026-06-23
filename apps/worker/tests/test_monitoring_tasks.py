"""Tests for worker/app/tasks/monitoring.py helpers.

_detect_delta is a pure-Python function — no DB, no mock needed.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.tasks.monitoring import _detect_delta


def _snap(subdomains=None, open_ports=None, endpoints=None):
    """Build a minimal ReconSnapshotORM-like namespace."""
    return SimpleNamespace(
        subdomains=subdomains or [],
        open_ports=open_ports or {},
        endpoints=endpoints or [],
    )


# ── Subdomain deltas ──────────────────────────────────────────────────────────

def test_detect_delta_new_subdomain():
    prev = _snap(subdomains=["target.com"])
    curr = {"subdomains": ["target.com", "api.target.com"], "open_ports": {}, "endpoints": []}
    deltas = _detect_delta(prev, curr)
    types = {d["type"] for d in deltas}
    assert "new_subdomain" in types
    new_sub = next(d for d in deltas if d["type"] == "new_subdomain")
    assert new_sub["value"] == "api.target.com"


def test_detect_delta_removed_subdomain():
    prev = _snap(subdomains=["target.com", "old.target.com"])
    curr = {"subdomains": ["target.com"], "open_ports": {}, "endpoints": []}
    deltas = _detect_delta(prev, curr)
    removed = [d for d in deltas if d["type"] == "removed_subdomain"]
    assert len(removed) == 1
    assert removed[0]["value"] == "old.target.com"


def test_detect_delta_no_subdomain_change():
    prev = _snap(subdomains=["target.com"])
    curr = {"subdomains": ["target.com"], "open_ports": {}, "endpoints": []}
    deltas = _detect_delta(prev, curr)
    assert not any(d["type"] in ("new_subdomain", "removed_subdomain") for d in deltas)


def test_detect_delta_both_added_and_removed():
    prev = _snap(subdomains=["a.target.com", "b.target.com"])
    curr = {"subdomains": ["a.target.com", "c.target.com"], "open_ports": {}, "endpoints": []}
    deltas = _detect_delta(prev, curr)
    added = [d for d in deltas if d["type"] == "new_subdomain"]
    removed = [d for d in deltas if d["type"] == "removed_subdomain"]
    assert any(d["value"] == "c.target.com" for d in added)
    assert any(d["value"] == "b.target.com" for d in removed)


# ── Port deltas ───────────────────────────────────────────────────────────────

def test_detect_delta_new_port():
    prev = _snap(open_ports={"target.com": [80]})
    curr = {"subdomains": [], "open_ports": {"target.com": [80, 443]}, "endpoints": []}
    deltas = _detect_delta(prev, curr)
    port_deltas = [d for d in deltas if d["type"] == "new_port"]
    assert len(port_deltas) == 1
    assert port_deltas[0]["host"] == "target.com"
    assert port_deltas[0]["port"] == 443


def test_detect_delta_no_port_change():
    prev = _snap(open_ports={"target.com": [80, 443]})
    curr = {"subdomains": [], "open_ports": {"target.com": [80, 443]}, "endpoints": []}
    deltas = _detect_delta(prev, curr)
    assert not any(d["type"] == "new_port" for d in deltas)


def test_detect_delta_port_on_new_host():
    prev = _snap(open_ports={})
    curr = {"subdomains": [], "open_ports": {"new.target.com": [22]}, "endpoints": []}
    deltas = _detect_delta(prev, curr)
    port_deltas = [d for d in deltas if d["type"] == "new_port"]
    assert len(port_deltas) == 1
    assert port_deltas[0]["host"] == "new.target.com"
    assert port_deltas[0]["port"] == 22


# ── Endpoint deltas ───────────────────────────────────────────────────────────

def test_detect_delta_new_endpoint():
    prev = _snap(endpoints=["https://target.com/"])
    curr = {"subdomains": [], "open_ports": {}, "endpoints": ["https://target.com/", "https://target.com/api"]}
    deltas = _detect_delta(prev, curr)
    ep_deltas = [d for d in deltas if d["type"] == "new_endpoint"]
    assert len(ep_deltas) == 1
    assert ep_deltas[0]["value"] == "https://target.com/api"


def test_detect_delta_no_endpoint_change():
    prev = _snap(endpoints=["https://target.com/"])
    curr = {"subdomains": [], "open_ports": {}, "endpoints": ["https://target.com/"]}
    deltas = _detect_delta(prev, curr)
    assert not any(d["type"] == "new_endpoint" for d in deltas)


# ── Empty baseline (first scan) ───────────────────────────────────────────────

def test_detect_delta_from_empty_baseline():
    prev = _snap()
    curr = {
        "subdomains": ["api.target.com"],
        "open_ports": {"api.target.com": [443]},
        "endpoints": ["https://api.target.com/v1"],
    }
    deltas = _detect_delta(prev, curr)
    types = {d["type"] for d in deltas}
    assert "new_subdomain" in types
    assert "new_port" in types
    assert "new_endpoint" in types


def test_detect_delta_all_empty():
    prev = _snap()
    curr = {"subdomains": [], "open_ports": {}, "endpoints": []}
    assert _detect_delta(prev, curr) == []


# ── None fields in prev snapshot ─────────────────────────────────────────────

def test_detect_delta_handles_none_subdomains_in_prev():
    prev = _snap(subdomains=None)
    curr = {"subdomains": ["new.target.com"], "open_ports": {}, "endpoints": []}
    deltas = _detect_delta(prev, curr)
    assert any(d["type"] == "new_subdomain" for d in deltas)


def test_detect_delta_handles_none_ports_in_prev():
    prev = _snap(open_ports=None)
    curr = {"subdomains": [], "open_ports": {"target.com": [80]}, "endpoints": []}
    deltas = _detect_delta(prev, curr)
    assert any(d["type"] == "new_port" for d in deltas)
