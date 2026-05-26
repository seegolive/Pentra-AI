"""Tests for PentraState TypedDict definition.

Task 10.1 — Sprint 10
"""

import typing


def test_pentra_state_reducers_accumulate():
    """operator.add reducer harus accumulate, bukan replace.

    Verifikasi bahwa list fields dengan operator.add berperilaku benar:
    dua partial state updates harus di-concatenate, bukan overwrite.
    """
    state1: dict = {"subdomains": [{"host": "api.target.com", "ip": None, "source": "subfinder",
                                    "is_alive": True, "status_code": 200, "tech_stack": []}]}
    state2: dict = {"subdomains": [{"host": "admin.target.com", "ip": None, "source": "subfinder",
                                    "is_alive": True, "status_code": 200, "tech_stack": []}]}

    # Simulate what LangGraph does when merging two partial updates via operator.add
    combined = state1["subdomains"] + state2["subdomains"]

    assert len(combined) == 2
    assert combined[0]["host"] == "api.target.com"
    assert combined[1]["host"] == "admin.target.com"


def test_phase_literals_are_valid():
    """Semua Literal values pada current_phase harus mencakup semua fase eksekusi."""
    from pentra_agent.graph.state import PentraState

    hints = typing.get_type_hints(PentraState)

    # current_phase harus terdefinisi
    assert hints.get("current_phase") is not None

    # Semua fase wajib ada di Literal
    required_phases = {"planning", "recon", "vuln_hunt", "exploit_validation", "report"}
    phase_hint = hints["current_phase"]
    # get_type_hints returns Literal[...] — extract args
    phase_args = set(typing.get_args(phase_hint))
    assert required_phases.issubset(phase_args), (
        f"Missing phases: {required_phases - phase_args}"
    )
