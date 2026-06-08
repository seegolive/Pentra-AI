"""Tests for Attack Playbooks — Task 15.3"""

import pytest

from pentra_agent.playbooks import (
    PLAYBOOKS,
    get_playbook_for_context,
    run_playbook,
)
from pentra_agent.playbooks.base import PlaybookResult


def test_get_playbook_sqli_for_aspnet_id_param():
    """sqli_error playbook harus dipilih untuk ASP.NET dengan ?id= parameter."""
    results = get_playbook_for_context(
        tech_stack=["asp.net", "mssql"],
        url="http://testaspnet.vulnweb.com/listproducts.aspx",
        param="id",
    )
    assert len(results) > 0
    vuln_classes = [p.vuln_class for p in results]
    assert "SQL_INJECTION" in vuln_classes
    # sqli should be first (highest score) for asp.net + ?id=
    assert results[0].vuln_class == "SQL_INJECTION"


def test_get_playbook_xss_for_search_param():
    """xss_reflected playbook harus dipilih untuk URL dengan ?search= parameter."""
    results = get_playbook_for_context(
        tech_stack=["php"],
        url="http://example.com/search.php",
        param="search",
    )
    assert len(results) > 0
    vuln_classes = [p.vuln_class for p in results]
    assert "XSS" in vuln_classes


def test_get_playbook_empty_for_unknown_context():
    """Tidak ada playbook yang dipilih jika tech stack dan URL tidak match."""
    results = get_playbook_for_context(
        tech_stack=["cobol"],
        url="http://example.com/home",
        param="page",
    )
    assert results == []


def test_run_playbook_returns_result_with_steps():
    """run_playbook harus mengembalikan PlaybookResult dengan steps_executed > 0."""
    playbook = PLAYBOOKS["sqli_error"]
    result = run_playbook(
        playbook=playbook,
        url="http://testaspnet.vulnweb.com/listproducts.aspx",
        param="id",
        tech_stack=["asp.net", "mssql"],
    )

    assert isinstance(result, PlaybookResult)
    assert result.playbook_name == "SQL Injection — Error Based"
    assert result.steps_executed > 0
    # run_playbook is a planning function — no findings yet
    assert result.confirmed_findings == []
    # Notes should mention the playbook name
    assert any("SQL Injection" in note for note in result.notes)
