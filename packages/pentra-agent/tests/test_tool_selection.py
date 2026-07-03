from __future__ import annotations


def test_graphql_enabled_when_graphql_in_tech_stack():
    from pentra_agent.nodes.vuln_hunt_node import _select_tools_for_tech_stack
    flags = _select_tools_for_tech_stack(["graphql", "react"], {})
    assert flags["run_graphql"] is True


def test_graphql_disabled_when_no_graphql_tech():
    from pentra_agent.nodes.vuln_hunt_node import _select_tools_for_tech_stack
    flags = _select_tools_for_tech_stack(["php", "mysql", "nginx"], {})
    assert flags["run_graphql"] is False


def test_soap_enabled_when_soap_in_tech_stack():
    from pentra_agent.nodes.vuln_hunt_node import _select_tools_for_tech_stack
    flags = _select_tools_for_tech_stack(["java", "soap", "tomcat"], {})
    assert flags["run_soap_xxe"] is True


def test_soap_disabled_when_no_soap_tech():
    from pentra_agent.nodes.vuln_hunt_node import _select_tools_for_tech_stack
    flags = _select_tools_for_tech_stack(["nodejs", "express", "mongodb"], {})
    assert flags["run_soap_xxe"] is False


def test_jwt_enabled_for_api_tech_stack():
    from pentra_agent.nodes.vuln_hunt_node import _select_tools_for_tech_stack
    flags = _select_tools_for_tech_stack(["fastapi", "python"], {})
    assert flags["run_jwt"] is True


def test_second_order_enabled_for_sql_tech():
    from pentra_agent.nodes.vuln_hunt_node import _select_tools_for_tech_stack
    flags = _select_tools_for_tech_stack(["php", "mysql"], {})
    assert flags["run_second_order"] is True


def test_second_order_disabled_for_nosql_stack():
    from pentra_agent.nodes.vuln_hunt_node import _select_tools_for_tech_stack
    flags = _select_tools_for_tech_stack(["nodejs", "mongodb", "redis"], {})
    assert flags["run_second_order"] is False


def test_biz_logic_always_enabled():
    from pentra_agent.nodes.vuln_hunt_node import _select_tools_for_tech_stack
    flags = _select_tools_for_tech_stack(["anything"], {})
    assert flags["run_biz_logic"] is True


def test_tool_config_override_disables_graphql():
    from pentra_agent.nodes.vuln_hunt_node import _select_tools_for_tech_stack
    flags = _select_tools_for_tech_stack(["graphql", "apollo"], {"run_graphql": False})
    assert flags["run_graphql"] is False


def test_tool_config_override_enables_soap_without_soap_tech():
    from pentra_agent.nodes.vuln_hunt_node import _select_tools_for_tech_stack
    flags = _select_tools_for_tech_stack(["nodejs", "express"], {"run_soap_xxe": True})
    assert flags["run_soap_xxe"] is True


def test_empty_tech_stack_defaults_all_true():
    from pentra_agent.nodes.vuln_hunt_node import _select_tools_for_tech_stack
    flags = _select_tools_for_tech_stack([], {})
    assert all(flags.values())
