"""Vuln testing modules."""

from pentra_tools.vuln.soap_xxe import SoapXxeScanner, XxeFinding, WsdlEndpoint, scan_soap_xxe
from pentra_tools.vuln.graphql_analyzer import (
    GraphQLFinding,
    analyze_graphql_endpoint,
    detect_graphql_endpoints,
    extract_schema,
    parse_schema,
)
from pentra_tools.vuln.race_condition import (
    RaceResult,
    identify_race_candidates,
    check_race_condition,
)
from pentra_tools.vuln.cors_tester import check_cors, scan_cors_on_endpoints
from pentra_tools.vuln.jwt_tester import (
    decode_jwt,
    forge_none_algorithm,
    forge_role_escalation,
    test_jwt_vulnerabilities,
)
from pentra_tools.vuln.second_order_sqli import (
    SecondOrderFinding,
    run_second_order_sqli_test,
)
from pentra_tools.vuln.business_logic import (
    BizLogicFinding,
    run_business_logic_test,
)
from pentra_tools.vuln.ssrf_oob_tester import (
    SsrfFinding,
    identify_ssrf_candidates,
    check_ssrf,
    scan_ssrf_on_endpoints,
)

__all__ = [
    "SoapXxeScanner", "XxeFinding", "WsdlEndpoint", "scan_soap_xxe",
    "GraphQLFinding", "analyze_graphql_endpoint", "detect_graphql_endpoints",
    "extract_schema", "parse_schema",
    "RaceResult", "identify_race_candidates", "check_race_condition",
    "check_cors", "scan_cors_on_endpoints",
    "decode_jwt", "forge_none_algorithm", "forge_role_escalation", "test_jwt_vulnerabilities",
    "SecondOrderFinding", "run_second_order_sqli_test",
    "BizLogicFinding", "run_business_logic_test",
    "SsrfFinding", "identify_ssrf_candidates", "check_ssrf", "scan_ssrf_on_endpoints",
]
