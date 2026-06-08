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

__all__ = [
    "SoapXxeScanner", "XxeFinding", "WsdlEndpoint", "scan_soap_xxe",
    "GraphQLFinding", "analyze_graphql_endpoint", "detect_graphql_endpoints",
    "extract_schema", "parse_schema",
    "RaceResult", "identify_race_candidates", "check_race_condition",
    "check_cors", "scan_cors_on_endpoints",
]
