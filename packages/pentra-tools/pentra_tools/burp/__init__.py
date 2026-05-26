"""pentra_tools.burp — Burp Suite MCP integration."""

from pentra_tools.burp.client import BurpMCPClient
from pentra_tools.burp.exceptions import (
    BurpConnectionError,
    BurpMCPToolError,
    BurpNotProError,
    BurpScanError,
)
from pentra_tools.burp.models import (
    CollaboratorInteraction,
    CollaboratorPayload,
    HttpRequest,
    ProxyEntry,
    RepeaterTab,
    ScanIssue,
    ScanTask,
    SitemapEntry,
)

__all__ = [
    # Client
    "BurpMCPClient",
    # Exceptions
    "BurpConnectionError",
    "BurpMCPToolError",
    "BurpNotProError",
    "BurpScanError",
    # Models
    "CollaboratorInteraction",
    "CollaboratorPayload",
    "HttpRequest",
    "ProxyEntry",
    "RepeaterTab",
    "ScanIssue",
    "ScanTask",
    "SitemapEntry",
]
