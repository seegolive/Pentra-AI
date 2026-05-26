"""Exceptions raised by the Burp Suite MCP client."""

from __future__ import annotations


class BurpConnectionError(Exception):
    """Burp Suite MCP server is not reachable or refused the connection.

    This is raised when the SSE connection to the MCP server cannot be
    established. Common causes:
      - Burp Suite is not running
      - The MCP extension is not loaded / not enabled
      - Wrong port configured (default: 9876)
    """


class BurpMCPToolError(Exception):
    """A tool call to the Burp MCP server returned an error payload."""

    def __init__(self, tool: str, detail: str) -> None:
        self.tool = tool
        self.detail = detail
        super().__init__(f"Burp MCP tool '{tool}' failed: {detail}")


class BurpNotProError(Exception):
    """The requested feature requires Burp Suite Professional.

    Affected tools: get_scanner_issues, generate_collaborator_payload,
    get_collaborator_interactions.
    """

    def __init__(self, tool: str) -> None:
        self.tool = tool
        super().__init__(
            f"Tool '{tool}' requires Burp Suite Professional edition. "
            "Community edition does not include the Burp Scanner or Collaborator."
        )


class BurpScanError(Exception):
    """An active scan could not be triggered or failed unexpectedly."""
