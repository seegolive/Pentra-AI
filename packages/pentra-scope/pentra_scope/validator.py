"""ScopeEnforcer — validates every agent action against the engagement scope.

Supports:
  - Exact domain match:      "target.com"
  - Wildcard subdomain:      "*.target.com"
  - IPv4 / IPv6 exact:       "203.0.113.5"
  - CIDR range:              "10.0.0.0/8"
  - URL inputs (scheme stripped before matching)
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from pentra_scope.errors import ScopeViolationError


class ScopeEnforcer:
    """Thread-safe, stateless scope validator.

    Usage::

        enforcer = ScopeEnforcer(
            in_scope=["target.com", "*.api.target.com", "10.0.0.0/8"],
            out_of_scope=["admin.target.com"],
        )
        enforcer.validate_or_raise("api.target.com")       # OK
        enforcer.validate_or_raise("admin.target.com")     # raises ScopeViolationError
        enforcer.validate_or_raise("https://target.com/x") # OK — URL stripped
    """

    def __init__(
        self,
        in_scope: list[str],
        out_of_scope: list[str] | None = None,
    ) -> None:
        self._in_scope = [s.strip().lower() for s in in_scope]
        self._out_of_scope = [s.strip().lower() for s in (out_of_scope or [])]

    # ── Public API ────────────────────────────────────────────────────────

    def validate_or_raise(self, target: str) -> None:
        """Raise ScopeViolationError if *target* is not permitted."""
        host = self._extract_host(target)
        if not self.is_allowed(host):
            raise ScopeViolationError(
                f"Target '{host}' is outside engagement scope. "
                f"Allowed: {self._in_scope}",
                target=host,
            )

    def is_allowed(self, target: str) -> bool:
        """Return True if *target* is in scope and not explicitly excluded."""
        host = self._extract_host(target).lower()

        # Explicit exclusion takes priority
        if any(self._matches(host, rule) for rule in self._out_of_scope):
            return False

        return any(self._matches(host, rule) for rule in self._in_scope)

    # ── Private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _extract_host(target: str) -> str:
        """Strip URL scheme/path and return just the hostname or IP."""
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or target
        else:
            # May still have a path like "target.com/api"
            host = target.split("/")[0]
        # Remove port if present
        host = re.sub(r":\d+$", "", host)
        return host.lower()

    @staticmethod
    def _matches(host: str, rule: str) -> bool:
        """Return True if *host* matches *rule*.

        Rule formats:
          * "target.com"        — exact domain or reverse-DNS match
          * "*.target.com"      — any subdomain of target.com
          * "target.com/*"      — treated as domain only (path ignored)
          * "203.0.113.5"       — exact IPv4/IPv6
          * "10.0.0.0/8"        — CIDR
        """
        # Strip path for domain rules, but preserve CIDR notation (e.g. 10.0.0.0/8)
        if "/" in rule and ":" not in rule and not _is_cidr(rule):
            rule = rule.split("/")[0]

        # CIDR check
        if _is_cidr(rule):
            try:
                return ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False)
            except ValueError:
                return False

        # Wildcard subdomain: *.target.com
        if rule.startswith("*."):
            parent = rule[2:]
            return host == parent or host.endswith("." + parent)

        # Exact match
        return host == rule


def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False
