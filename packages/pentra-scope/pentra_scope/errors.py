"""ScopeViolationError — raised when a target is outside engagement scope."""

from __future__ import annotations


class ScopeViolationError(Exception):
    """Raised when an action targets a host/IP outside the engagement scope."""

    def __init__(self, message: str, target: str | None = None) -> None:
        super().__init__(message)
        self.target = target
