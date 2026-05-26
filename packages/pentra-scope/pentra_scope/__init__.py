"""pentra-scope — Scope enforcer for Pentra AI.

Every tool call and agent action MUST pass through ScopeEnforcer before execution.
"""

from pentra_scope.errors import ScopeViolationError
from pentra_scope.validator import ScopeEnforcer

__all__ = ["ScopeEnforcer", "ScopeViolationError"]
