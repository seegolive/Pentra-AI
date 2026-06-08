# packages/pentra-agent/pentra_agent/playbooks/base.py

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)


@dataclass
class PlaybookStep:
    name: str
    action: Literal[
        "probe_reflection",   # Check if input is reflected in response
        "error_based_probe",  # Check for syntax error in response
        "boolean_probe",      # Boolean-based test
        "time_based_probe",   # Time-delay based test
        "oob_probe",          # Out-of-band via Collaborator
        "boundary_probe",     # Boundary/overflow test
        "traverse_probe",     # Path traversal test
        "idor_probe",         # Object reference manipulation
        "confirm_with_burp",  # Send to Burp Repeater
        "manual_review",      # Flag for manual review
    ]
    payload_template: str    # Template payload; {MARKER} = injection point
    detect_pattern: str      # Regex or string for success detection
    description: str
    is_destructive: bool = False
    requires_burp: bool = False


@dataclass
class Playbook:
    name: str
    vuln_class: str
    description: str
    steps: list[PlaybookStep]
    tech_stack_hints: list[str]  # Relevant tech stack keywords
    url_patterns: list[str]      # URL pattern hints (e.g., "?id=", "?cat=")
    priority: int = 5            # 1=highest, 10=lowest


@dataclass
class PlaybookResult:
    playbook_name: str
    steps_executed: int
    steps_confirmed: int
    confirmed_findings: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def run_playbook(
    playbook: Playbook,
    url: str,
    param: str,
    tech_stack: list[str],
) -> PlaybookResult:
    """Return a PlaybookResult describing which steps are applicable.

    This is a *planning* function — it does not send HTTP requests.
    It annotates the result with which steps are safe/applicable so the
    caller (vuln_hunt_node) can inject those into its testing pipeline.

    Steps requiring Burp are included only as notes when Burp is unavailable.
    Non-destructive steps are always included.
    """
    applicable_steps = [s for s in playbook.steps if not s.is_destructive]
    burp_only = [s for s in playbook.steps if s.requires_burp]

    notes = [
        f"Playbook '{playbook.name}' matched for {url}?{param}",
        f"Applicable steps: {[s.name for s in applicable_steps]}",
    ]
    if burp_only:
        notes.append(
            f"Burp-required steps (skipped if Burp unavailable): "
            f"{[s.name for s in burp_only]}"
        )

    log.info(
        "[playbook] %s → %d steps for %s[%s]",
        playbook.name,
        len(applicable_steps),
        url,
        param,
    )

    return PlaybookResult(
        playbook_name=playbook.name,
        steps_executed=len(applicable_steps),
        steps_confirmed=0,
        confirmed_findings=[],
        notes=notes,
    )
