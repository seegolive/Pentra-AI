"""Fine-tuning Dataset Exporter — Task 18.14 (xOffense pattern).

Exports confirmed findings as JSONL training data for LLM fine-tuning.
Each record is a (prompt, completion) pair representing the ReAct thought
process that led to a confirmed finding.

Output format: OpenAI chat fine-tuning JSONL
  {"messages": [
    {"role": "system", "content": "<pentest system prompt>"},
    {"role": "user", "content": "<observation with URL/param/baseline>"},
    {"role": "assistant", "content": "<thought + action that confirmed finding>"}
  ]}

Usage:
    exporter = FineTuneExporter(output_path="/tmp/pentra_finetune.jsonl")
    exporter.add_finding(
        finding=confirmed_finding_dict,
        observation=react_observation_text,
        thought=react_thought_text,
        action="test_injection",
    )
    exporter.save()

    # Or export from a completed scan state:
    exporter.export_from_state(state_dict, memory)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are an expert penetration tester using the ReAct (Reason+Act) framework. "
    "You analyze web application HTTP traffic to identify and confirm vulnerabilities. "
    "For each step, output:\n"
    "Thought: [Your reasoning about the current situation]\n"
    "Action: [test_injection or skip_candidate]\n"
    "Action Input: [JSON parameters for the action]"
)


@dataclass
class FineTuneRecord:
    """A single training record for LLM fine-tuning."""
    vuln_class: str
    severity: str
    url: str
    param: str
    payload: str
    thought: str
    action: str
    observation: str
    tech_stack: list[str] = field(default_factory=list)
    engagement_id: str = ""

    def to_chat_jsonl(self) -> dict:
        """Convert to OpenAI chat fine-tuning format."""
        user_content = self.observation or (
            f"URL: {self.url}\nParameter: {self.param}\n"
            f"Tech stack: {', '.join(self.tech_stack)}\n"
            f"Vulnerability type to test: {self.vuln_class}"
        )
        assistant_content = (
            f"Thought: {self.thought}\n"
            f"Action: {self.action}\n"
            f"Action Input: {{\"url\": {self.url!r}, \"param\": {self.param!r}, "
            f"\"payload\": {self.payload!r}}}"
        )
        return {
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
                {"role": "assistant", "content": assistant_content},
            ],
            "_metadata": {
                "vuln_class": self.vuln_class,
                "severity": self.severity,
                "url": self.url,
                "param": self.param,
                "payload": self.payload,
                "engagement_id": self.engagement_id,
            }
        }


class FineTuneExporter:
    """Accumulates and exports fine-tuning records from confirmed findings."""

    def __init__(self, output_path: str = "/tmp/pentra_finetune.jsonl") -> None:
        self.output_path = output_path
        self._records: list[FineTuneRecord] = []

    def add_finding(
        self,
        finding: dict,
        observation: str = "",
        thought: str = "",
        action: str = "test_injection",
        tech_stack: list[str] | None = None,
    ) -> None:
        """Add a confirmed finding as a training record.

        Args:
            finding:     The confirmed finding dict from vuln_hunt_node.
            observation: The full ReAct observation text (URL + baseline snippet).
            thought:     The LLM's reasoning that preceded the confirmed action.
            action:      The action taken (default: "test_injection").
            tech_stack:  Tech stack for this target.
        """
        if not finding.get("payload"):
            return  # only export findings with confirmed payloads

        record = FineTuneRecord(
            vuln_class=finding.get("vuln_class", ""),
            severity=finding.get("severity", ""),
            url=finding.get("target_url", ""),
            param=finding.get("param_name", ""),
            payload=finding.get("payload", ""),
            thought=thought,
            action=action,
            observation=observation[:2000] if observation else "",
            tech_stack=tech_stack or [],
            engagement_id=finding.get("engagement_id", ""),
        )
        self._records.append(record)
        log.debug("[finetune] Added record: %s @ %s[%s]", record.vuln_class, record.url, record.param)

    def export_from_state(self, state: dict, memory: Any | None = None) -> int:
        """Extract training records from a completed scan state.

        Args:
            state:  The final PentraState dict after vuln_hunt_node.
            memory: Optional LocatedMemory instance (provides react history).

        Returns:
            Number of records added.
        """
        added = 0
        findings = state.get("findings", [])
        tech_stack = state.get("tech_stack", [])
        engagement_id = state.get("engagement_id", "")

        # Get react history from memory if available
        react_steps: dict[tuple[str, str], dict] = {}
        if memory and hasattr(memory, "react_history"):
            for step in memory.react_history:
                key = (step.get("url", ""), step.get("param", ""))
                react_steps[key] = step

        for finding in findings:
            url = finding.get("target_url", "")
            param = finding.get("param_name", "")
            payload = finding.get("payload", "")
            if not (url and param and payload):
                continue

            step = react_steps.get((url, param), {})
            thought = step.get("thought", f"The {param} parameter is likely vulnerable to {finding.get('vuln_class', '?')}.")

            enriched_finding = {**finding, "engagement_id": engagement_id}
            self.add_finding(
                finding=enriched_finding,
                thought=thought,
                tech_stack=tech_stack,
            )
            added += 1

        log.info("[finetune] Extracted %d training records from state", added)
        return added

    def save(self, append: bool = True) -> int:
        """Write records to JSONL file.

        Args:
            append:  If True, append to existing file. If False, overwrite.

        Returns:
            Number of records written.
        """
        if not self._records:
            return 0

        mode = "a" if append and os.path.exists(self.output_path) else "w"
        try:
            with open(self.output_path, mode) as f:
                for record in self._records:
                    line = json.dumps(record.to_chat_jsonl(), ensure_ascii=False)
                    f.write(line + "\n")
            log.info(
                "[finetune] Saved %d records to %s (mode=%s)",
                len(self._records), self.output_path, mode,
            )
            written = len(self._records)
            self._records.clear()
            return written
        except OSError as exc:
            log.error("[finetune] Failed to save: %s", exc)
            return 0

    @property
    def pending_count(self) -> int:
        return len(self._records)

    @staticmethod
    def count_records(path: str) -> int:
        """Count records in an existing JSONL file."""
        try:
            with open(path) as f:
                return sum(1 for line in f if line.strip())
        except OSError:
            return 0
