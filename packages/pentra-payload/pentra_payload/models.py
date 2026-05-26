"""Pydantic models for payload generation context and results."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from pentra_shared.types.vuln_class import VulnClass


class PayloadContext(BaseModel):
    """Context describing the target parameter and vulnerability being tested."""

    vuln_class: VulnClass
    tech_stack: list[str] = Field(default_factory=list)
    target_url: str
    parameter_name: str
    parameter_value: str = Field(description="Original/current value of the parameter")
    parameter_position: Literal["path", "query", "body", "header", "cookie"] = "query"
    http_method: str = "GET"
    additional_context: str = ""


class Payload(BaseModel):
    """A single generated test payload."""

    value: str = Field(description="The payload string to inject")
    rationale: str = Field(description="Why this payload might work in this context")
    severity_hint: Literal["critical", "high", "medium", "low", "info"] = "medium"
    requires_encoding: bool = False


class PayloadGenerateRequest(BaseModel):
    """API request schema for payload generation."""

    context: PayloadContext
    count: int = Field(default=10, ge=1, le=50)
    knowledge_ids: list[str] = Field(
        default_factory=list,
        description="Optional: specific knowledge record IDs to include as context",
    )


class PayloadGenerateResponse(BaseModel):
    """API response schema for payload generation."""

    payloads: list[Payload]
    knowledge_used: int = Field(description="Number of KB records used as context")
    model_used: str
