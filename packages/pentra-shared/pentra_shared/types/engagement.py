from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

EngagementMode = Literal["semi_auto", "agentic"]
EngagementStatus = Literal[
    "planning",
    "active",
    "paused",
    "completed",
    "archived",
]


class Scope(BaseModel):
    """Defines the authorised target surface for an engagement."""

    model_config = ConfigDict(from_attributes=True)

    in_scope: list[str] = Field(
        description="Authorised targets: domains, IP addresses, CIDRs (e.g., 'target.com', '10.0.0.0/8')"
    )
    out_of_scope: list[str] = Field(
        default_factory=list,
        description="Explicitly excluded targets within the in-scope range",
    )


class Engagement(BaseModel):
    """An engagement represents a single pentest or bug-bounty session against a target.

    The LangGraph thread_id is derived from the engagement id so the agent state
    can always be resumed after a HITL pause.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    workspace_id: UUID
    name: str = Field(max_length=200)
    description: str | None = Field(default=None, max_length=2000)

    # ── Mode & Status ─────────────────────────────────────────────────────
    mode: EngagementMode = Field(default="semi_auto")
    status: EngagementStatus = Field(default="planning")

    # ── Scope ─────────────────────────────────────────────────────────────
    in_scope: list[str] = Field(
        description="Authorised targets (domains, IPs, CIDRs)"
    )
    out_of_scope: list[str] = Field(
        default_factory=list,
        description="Explicitly excluded sub-targets",
    )

    # ── LLM Configuration ─────────────────────────────────────────────────
    llm_model: str = Field(
        description="Ollama model tag selected for this engagement (e.g., 'qwen2.5-coder:32b')"
    )

    # ── LangGraph ─────────────────────────────────────────────────────────
    langgraph_thread_id: str = Field(
        description="LangGraph checkpoint thread ID — equals engagement ID as string"
    )

    # ── Lifecycle ─────────────────────────────────────────────────────────
    created_by: UUID = Field(description="User ID of the operator who created this engagement")
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @property
    def scope(self) -> Scope:
        """Return a Scope object for use with ScopeEnforcer."""
        return Scope(in_scope=self.in_scope, out_of_scope=self.out_of_scope)


class EngagementCreate(BaseModel):
    """Schema for creating a new engagement via the API."""

    model_config = ConfigDict(from_attributes=True)

    workspace_id: UUID
    name: str = Field(max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    mode: EngagementMode = Field(default="semi_auto")
    in_scope: list[str] = Field(min_length=1)
    out_of_scope: list[str] = Field(default_factory=list)
    llm_model: str = Field(
        default="qwen2.5-coder:32b",
        description="Ollama model tag to use for this engagement",
    )


class EngagementUpdate(BaseModel):
    """Schema for patching an existing engagement."""

    model_config = ConfigDict(from_attributes=True)

    name: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    mode: EngagementMode | None = None
    status: EngagementStatus | None = None
    in_scope: list[str] | None = None
    out_of_scope: list[str] | None = None
    llm_model: str | None = None


class EngagementResponse(Engagement):
    """API response schema — extends Engagement with computed fields."""

    finding_count: int = Field(default=0)
    open_finding_count: int = Field(default=0)
