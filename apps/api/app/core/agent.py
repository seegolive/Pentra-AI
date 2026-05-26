"""Agent service singleton — initialised at API startup."""

from __future__ import annotations

from pentra_agent.service import AgentService

_agent_service: AgentService | None = None


def init_agent_service(checkpointer=None) -> None:
    """Called once during FastAPI lifespan startup."""
    global _agent_service
    _agent_service = AgentService(checkpointer=checkpointer)


def get_agent_service() -> AgentService:
    if _agent_service is None:
        raise RuntimeError("AgentService not initialised — call init_agent_service() first")
    return _agent_service
