"""pentra-shared — shared Pydantic models, enums, and constants for Pentra AI.

All packages in the monorepo should import shared types from here rather than
defining their own, to guarantee consistency across the API, agent, and knowledge
engine.

Quick start::

    from pentra_shared.types import VulnClass, Severity, KnowledgeRecord
    from pentra_shared.constants import KNOWLEDGE_SEARCH_DEFAULT_TOP_K
"""

__version__ = "0.1.0"
