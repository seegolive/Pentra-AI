# Consumers should import directly from submodules:
#   from pentra_knowledge.api.router import router
#   from pentra_knowledge.api.schemas import SearchRequest
#
# Eager imports are intentionally omitted to avoid requiring all runtime
# dependencies (qdrant-client, httpx, etc.) when only schemas are needed.
