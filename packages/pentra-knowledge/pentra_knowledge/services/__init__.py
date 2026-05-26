# Consumers should import directly from submodules:
#   from pentra_knowledge.services.embedding import embed
#   from pentra_knowledge.services.search import hybrid_search
#
# Eager imports are intentionally omitted to avoid requiring qdrant-client
# and httpx when only the config or ORM models are needed.
