---
applyTo: "packages/pentra-knowledge/**,apps/worker/tasks/knowledge_update.py"
---

# Knowledge Engine — Copilot Instructions

You are working inside `packages/pentra-knowledge/` — the most critical Phase 1 component.

## What This Package Does

Ingests, processes, embeds, and serves knowledge from real-world bug bounty reports
(HackerOne, Bugcrowd, writeups) to power RAG-based technique suggestions for agents.

## Key Responsibilities

1. **Ingestion** — parse raw H1 CSV / GraphQL / user uploads into `KnowledgeRecord`
2. **LLM Extraction** — use `settings.OLLAMA_MODEL_FAST` (qwen2.5-coder:7b) to extract
   `key_insight`, `attack_technique`, `indicators`, `prerequisites` from raw text
3. **Embedding** — BGE-M3 via Ollama → store dense + sparse vectors in Qdrant
4. **Hybrid Search** — semantic (dense cosine) + lexical (sparse SPLADE) + metadata filter
5. **REST API** — expose `GET /knowledge/search`, `GET /knowledge/{id}`, `POST /knowledge/inject`

## Qdrant Collection Config

```python
COLLECTION_NAME = "knowledge"
DENSE_DIM = 1024          # BGE-M3 output dimension
DISTANCE = Distance.COSINE
```

## KnowledgeRecord Fields — Must All Be Populated

Critical fields that MUST be extracted (either from source or via LLM):
- `vuln_class` (use `VulnClass` enum from `pentra-shared`)
- `tech_stack` (list of strings: ["Ruby on Rails", "PostgreSQL"])
- `attack_technique` (1–3 sentence summary of HOW the bug was found)
- `key_insight` (the "aha moment" — what made this bug non-obvious)
- `indicators` (signals that suggest this bug class: ["numeric ID in URL path"])
- `what_tools_missed` (why Burp/Nuclei didn't catch it)

## Seed Data Format (reddelexc CSV)

```csv
id,title,severity,bounty,program,url,disclosed_at,type
1234567,"IDOR on /api/users","High",5000,"Shopify","https://hackerone.com/reports/1234567","2023-01-15","IDOR"
```

Map CSV columns to `KnowledgeRecord` fields.
Use LLM to fill in fields not available in CSV (attack_technique, key_insight, etc.).
Process in batches of 50 to avoid Ollama timeout.

## H1 GraphQL Scraper Pattern

```python
H1_GRAPHQL_URL = "https://hackerone.com/graphql"

HACKTIVITY_QUERY = """
query HacktivityQuery($cursor: String) {
  hacktivity(
    querystring: "disclosed:true"
    first: 25
    after: $cursor
    order_by: {field: latest_disclosable_activity_at, direction: DESC}
  ) {
    edges {
      node {
        ... on HackerOneActivity {
          id
          title
          severity { rating }
          bounty_amount
          disclosed_at
          report {
            vulnerability_information
          }
          team { name }
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""
```

## Search Query Building

When building search queries from agent context, combine:
1. Tech stack terms: "Ruby on Rails REST API"
2. Endpoint pattern: "/api/v1/users/{id}"
3. Observed behavior: "numeric ID in URL path, authenticated endpoint"

Keep queries under 512 tokens for BGE-M3 context window efficiency.
