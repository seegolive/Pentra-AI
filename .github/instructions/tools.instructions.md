---
applyTo: "packages/pentra-tools/**,packages/pentra-scope/**"
---

# Tool Integration Layer — Copilot Instructions

## pentra-scope — First Line of Defense

`ScopeEnforcer` must be imported and called at the START of every tool wrapper.

```python
from pentra_scope import ScopeEnforcer, ScopeViolationError

class AnyToolWrapper:
    def __init__(self, scope_enforcer: ScopeEnforcer):
        self.scope = scope_enforcer  # injected, not instantiated here

    async def run(self, target: str, **kwargs):
        self.scope.validate_or_raise(target)  # FIRST LINE ALWAYS
        # ... rest of implementation
```

## Tool Output — Always Structured

Every tool wrapper returns `ToolResult`:
```python
@dataclass
class ToolResult:
    tool: str
    success: bool
    data: Any                  # Parsed structured output
    raw: str                   # Raw stdout for LLM if needed
    error: str | None
    duration_seconds: float
    target: str
    command: list[str]         # Exact command executed (for audit log)
```

## Burp MCP — Connection Details

```python
# Default Burp MCP server config (PortSwigger official extension)
BURP_MCP_HOST = "host.docker.internal"  # Burp runs on host, not in Docker
BURP_MCP_PORT = 9876
BURP_MCP_BASE_URL = f"http://{BURP_MCP_HOST}:{BURP_MCP_PORT}"

# MCP uses SSE transport — use httpx with SSE support
# Reference: https://github.com/PortSwigger/mcp-server
```

## Rate Limiting

All tool wrappers must respect rate limits to avoid accidental DoS:
```python
from pentra_tools.base import RateLimiter

# Inject rate limiter — different tools have different limits
class NmapWrapper(AsyncToolWrapper):
    rate_limiter = RateLimiter(max_calls=10, period=60)  # 10 scans/minute
    timeout = 600  # 10 minutes max

class FfufWrapper(AsyncToolWrapper):
    rate_limiter = RateLimiter(max_calls=5, period=60)
    timeout = 300
```

## Streaming Output to WebSocket

Tools with long-running output (nmap, ffuf) should stream lines to the Live Feed:
```python
async def _exec_stream(
    self,
    cmd: list[str],
    on_line: Callable[[str], Awaitable[None]] | None = None,
    timeout: int = 300,
) -> tuple[str, str, int]:
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    # Stream stdout lines
    lines = []
    async for line in process.stdout:
        decoded = line.decode().strip()
        lines.append(decoded)
        if on_line:
            await on_line(decoded)  # → WebSocket broadcast
    ...
```
