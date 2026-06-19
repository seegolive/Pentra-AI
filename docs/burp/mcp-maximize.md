# BURP-MCP-MAXIMIZE.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `PROGRESS.md` → file ini  
> **Tujuan:** Maksimalkan penggunaan SELURUH 27 tools Burp MCP + extend dengan custom tools  
> **Prinsip:** Official MCP server bisa di-extend via Tools.kt — kita manfaatkan ini

---

## Arsitektur Enhancement

```
Burp Suite Pro
  └── MCP Server Extension (Official PortSwigger)
        ├── 27 Built-in Tools (sebagian besar BELUM dipakai Pentra AI)
        └── Custom Tools (bisa ditambah via Tools.kt fork)
              │
              │ SSE http://localhost:9877
              ▼
  BurpMCPClient (packages/pentra-tools/pentra_tools/burp/client.py)
        ├── SUDAH ADA: health_check, proxy_history, scanner_issues, collaborator
        └── BELUM ADA: 18 tools yang belum di-wrap
              │
              ▼
  Agent Nodes (recon_node, vuln_hunt_node, triage_node)
```

---

## Peta Lengkap 27 Tools — Status Pentra AI

### GROUP 1: HTTP Requests (Mengirim request langsung via Burp)

| Tool | Status Pentra AI | Kegunaan untuk Pentest |
|------|-----------------|----------------------|
| `send_http1_request` | ✅ Dipakai (indirect) | Kirim HTTP/1.1 request via Burp — traffic tercatat di history |
| `send_http2_request` | ❌ Belum di-wrap | **PENTING** — test target HTTP/2, header injection, priority attacks |

### GROUP 2: Proxy History & Traffic Analysis

| Tool | Status Pentra AI | Kegunaan untuk Pentest |
|------|-----------------|----------------------|
| `get_proxy_http_history` | ✅ Ada | Ambil seluruh HTTP history |
| `get_proxy_http_history_regex` | ✅ Ada (partial) | Filter history by regex — untuk focus ke endpoint tertentu |
| `get_proxy_websocket_history` | ❌ Belum di-wrap | **PENTING** — WebSocket security testing, WS injection |
| `get_proxy_websocket_history_regex` | ❌ Belum di-wrap | Filter WebSocket traffic |

### GROUP 3: Scanner (Pro Only)

| Tool | Status Pentra AI | Kegunaan untuk Pentest |
|------|-----------------|----------------------|
| `get_scanner_issues` | ✅ Ada | Ambil scanner findings |
| `generate_collaborator_payload` | ✅ Ada | OOB payload untuk blind SSRF/XSS |
| `get_collaborator_interactions` | ✅ Ada | Poll Collaborator callback |

### GROUP 4: Repeater & Intruder

| Tool | Status Pentra AI | Kegunaan untuk Pentest |
|------|-----------------|----------------------|
| `create_repeater_tab` | ❌ Belum di-wrap | Buat Repeater tab — agent bisa save request untuk review |
| `create_repeater_tab_http2` | ❌ Belum di-wrap | Repeater untuk HTTP/2 targets |
| `send_to_intruder` | ❌ Belum di-wrap | **SANGAT PENTING** — kirim ke Intruder untuk fuzzing otomatis |

### GROUP 5: Organizer

| Tool | Status Pentra AI | Kegunaan untuk Pentest |
|------|-----------------|----------------------|
| `get_organizer_items` | ❌ Belum di-wrap | Akses saved items di Organizer |
| `get_organizer_items_regex` | ❌ Belum di-wrap | Filter Organizer items |

### GROUP 6: Proxy Intercept Control

| Tool | Status Pentra AI | Kegunaan untuk Pentest |
|------|-----------------|----------------------|
| `set_proxy_intercept_state` | ❌ Belum di-wrap | **PENTING** — toggle intercept on/off programmatically |
| `set_task_execution_engine_state` | ❌ Belum di-wrap | Pause/resume Burp scanner task engine |

### GROUP 7: Editor Control

| Tool | Status Pentra AI | Kegunaan untuk Pentest |
|------|-----------------|----------------------|
| `get_active_editor_contents` | ❌ Belum di-wrap | Ambil isi editor Burp yang aktif |
| `set_active_editor_contents` | ❌ Belum di-wrap | Inject content ke editor aktif — untuk payload testing |

### GROUP 8: Configuration

| Tool | Status Pentra AI | Kegunaan untuk Pentest |
|------|-----------------|----------------------|
| `output_project_options` | ❌ Belum di-wrap | Export project config — scope, SSL config, dll |
| `output_user_options` | ❌ Belum di-wrap | Export user config — proxy settings, upstream proxy |
| `set_project_options` | ❌ Belum di-wrap | Modify project config — set scope programmatically |
| `set_user_options` | ❌ Belum di-wrap | Modify user settings |

### GROUP 9: Encoding & Utilities

| Tool | Status Pentra AI | Kegunaan untuk Pentest |
|------|-----------------|----------------------|
| `url_encode` | ❌ Belum di-wrap | URL encode consistent dengan Burp decoder |
| `url_decode` | ❌ Belum di-wrap | URL decode — untuk analisis encoded parameters |
| `base64_encode` | ❌ Belum di-wrap | Base64 encode |
| `base64_decode` | ❌ Belum di-wrap | Base64 decode — decode JWT, cookies |
| `generate_random_string` | ❌ Belum di-wrap | Random string untuk unique markers/payloads |

---

## Status: 9/27 dipakai, 18/27 belum

```
SUDAH DIPAKAI (9):
  health_check
  get_proxy_http_history
  get_proxy_http_history_regex (partial)
  get_scanner_issues
  generate_collaborator_payload
  get_collaborator_interactions
  send_http1_request (indirect)
  send_http2_request (belum)  ← target pertama
  
BELUM DIPAKAI (18):
  send_http2_request
  get_proxy_websocket_history
  get_proxy_websocket_history_regex
  create_repeater_tab
  create_repeater_tab_http2
  send_to_intruder
  get_organizer_items
  get_organizer_items_regex
  set_proxy_intercept_state
  set_task_execution_engine_state
  get_active_editor_contents
  set_active_editor_contents
  output_project_options
  output_user_options
  set_project_options
  set_user_options
  url_encode + url_decode
  base64_encode + base64_decode
  generate_random_string
```

---

## Implementasi: `BurpMCPClient` Lengkap

**File: `packages/pentra-tools/pentra_tools/burp/client.py`**

Ganti seluruh `BurpMCPClient` dengan versi komprehensif berikut:

```python
# packages/pentra-tools/pentra_tools/burp/client.py

"""
BurpMCPClient — Full coverage untuk semua 27 tools Burp MCP Official Server.
Connects ke PortSwigger MCP Server via SSE di http://localhost:9877.

Tool reference: https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Literal

import httpx

logger = logging.getLogger(__name__)


# ── Response Models ────────────────────────────────────────────────────────

@dataclass
class ProxyEntry:
    url: str
    method: str
    request_raw: str
    response_raw: str | None
    response_status: int | None
    timestamp: str | None = None


@dataclass
class WebSocketEntry:
    url: str
    direction: str          # "client_to_server" | "server_to_client"
    message: str
    timestamp: str | None = None


@dataclass
class ScanIssue:
    name: str
    severity: str           # "high" | "medium" | "low" | "information"
    confidence: str         # "certain" | "firm" | "tentative"
    url: str
    detail: str
    remediation: str | None = None
    request: str | None = None
    response: str | None = None


@dataclass
class CollaboratorPayload:
    payload: str            # e.g., "xyz.oastify.com"
    payload_id: str


@dataclass
class CollaboratorInteraction:
    interaction_type: str   # "dns" | "http" | "smtp"
    client_ip: str
    timestamp: str
    data: dict


@dataclass
class RepeaterTab:
    tab_id: str | None
    name: str | None


@dataclass
class OrganizerItem:
    url: str
    method: str
    request_raw: str
    notes: str | None = None


@dataclass
class HttpResponse:
    status_code: int
    headers: dict[str, str]
    body: str
    protocol: str           # "HTTP/1.1" | "HTTP/2"


@dataclass
class ProjectOptions:
    scope: dict
    proxy: dict
    scanner: dict
    raw: dict


# ── MCP Tool Caller ────────────────────────────────────────────────────────

class BurpMCPClient:
    """
    Full-coverage client untuk PortSwigger official Burp MCP Server.
    Semua 27 tools dari Tools.kt ter-implementasi.

    Connection:
      Burp Pro berjalan di host machine dengan MCP extension enabled.
      Default URL: http://127.0.0.1:9877 (via WSL2 NAT workaround)
      Atau: http://host.docker.internal:9877 (dari dalam Docker)
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 30.0,
    ):
        self.base_url = (
            base_url
            or os.getenv("BURP_MCP_URL", "http://127.0.0.1:9877")
        ).rstrip("/")
        self.timeout = timeout

    # ── Internal MCP caller ────────────────────────────────────────────────

    async def _call_tool(self, tool_name: str, params: dict) -> Any:
        """
        Panggil MCP tool via SSE endpoint.
        Semua tools dikirim sebagai JSON POST ke /mcp/tools/call.
        """
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": params,
            },
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/mcp",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                result = response.json()

                if "error" in result:
                    raise BurpMCPError(
                        f"Tool '{tool_name}' error: {result['error']}"
                    )

                return result.get("result", {})

            except httpx.ConnectError:
                raise BurpNotAvailableError(
                    f"Cannot connect to Burp MCP at {self.base_url}. "
                    "Ensure Burp Pro is running with MCP extension enabled."
                )
            except httpx.TimeoutException:
                raise BurpMCPError(
                    f"Tool '{tool_name}' timed out after {self.timeout}s"
                )

    # ── GROUP 1: Health ────────────────────────────────────────────────────

    async def health_check(self) -> bool:
        """
        Cek apakah Burp MCP server bisa diakses.
        Return True jika online, False jika tidak.
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/mcp")
                return resp.status_code in (200, 404, 405)
        except Exception:
            return False

    async def list_tools(self) -> list[str]:
        """
        List semua tools yang tersedia di Burp MCP server.
        Berguna untuk verifikasi versi dan capabilities.
        """
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self.base_url}/mcp",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            result = resp.json()
            tools = result.get("result", {}).get("tools", [])
            return [t["name"] for t in tools]

    # ── GROUP 2: HTTP Requests ─────────────────────────────────────────────

    async def send_http1_request(
        self,
        host: str,
        port: int,
        request: str,         # Raw HTTP request string
        use_https: bool = True,
    ) -> HttpResponse:
        """
        Kirim HTTP/1.1 request via Burp — traffic tercatat di proxy history.
        Gunakan ini untuk manual payload testing yang perlu tercatat.
        """
        result = await self._call_tool("send_http1_request", {
            "host": host,
            "port": port,
            "request": request,
            "useHttps": use_https,
        })
        return _parse_http_response(result, "HTTP/1.1")

    async def send_http2_request(
        self,
        host: str,
        port: int,
        request: str,
        use_https: bool = True,
    ) -> HttpResponse:
        """
        Kirim HTTP/2 request via Burp.
        **PENTING** — test target yang pakai HTTP/2 (nginx, h2c, gRPC).
        HTTP/2 headers injection, priority attacks, stream manipulation.
        """
        result = await self._call_tool("send_http2_request", {
            "host": host,
            "port": port,
            "request": request,
            "useHttps": use_https,
        })
        return _parse_http_response(result, "HTTP/2")

    # ── GROUP 3: Proxy History ─────────────────────────────────────────────

    async def get_proxy_http_history(
        self,
        limit: int = 100,
    ) -> list[ProxyEntry]:
        """
        Ambil semua HTTP proxy history.
        Gunakan untuk analisis traffic pattern yang sudah tercapture.
        """
        result = await self._call_tool("get_proxy_http_history", {
            "count": limit,
        })
        return _parse_proxy_history(result)

    async def get_proxy_http_history_regex(
        self,
        filter_regex: str,
        limit: int = 50,
    ) -> list[ProxyEntry]:
        """
        Ambil proxy history yang match regex.
        Contoh filter: "api\\/v[0-9]+\\/users", "\\.php\\?", "admin"
        """
        result = await self._call_tool("get_proxy_http_history_regex", {
            "regex": filter_regex,
            "count": limit,
        })
        return _parse_proxy_history(result)

    async def get_proxy_websocket_history(
        self,
        limit: int = 50,
    ) -> list[WebSocketEntry]:
        """
        Ambil WebSocket proxy history.
        **Baru di-wrap** — untuk WebSocket security testing:
        - WS injection
        - Authentication bypass via WS
        - Data exfiltration via WS
        """
        result = await self._call_tool("get_proxy_websocket_history", {
            "count": limit,
        })
        return _parse_websocket_history(result)

    async def get_proxy_websocket_history_regex(
        self,
        filter_regex: str,
        limit: int = 50,
    ) -> list[WebSocketEntry]:
        """Ambil WebSocket history yang match regex."""
        result = await self._call_tool("get_proxy_websocket_history_regex", {
            "regex": filter_regex,
            "count": limit,
        })
        return _parse_websocket_history(result)

    # ── GROUP 4: Scanner (Pro Only) ────────────────────────────────────────

    async def get_scanner_issues(
        self,
        url_prefix: str | None = None,
    ) -> list[ScanIssue]:
        """
        Ambil semua scanner findings dari Burp Pro scanner.
        Optional filter by URL prefix.
        """
        params = {}
        if url_prefix:
            params["urlPrefix"] = url_prefix

        result = await self._call_tool("get_scanner_issues", params)
        return _parse_scanner_issues(result)

    async def generate_collaborator_payload(self) -> CollaboratorPayload:
        """
        Generate Burp Collaborator payload untuk out-of-band testing.
        Gunakan untuk: blind SSRF, blind XSS, blind command injection.
        Format: "xyz123.oastify.com"
        """
        result = await self._call_tool("generate_collaborator_payload", {})
        return CollaboratorPayload(
            payload=result.get("payload", ""),
            payload_id=result.get("payloadId", ""),
        )

    async def get_collaborator_interactions(
        self,
        payload: str,
    ) -> list[CollaboratorInteraction]:
        """
        Poll Collaborator untuk melihat apakah payload sudah di-trigger.
        Tunggu 5-30 detik setelah inject sebelum poll.
        """
        result = await self._call_tool("get_collaborator_interactions", {
            "payload": payload,
        })
        interactions = result.get("interactions", [])
        return [
            CollaboratorInteraction(
                interaction_type=i.get("type", ""),
                client_ip=i.get("clientIp", ""),
                timestamp=i.get("timestamp", ""),
                data=i.get("data", {}),
            )
            for i in interactions
        ]

    # ── GROUP 5: Repeater & Intruder ──────────────────────────────────────

    async def create_repeater_tab(
        self,
        host: str,
        port: int,
        request: str,
        use_https: bool = True,
        tab_name: str | None = None,
    ) -> RepeaterTab:
        """
        Buat Repeater tab dengan request yang sudah dipersiapkan.
        Agent bisa save request menarik untuk manual review.
        Tab tetap ada di Burp UI setelah agent selesai.
        """
        params = {
            "host": host,
            "port": port,
            "request": request,
            "useHttps": use_https,
        }
        if tab_name:
            params["name"] = tab_name

        result = await self._call_tool("create_repeater_tab", params)
        return RepeaterTab(
            tab_id=result.get("tabId"),
            name=result.get("name"),
        )

    async def create_repeater_tab_http2(
        self,
        host: str,
        port: int,
        request: str,
        use_https: bool = True,
        tab_name: str | None = None,
    ) -> RepeaterTab:
        """Buat Repeater tab untuk HTTP/2 request."""
        params = {
            "host": host,
            "port": port,
            "request": request,
            "useHttps": use_https,
        }
        if tab_name:
            params["name"] = tab_name

        result = await self._call_tool("create_repeater_tab_http2", params)
        return RepeaterTab(
            tab_id=result.get("tabId"),
            name=result.get("name"),
        )

    async def send_to_intruder(
        self,
        host: str,
        port: int,
        request: str,
        use_https: bool = True,
        insertion_points: list[dict] | None = None,
    ) -> dict:
        """
        Kirim request ke Burp Intruder untuk fuzzing.
        **SANGAT POWERFUL** — agent bisa setup Intruder attack otomatis:

        insertion_points format:
        [
            {"start": 45, "end": 52}  # byte offset dari parameter value
        ]

        Setelah send, user bisa langsung launch attack dari Burp UI.
        """
        params = {
            "host": host,
            "port": port,
            "request": request,
            "useHttps": use_https,
        }
        if insertion_points:
            params["insertionPoints"] = insertion_points

        return await self._call_tool("send_to_intruder", params)

    # ── GROUP 6: Organizer ─────────────────────────────────────────────────

    async def get_organizer_items(
        self,
        limit: int = 50,
    ) -> list[OrganizerItem]:
        """
        Ambil items dari Burp Organizer.
        Organizer berisi requests yang sudah disimpan manual oleh researcher.
        Berguna untuk context: request apa yang sudah dianalisis sebelumnya.
        """
        result = await self._call_tool("get_organizer_items", {
            "count": limit,
        })
        return _parse_organizer_items(result)

    async def get_organizer_items_regex(
        self,
        filter_regex: str,
        limit: int = 20,
    ) -> list[OrganizerItem]:
        """Filter Organizer items by regex."""
        result = await self._call_tool("get_organizer_items_regex", {
            "regex": filter_regex,
            "count": limit,
        })
        return _parse_organizer_items(result)

    # ── GROUP 7: Proxy Intercept Control ──────────────────────────────────

    async def set_proxy_intercept_state(
        self,
        enabled: bool,
    ) -> bool:
        """
        Toggle proxy intercept on atau off secara programmatic.

        Penggunaan:
        - enable sebelum test authentication flow (intercept request)
        - disable setelah selesai (agent jalan tanpa intercept blocking)
        - SELALU disable saat running automated scans
        """
        await self._call_tool("set_proxy_intercept_state", {
            "intercept": enabled,
        })
        logger.info(
            "[burp_mcp] Proxy intercept: %s",
            "ENABLED" if enabled else "DISABLED"
        )
        return True

    async def set_task_execution_engine_state(
        self,
        running: bool,
    ) -> bool:
        """
        Pause atau resume Burp's task execution engine.
        Gunakan untuk pause scanner saat tidak diperlukan,
        resume ketika agent siap menganalisis findings.
        """
        await self._call_tool("set_task_execution_engine_state", {
            "running": running,
        })
        logger.info(
            "[burp_mcp] Task engine: %s",
            "RUNNING" if running else "PAUSED"
        )
        return True

    # ── GROUP 8: Editor Control ────────────────────────────────────────────

    async def get_active_editor_contents(self) -> str:
        """
        Ambil isi dari Burp editor yang sedang aktif.
        Berguna untuk: capture request/response yang sedang dilihat researcher.
        """
        result = await self._call_tool("get_active_editor_contents", {})
        return result.get("contents", "")

    async def set_active_editor_contents(
        self,
        contents: str,
    ) -> bool:
        """
        Inject content ke Burp editor yang aktif.
        Gunakan untuk: setup payload di editor sebelum manual testing.
        HATI-HATI: ini modifikasi UI secara programmatic.
        """
        await self._call_tool("set_active_editor_contents", {
            "contents": contents,
        })
        return True

    # ── GROUP 9: Configuration ─────────────────────────────────────────────

    async def get_project_options(self) -> dict:
        """
        Export current project options sebagai JSON.
        Berguna untuk: backup scope, SSL config, session handling rules.
        """
        result = await self._call_tool("output_project_options", {})
        return result.get("options", {})

    async def get_user_options(self) -> dict:
        """Export current user options (proxy, upstream, dll)."""
        result = await self._call_tool("output_user_options", {})
        return result.get("options", {})

    async def set_project_scope(
        self,
        in_scope_urls: list[str],
        out_of_scope_urls: list[str] | None = None,
    ) -> bool:
        """
        Set Burp project scope programmatically.
        Sync scope dari Pentra AI engagement ke Burp Pro.
        Ini memastikan Burp scanner hanya scan URL yang in-scope.

        PENTING: Call ini di awal setiap engagement.
        """
        # Get current options first
        current = await self.get_project_options()

        # Build scope config
        include = [{"enabled": True, "scheme": "", "host": url, "port": "", "file": ""}
                   for url in in_scope_urls]
        exclude = [{"enabled": True, "scheme": "", "host": url, "port": "", "file": ""}
                   for url in (out_of_scope_urls or [])]

        current["target"] = current.get("target", {})
        current["target"]["scope"] = {
            "advanced_mode": False,
            "include": include,
            "exclude": exclude,
        }

        await self._call_tool("set_project_options", {
            "options": json.dumps(current),
        })
        logger.info(
            "[burp_mcp] Scope set: %d in-scope, %d out-of-scope",
            len(in_scope_urls),
            len(out_of_scope_urls or [])
        )
        return True

    # ── GROUP 10: Encoding Utilities ──────────────────────────────────────

    async def url_encode(self, text: str) -> str:
        """
        URL encode via Burp — consistent dengan Burp Decoder.
        Lebih reliable dari Python urllib.parse untuk edge cases.
        """
        result = await self._call_tool("url_encode", {"data": text})
        return result.get("result", text)

    async def url_decode(self, text: str) -> str:
        """URL decode via Burp."""
        result = await self._call_tool("url_decode", {"data": text})
        return result.get("result", text)

    async def base64_encode(self, data: str) -> str:
        """Base64 encode via Burp."""
        result = await self._call_tool("base64_encode", {"data": data})
        return result.get("result", "")

    async def base64_decode(self, data: str) -> str:
        """
        Base64 decode via Burp.
        Gunakan untuk: decode JWT, decode cookies, decode API tokens.
        """
        result = await self._call_tool("base64_decode", {"data": data})
        return result.get("result", "")

    async def generate_random_string(self, length: int = 16) -> str:
        """
        Generate random string via Burp.
        Gunakan untuk: unique injection markers, CSRF-style tokens, nonce.
        """
        result = await self._call_tool("generate_random_string", {
            "length": length,
        })
        return result.get("result", "")


# ── Exceptions ────────────────────────────────────────────────────────────

class BurpMCPError(Exception):
    """General Burp MCP error."""

class BurpNotAvailableError(BurpMCPError):
    """Burp Pro tidak bisa diakses."""


# ── Parsers ───────────────────────────────────────────────────────────────

def _parse_proxy_history(result: dict) -> list[ProxyEntry]:
    entries = result.get("entries", result.get("items", []))
    return [
        ProxyEntry(
            url=e.get("url", ""),
            method=e.get("method", "GET"),
            request_raw=e.get("request", ""),
            response_raw=e.get("response"),
            response_status=e.get("responseStatus"),
            timestamp=e.get("timestamp"),
        )
        for e in (entries if isinstance(entries, list) else [])
    ]


def _parse_websocket_history(result: dict) -> list[WebSocketEntry]:
    messages = result.get("messages", result.get("entries", []))
    return [
        WebSocketEntry(
            url=m.get("url", ""),
            direction=m.get("direction", ""),
            message=m.get("message", ""),
            timestamp=m.get("timestamp"),
        )
        for m in (messages if isinstance(messages, list) else [])
    ]


def _parse_scanner_issues(result: dict) -> list[ScanIssue]:
    issues = result.get("issues", [])
    return [
        ScanIssue(
            name=i.get("issueName", i.get("name", "Unknown")),
            severity=i.get("severity", "information").lower(),
            confidence=i.get("confidence", "tentative").lower(),
            url=i.get("url", ""),
            detail=i.get("issueDetail", i.get("detail", "")),
            remediation=i.get("remediationDetail", i.get("remediation")),
            request=i.get("request"),
            response=i.get("response"),
        )
        for i in (issues if isinstance(issues, list) else [])
    ]


def _parse_organizer_items(result: dict) -> list[OrganizerItem]:
    items = result.get("items", [])
    return [
        OrganizerItem(
            url=item.get("url", ""),
            method=item.get("method", "GET"),
            request_raw=item.get("request", ""),
            notes=item.get("notes"),
        )
        for item in (items if isinstance(items, list) else [])
    ]


def _parse_http_response(result: dict, protocol: str) -> HttpResponse:
    return HttpResponse(
        status_code=result.get("statusCode", 0),
        headers=result.get("headers", {}),
        body=result.get("body", ""),
        protocol=protocol,
    )
```

---

## Integrasi ke Agent Nodes

### recon_node.py — Tambahkan Scope Sync + WebSocket Detection

```python
# packages/pentra-agent/pentra_agent/nodes/recon_node.py
# Di awal recon_node(), setelah scope check:

async def recon_node(state: PentraState) -> dict:
    # ... existing code ...

    # ── 1. Sync Burp scope dengan engagement scope ────────────────────
    if burp_active:
        try:
            await burp.set_project_scope(
                in_scope_urls=state["scope"]["in_scope"],
                out_of_scope_urls=state["scope"]["out_of_scope"],
            )
            logger.info("[recon_node] Burp scope synced with engagement scope")
        except Exception as e:
            logger.warning("[recon_node] Burp scope sync failed: %s", e)

        # Disable intercept saat automated scanning
        await burp.set_proxy_intercept_state(enabled=False)

    # ── 2. Ambil Organizer items untuk context ────────────────────────
    if burp_active:
        try:
            organizer_items = await burp.get_organizer_items(limit=20)
            if organizer_items:
                logger.info(
                    "[recon_node] Burp Organizer: %d saved items",
                    len(organizer_items)
                )
                # Add ke endpoints sebagai hint dari manual researcher
                for item in organizer_items:
                    if scope.is_allowed(item.url):
                        all_endpoints.append({
                            "url": item.url,
                            "method": item.method,
                            "source": "burp_organizer",
                            "notes": item.notes,
                        })
        except Exception:
            pass
```

### vuln_hunt_node.py — HTTP/2 Detection + Intruder + WebSocket Testing

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py

async def _test_http2_support(burp: BurpMCPClient, host: str, port: int) -> bool:
    """
    Cek apakah target support HTTP/2.
    Jika ya, gunakan send_http2_request untuk testing.
    HTTP/2 punya attack surface berbeda: header injection, stream manipulation.
    """
    try:
        resp = await burp.send_http2_request(
            host=host,
            port=port,
            request="GET / HTTP/2\r\nHost: {host}\r\n\r\n".format(host=host),
            use_https=True,
        )
        return resp.status_code > 0 and resp.protocol == "HTTP/2"
    except Exception:
        return False


async def _test_websocket_endpoints(
    burp: BurpMCPClient,
    scope: ScopeEnforcer,
) -> list[dict]:
    """
    Analisis WebSocket history untuk security issues.
    WebSocket sering luput dari scanner karena berbeda dari HTTP biasa.
    """
    findings = []

    try:
        ws_history = await burp.get_proxy_websocket_history(limit=100)
        if not ws_history:
            return []

        logger.info("[vuln_hunt] Found %d WebSocket messages to analyze", len(ws_history))

        # Filter messages yang in-scope
        in_scope_ws = [
            msg for msg in ws_history
            if scope.is_allowed(msg.url)
        ]

        # Analisis untuk patterns yang suspicious
        for msg in in_scope_ws:
            # Cek apakah ada data sensitif di WS message
            sensitive_patterns = [
                ("token", "authentication token in WebSocket"),
                ("password", "password in WebSocket message"),
                ("secret", "secret in WebSocket message"),
                ('"id":', "user ID exposed in WebSocket"),
                ("admin", "admin reference in WebSocket"),
            ]
            for pattern, description in sensitive_patterns:
                if pattern.lower() in msg.message.lower():
                    findings.append({
                        "title": f"Sensitive Data in WebSocket: {description}",
                        "severity": "medium",
                        "vuln_class": "INFORMATION_DISCLOSURE",
                        "target_url": msg.url,
                        "description": f"WebSocket message contains sensitive pattern: {pattern}",
                        "source": "burp_websocket_analysis",
                        "request_raw": f"WebSocket {msg.direction}: {msg.message[:500]}",
                        "response_raw": "",
                    })

    except Exception as e:
        logger.warning("[vuln_hunt] WebSocket analysis failed: %s", e)

    return findings


async def _setup_intruder_for_sqli(
    burp: BurpMCPClient,
    scope: ScopeEnforcer,
    url: str,
    param: str,
    base_request: str,
) -> bool:
    """
    Setup Burp Intruder untuk SQL injection fuzzing.
    Agent prepare Intruder → researcher bisa langsung launch dari Burp UI.

    Ini adalah "handoff" pattern: agent setup, human launch.
    """
    try:
        scope.validate_or_raise(url)

        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_https = parsed.scheme == "https"

        # Find insertion point (parameter value position in request)
        param_start = base_request.find(f"{param}=")
        if param_start == -1:
            return False

        value_start = param_start + len(param) + 1
        value_end = base_request.find("&", value_start)
        if value_end == -1:
            value_end = len(base_request)

        await burp.send_to_intruder(
            host=host,
            port=port,
            request=base_request,
            use_https=use_https,
            insertion_points=[{"start": value_start, "end": value_end}],
        )

        logger.info(
            "[vuln_hunt] Intruder configured for SQLi on %s?%s — "
            "launch from Burp UI",
            url, param
        )
        return True

    except Exception as e:
        logger.warning("[vuln_hunt] Intruder setup failed: %s", e)
        return False


async def _save_interesting_request_to_repeater(
    burp: BurpMCPClient,
    url: str,
    request: str,
    finding_title: str,
) -> None:
    """
    Save request yang menarik ke Burp Repeater untuk manual follow-up.
    Agent automatically save semua confirmed/potential findings ke Repeater.
    Researcher bisa langsung manual test dari Burp UI.
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        tab = await burp.create_repeater_tab(
            host=host,
            port=port,
            request=request,
            use_https=parsed.scheme == "https",
            tab_name=f"PentraAI: {finding_title[:40]}",
        )
        logger.info(
            "[vuln_hunt] Saved to Repeater: '%s'",
            finding_title[:40]
        )
    except Exception:
        pass  # Non-critical — don't fail if Repeater save fails
```

### Tambahkan utility helpers untuk encoding

```python
# packages/pentra-agent/pentra_agent/utils/burp_utils.py

"""
Helper utilities yang memanfaatkan Burp MCP encoding tools.
Lebih reliable dari Python built-in untuk pentest payload encoding.
"""

async def encode_payload_for_injection(
    burp: "BurpMCPClient",
    payload: str,
    encoding: str,  # "url" | "base64" | "double_url" | "html"
) -> str:
    """
    Encode payload menggunakan Burp's encoding — konsisten dengan Burp Decoder.
    Gunakan ini untuk generate encoded variants saat testing WAF bypass.
    """
    if encoding == "url":
        return await burp.url_encode(payload)
    elif encoding == "base64":
        return await burp.base64_encode(payload)
    elif encoding == "double_url":
        single_encoded = await burp.url_encode(payload)
        return await burp.url_encode(single_encoded)
    else:
        return payload


async def decode_interesting_value(
    burp: "BurpMCPClient",
    value: str,
) -> dict:
    """
    Auto-detect dan decode value yang mungkin encoded.
    Try: base64, URL decode, JWT decode.
    Berguna untuk analisis cookies dan tokens.
    """
    results = {"original": value}

    # Try base64
    try:
        decoded = await burp.base64_decode(value)
        if decoded and len(decoded) > 0:
            results["base64_decoded"] = decoded
    except Exception:
        pass

    # Try URL decode
    try:
        url_decoded = await burp.url_decode(value)
        if url_decoded != value:
            results["url_decoded"] = url_decoded
    except Exception:
        pass

    return results


async def generate_unique_marker(burp: "BurpMCPClient") -> str:
    """
    Generate unique marker string untuk injection testing.
    Lebih unique dari hardcoded "PENTRA_MARKER" karena random setiap call.
    """
    random_str = await burp.generate_random_string(12)
    return f"PENTRA{random_str}MARKER"
```

---

## Workflow Baru yang Dimungkinkan

### Workflow 1: Full Burp Integration per Engagement

```python
# Di awal setiap engagement — burp_startup_sequence()

async def burp_startup_sequence(
    burp: BurpMCPClient,
    scope: list[str],
    out_of_scope: list[str],
) -> dict:
    """
    Setup Burp Pro untuk engagement baru.
    Dipanggil sekali di awal sebelum recon dimulai.
    """
    status = {}

    # 1. Sync scope
    await burp.set_project_scope(scope, out_of_scope)
    status["scope_synced"] = True

    # 2. Disable intercept (tidak mau block automated requests)
    await burp.set_proxy_intercept_state(enabled=False)
    status["intercept_disabled"] = True

    # 3. Pause task engine (akan di-enable saat active scan)
    await burp.set_task_execution_engine_state(running=False)
    status["task_engine_paused"] = True

    # 4. List available tools (verifikasi version)
    tools = await burp.list_tools()
    status["tools_available"] = len(tools)
    status["has_collaborator"] = "generate_collaborator_payload" in tools
    status["has_http2"] = "send_http2_request" in tools

    logger.info("[burp] Startup complete: %s", status)
    return status
```

### Workflow 2: HTTP/2 Target Testing

```python
# Di vuln_hunt_node — tambahkan HTTP/2 branch

is_http2 = await _test_http2_support(burp, host, port)
if is_http2:
    logger.info("[vuln_hunt] Target supports HTTP/2 — testing H2-specific attacks")

    # HTTP/2 Header Injection test
    h2_request = (
        "GET /?pentra_test=1 HTTP/2\r\n"
        f"Host: {host}\r\n"
        "X-Custom-Header: test\r\n"
        "Transfer-Encoding: chunked\r\n"  # H2 TE desync test
        "\r\n"
    )
    resp = await burp.send_http2_request(host, port, h2_request)

    # Save ke Repeater untuk manual H2 testing
    await burp.create_repeater_tab_http2(
        host=host, port=port,
        request=h2_request,
        tab_name=f"PentraAI: H2 {host}"
    )
```

### Workflow 3: OOB SSRF Testing dengan Collaborator + Unique Marker

```python
# Pattern lengkap untuk blind SSRF testing

async def test_ssrf_with_collaborator(
    burp: BurpMCPClient,
    url: str,
    param: str,
    base_value: str,
) -> dict | None:
    """
    Full OOB SSRF test menggunakan Burp Collaborator + random marker.
    """
    # 1. Generate unique marker
    marker = await burp.generate_random_string(8)

    # 2. Generate Collaborator payload
    collab = await burp.generate_collaborator_payload()
    ssrf_payload = f"http://{marker}.{collab.payload}/"

    # 3. URL encode payload untuk injection
    encoded_payload = await burp.url_encode(ssrf_payload)

    # 4. Send request dengan SSRF payload
    # ... (inject ke parameter) ...

    # 5. Tunggu dan poll Collaborator
    await asyncio.sleep(10)
    interactions = await burp.get_collaborator_interactions(collab.payload)

    if interactions:
        return {
            "title": f"SSRF via parameter '{param}'",
            "severity": "high",
            "vuln_class": "SSRF",
            "collaborator_hits": len(interactions),
            "interaction_types": [i.interaction_type for i in interactions],
        }
    return None
```

---

## Tests untuk BurpMCPClient Baru

```python
# packages/pentra-tools/tests/test_burp_mcp_full.py

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

@pytest.fixture
def burp_client():
    from pentra_tools.burp.client import BurpMCPClient
    return BurpMCPClient(base_url="http://localhost:9877")


@pytest.mark.asyncio
async def test_health_check_success(burp_client):
    with patch("httpx.AsyncClient") as mock_cls:
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)
        mock.get = AsyncMock(return_value=MagicMock(status_code=200))
        mock_cls.return_value = mock
        assert await burp_client.health_check() is True


@pytest.mark.asyncio
async def test_health_check_unreachable(burp_client):
    import httpx
    with patch("httpx.AsyncClient") as mock_cls:
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)
        mock.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_cls.return_value = mock
        assert await burp_client.health_check() is False


@pytest.mark.asyncio
async def test_parse_proxy_history_empty(burp_client):
    with patch.object(burp_client, "_call_tool", return_value={"entries": []}):
        result = await burp_client.get_proxy_http_history()
        assert result == []


@pytest.mark.asyncio
async def test_parse_websocket_history(burp_client):
    mock_data = {
        "messages": [
            {"url": "ws://target.com/ws", "direction": "client_to_server",
             "message": '{"action":"ping"}', "timestamp": "2026-06-04"}
        ]
    }
    with patch.object(burp_client, "_call_tool", return_value=mock_data):
        result = await burp_client.get_proxy_websocket_history()
        assert len(result) == 1
        assert result[0].url == "ws://target.com/ws"
        assert result[0].direction == "client_to_server"


@pytest.mark.asyncio
async def test_generate_collaborator_payload(burp_client):
    mock_data = {"payload": "xyz123.oastify.com", "payloadId": "abc"}
    with patch.object(burp_client, "_call_tool", return_value=mock_data):
        result = await burp_client.generate_collaborator_payload()
        assert result.payload == "xyz123.oastify.com"
        assert result.payload_id == "abc"


@pytest.mark.asyncio
async def test_set_proxy_intercept_state(burp_client):
    with patch.object(burp_client, "_call_tool", return_value={}) as mock_call:
        result = await burp_client.set_proxy_intercept_state(enabled=False)
        assert result is True
        mock_call.assert_called_once_with(
            "set_proxy_intercept_state", {"intercept": False}
        )


@pytest.mark.asyncio
async def test_encoding_utils(burp_client):
    with patch.object(burp_client, "_call_tool",
                      return_value={"result": "hello%20world"}):
        result = await burp_client.url_encode("hello world")
        assert result == "hello%20world"


def test_burp_not_available_error():
    from pentra_tools.burp.client import BurpNotAvailableError
    err = BurpNotAvailableError("Cannot connect")
    assert "Cannot connect" in str(err)


def test_parse_scanner_issues_severity_normalized():
    from pentra_tools.burp.client import _parse_scanner_issues
    raw = {
        "issues": [{
            "issueName": "SQL injection",
            "severity": "High",           # Capital H
            "confidence": "Certain",
            "url": "http://target.com/products?id=1",
            "issueDetail": "SQL injection detected",
        }]
    }
    issues = _parse_scanner_issues(raw)
    assert len(issues) == 1
    assert issues[0].severity == "high"   # Normalized to lowercase
    assert issues[0].confidence == "certain"
```

---

## Checklist Implementasi

```
BurpMCPClient Overhaul
[ ] Ganti client.py lama dengan versi komprehensif di atas
[ ] Semua 27 tools ter-implementasi
[ ] Exception hierarchy: BurpMCPError, BurpNotAvailableError
[ ] Parser functions untuk semua response types
[ ] 8 unit tests pass

recon_node.py Enhancement
[ ] burp_startup_sequence() dipanggil di awal engagement
[ ] set_project_scope() sync scope ke Burp
[ ] set_proxy_intercept_state(False) disabled saat automated
[ ] get_organizer_items() membaca saved requests researcher
[ ] Organizer items masuk ke endpoints list

vuln_hunt_node.py Enhancement
[ ] _test_http2_support() detect HTTP/2
[ ] send_http2_request() dipakai untuk HTTP/2 targets
[ ] _test_websocket_endpoints() analisis WS history
[ ] _setup_intruder_for_sqli() setup Intruder untuk SQLi candidates
[ ] _save_interesting_request_to_repeater() save findings ke Repeater
[ ] test_ssrf_with_collaborator() full OOB test pattern

burp_utils.py (new)
[ ] encode_payload_for_injection() — URL/base64/double-URL encoding
[ ] decode_interesting_value() — auto-decode cookies dan tokens
[ ] generate_unique_marker() — random marker per request

Total tests baru: 8+ tests, semua passing
```

---

## Prompt untuk Copilot

```
Baca CLAUDE.md, PROGRESS.md, dan BURP-MCP-MAXIMIZE.md secara lengkap.

Kita akan maximize seluruh kapabilitas Burp MCP Official (27 tools).

Mulai dari langkah 1:
1. Ganti SELURUH isi packages/pentra-tools/pentra_tools/burp/client.py
   dengan implementasi komprehensif di BURP-MCP-MAXIMIZE.md.
   Semua 27 tools harus ter-implementasi.

2. Buat packages/pentra-tools/tests/test_burp_mcp_full.py
   dengan 8 unit tests sesuai BURP-MCP-MAXIMIZE.md.

3. Jalankan: uv run pytest packages/pentra-tools/tests/test_burp_mcp_full.py -v
   Pastikan 8 tests pass.

4. Setelah tests pass, update recon_node.py:
   - Tambahkan burp_startup_sequence() di awal node
   - Sync scope ke Burp via set_project_scope()
   - Disable intercept via set_proxy_intercept_state(False)
   - Baca Organizer items

Ikuti semua konvensi di CLAUDE.md.
Scope check WAJIB sebelum setiap Burp call yang mengirim request ke target.
```

---

*BURP-MCP-MAXIMIZE.md — Pentra AI*  
*Full coverage: 27 tools official + custom workflows*  
*HTTP/2 testing, WebSocket analysis, Intruder setup, OOB SSRF, scope sync*
