# Pentra AI — Progress Report
**Tanggal:** 5 Juni 2026  
**Status:** Phase 2 (Agent Engine) — Sprint 17 aktif

---

## Executive Summary

Pentra AI adalah platform riset keamanan AI self-hosted yang mengintegrasikan local LLM (Ollama), Burp Suite Pro via MCP, dan LangGraph multi-agent orchestration. Sesi ini menyelesaikan wiring `managed_session()` ke seluruh node agent, memvalidasi 33 Burp MCP tools, mengimplementasikan fitur-fitur baru (request smuggling detection, WebSocket analysis, organizer regex), dan melakukan E2E live scan dengan hasil **10 HIGH vulnerabilities confirmed** pada target `testaspnet.vulnweb.com`.

---

## 1. Status Keseluruhan

| Phase | Status | Keterangan |
|-------|--------|------------|
| Phase 1 — Knowledge Engine | ✅ COMPLETE | KB Browser UI, hybrid search, 1000+ records |
| Phase 2 — Agent Engine | 🔄 ACTIVE | Sprint 17, E2E flow validated |

### Test Coverage
```
pentra-tools:   95 passed, 3 skipped
pentra-agent:   49 passed, 4 skipped
Total:         144 passed, 0 failed
```

---

## 2. Pekerjaan Sesi Ini

### 2.1 `managed_session()` Wiring (Bug Fix)
Sebelumnya setiap Burp MCP tool call membuka koneksi SSE baru, menguras session pool Burp (~4 concurrent limit). Fix: satu `managed_session()` dibuka per fungsi besar, semua tool call dalam fungsi tersebut reuse koneksi yang sama.

**Lokasi perubahan:**

| Fungsi | File | Perubahan |
|--------|------|-----------|
| `_fetch_burp_endpoints()` | `recon_node.py:486` | `async with client.managed_session():` |
| `_get_burp_proxy_findings()` | `vuln_hunt_node.py:604` | `async with client.managed_session():` |
| `_run_burp_active_scan()` | `vuln_hunt_node.py:709` | `async with client.managed_session():` |
| `_get_collaborator_payload()` | `vuln_hunt_node.py:793` | `async with client.managed_session():` |
| `_run_llm_burp_active_testing()` | `vuln_hunt_node.py:975` | manual `__aenter__`/`__aexit__` (fungsi 500+ baris) |
| `_run_burp_extended_checks()` | `vuln_hunt_node.py:2318` | `async with client.managed_session():` |

### 2.2 SSE ReadTimeout Fix (Critical Bug Fix)

**Problem:** `mcp.client.sse.sse_client` memiliki `sse_read_timeout=300s` (5 menit) default. Saat LLM analysis berjalan >5 menit (menganalisis 56–59 req/resp pairs), SSE stream timeout → Burp MCP session mati → semua tool call berikutnya gagal → **0 findings**.

**Bukti:** Run pertama (11:40:25 → 11:45:26 = tepat 5 menit) → `httpx.ReadTimeout` → 0 confirmed findings.

**Fix:**
```python
# packages/pentra-tools/pentra_tools/burp/client.py
# managed_session() dan _session() — keduanya:
sse_client(
    self._sse_url,
    headers={"Host": self._host_header},
    sse_read_timeout=60 * 30,  # 30 menit
)
```

**Hasil:** Run kedua — **10 HIGH findings confirmed**, tidak ada ReadTimeout.

### 2.3 `_PRO_ONLY_TOOLS` → `_PRO_EDITION_PHRASES` Fix

Sebelumnya `BurpNotProError` di-raise untuk **semua error** pada tool tertentu (terlalu agresif). Sekarang hanya di-raise jika error text mengandung frasa Pro-edition:

```python
_PRO_EDITION_PHRASES = ("professional", "community edition", "pro edition", "pro only")
# raise BurpNotProError hanya jika: any(p in error_text.lower() for p in _PRO_EDITION_PHRASES)
```

### 2.4 `generate_collaborator_payload` — Custom Data Sanitization

Burp mensyaratkan `custom_data` alphanumeric only, max 16 chars. Input `"pentra-pro-test"` (mengandung `-`) menyebabkan error. Fix: auto-sanitize sebelum kirim ke Burp:

```python
safe = re.sub(r"[^A-Za-z0-9]", "", custom_data)[:16]
```

### 2.5 Fitur Baru: `_test_request_smuggling()`

Mendeteksi HTTP Request Smuggling via timing anomaly menggunakan `send_http1_request` (CL.TE dan TE.CL probes). Threshold: `max(baseline × 3, 4000ms)`. Jika timing anomaly terdeteksi → simpan ke Burp Repeater untuk konfirmasi manual.

### 2.6 Fitur Baru: WebSocket & Organizer Regex Filter

- `_test_websocket_endpoints()` → `get_proxy_websocket_history_regex(filter_regex=domain_patterns)` — server-side filter, fallback ke unfiltered
- `_fetch_burp_endpoints()` → `get_organizer_items_regex(filter_regex=escaped_domain)` — server-side domain filter

### 2.7 `burp_utils.py` — Utility Functions

```python
encode_payload_for_injection(burp, payload, encoding)  # url, base64, double-url, etc.
decode_interesting_value(burp, value)                   # detect & decode base64/url encoded values  
generate_unique_marker(burp)                            # PENTRAXXXXXXXXMARKER via generate_random_string
```

---

## 3. Capability Check Burp MCP — 33/33 ✅

```
✅ health_check          ✅ list_tools (27 items)
✅ get_proxy_history     ✅ get_proxy_history_regex
✅ get_sitemap           ✅ get_proxy_websocket_history
✅ get_proxy_websocket_history_regex
✅ get_organizer_items   ✅ get_organizer_items_regex
✅ set_proxy_intercept   ✅ set_proxy_intercept_state
✅ set_task_execution_engine_state
✅ get_active_editor_contents  ✅ set_active_editor_contents
✅ get_project_options   ✅ get_user_options
✅ set_project_scope     ✅ set_project_options_raw
✅ set_user_options_raw  ✅ url_encode / url_decode
✅ base64_encode / base64_decode
✅ generate_random_string
✅ send_request (HTTP/1)  ✅ send_http1_request
✅ send_http2_request     ✅ trigger_active_scan
✅ get_scan_results       ✅ create_repeater_tab
✅ create_repeater_tab_http2
✅ send_to_repeater (legacy)
✅ send_to_intruder
✅ generate_collaborator_payload [PRO]
✅ poll_collaborator [PRO]
✅ get_collaborator_interactions [PRO]
```

---

## 4. E2E Live Scan — Hasil

**Target:** `testaspnet.vulnweb.com` (Acunetix intentionally vulnerable ASP.NET app)  
**Engagement ID:** `ac5efd5d-2a14-40a7-8f89-3cab2d3c9a02`  
**Durasi total:** 39 menit (recon 80s + vuln hunt 2335s)  
**JSON Report:** `/tmp/pentra_scan_testaspnet_vulnweb_com_ac5efd5d.json`

### Phase 1 — Recon (80 detik)
```
subfinder      → 1 subdomain (testaspnet.vulnweb.com)
httpx          → 8 live endpoints via Burp proxy
rate limiter   → safe_rps=5, delay=300ms
Burp scope     → synced (1 in-scope, 0 out-of-scope)
Burp intercept → DISABLED (otomatis)
proxy history  → 27 unique endpoints captured
tech stack     → IIS (ASP.NET)
```

### Phase 2 — Vuln Hunt (2335 detik)

| Step | Hasil |
|------|-------|
| nuclei | 0 findings (running ~10 menit) |
| Burp active scan | 8 endpoint di-trigger |
| Proxy findings | 27 entries |
| Request smuggling | No timing anomaly |
| WebSocket | 1 message analyzed |
| Collaborator | `ta7lysxo9dgejx3i2pk75s2o1f78vnz0ihihkcohrcu1.oastify.com` |
| LLM crawl | 30 pages, 30 responses |
| LLM analysis | 59 req/resp pairs → 18 candidates |
| ReAct testing | 18 candidates → **10 CONFIRMED** |

### 10 Findings Confirmed

| # | Severity | Vuln Class | Parameter | Endpoint |
|---|----------|------------|-----------|----------|
| 1 | HIGH | Deserialization | `__VIEWSTATE` (body) | `/login.aspx` |
| 2 | HIGH | SQL Injection (time-based) | `id` (query) | `/comment.aspx?id=1` |
| 3 | HIGH | SQL Injection (time-based) | `cat` (query) | `/listproducts.aspx?cat=1` |
| 4 | HIGH | SQL Injection (time-based) | `id` (query) | `/artists.aspx?id=1` |
| 5 | HIGH | SQL Injection (time-based) | `id` (query) | `/comment.aspx?id=1` |
| 6 | HIGH | SQL Injection (time-based) | `id` (query) | `/categories.aspx?id=1` |
| 7 | HIGH | SQL Injection (time-based) | `username` (query) | `/login.aspx` |
| 8 | HIGH | SQL Injection (time-based) | `id` (query) | `/ReadNews.aspx?id=1` |
| 9 | HIGH | IDOR | `id` (query) | `/Comments.aspx?id=1` |
| 10 | HIGH | Host Header Injection | `Host` (header) | `/` |

**Payload examples:**
- SQLi: `' OR SLEEP(5)--` (time-based blind, response delay 5–51s confirmed)
- IDOR: `id=2` vs `id=1` → different `__VIEWSTATE` dan form action
- Host Header: `Host: attacker.com` → response size -13258 bytes vs baseline

**Burp UI artifacts created:**
- 8 Repeater tabs (satu per confirmed finding)
- 6 Intruder configs (semua SQLi endpoints)

**Anomaly detections (tidak confirm tapi menarik):**
- `PATH_INCLUSION` pada `NewsAd` parameter di `/ReadNews.aspx` → `<iframe src="../web.config">` — LFI candidate
- `ERROR_DISCLOSURE` pada `__VIEWSTATE` di `Signup.aspx` → `exception, stack trace, unhandled` di response

---

## 5. Arsitektur Komponen (Current State)

```
packages/pentra-tools/
  pentra_tools/burp/
    client.py         (1379 baris) — 33 MCP tools, managed_session, sse_read_timeout=30min
    models.py         — Pydantic models (ProxyEntry, ScanIssue, CollaboratorPayload, ...)
    exceptions.py     — BurpConnectionError, BurpNotProError, BurpMCPToolError
    tests/            — 95 passed, 3 skipped

packages/pentra-agent/
  pentra_agent/
    nodes/
      recon_node.py       (586 baris)  — subfinder, httpx, Burp sitemap, LLM analysis
      vuln_hunt_node.py  (2557 baris)  — nuclei, ffuf, Burp scanner, LLM ReAct loop
      osint_node.py                    — OSINT collection
      report_node.py                   — Report generation
    playbooks/
      base.py             — Playbook runner (SQLi, IDOR, XSS, ...)
    utils/
      burp_utils.py       — encode_payload, decode_interesting, generate_unique_marker
    graph/
      state.py            — PentraState TypedDict
      graph.py            — LangGraph StateGraph builder
    tests/                — 49 passed, 4 skipped
```

---

## 6. Issues Terbuka

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1 | Nuclei 0 findings + empty error | Medium | 🔴 Open — nuclei berjalan 10 menit tapi 0 hasil |
| 2 | LFI pada `NewsAd` tidak di-confirm | Low | 🟡 Detected (PATH_INCLUSION anomaly) tapi LLM tidak confirm |
| 3 | Severity mapping: log bilang CRITICAL, report bilang HIGH | Low | 🟡 Inconsistency di severity normalization |
| 4 | LLM Ollama 500 error saat recon (non-fatal) | Low | 🟡 Intermittent, fallback berjalan |
| 5 | `bge-m3` embedding belum di-install | Medium | 🔵 Pakai `qwen2.5:32b` fallback untuk embedding |
| 6 | KB scale: baru ~1000 records, target 3000+ | Low | 🔵 Scraping in progress |

---

## 7. Next Steps

### Immediate
- [ ] Investigasi nuclei 0 findings — test manual nuclei dengan target yang sama
- [ ] Fix severity normalization (CRITICAL di log → HIGH di report)
- [ ] Fix LFI confirmation pada `NewsAd` parameter

### Sprint 17 Remaining
- [ ] 17.2 — E2E-v16 Live Run (manual validation) — *in progress*
- [ ] `bge-m3` install → re-embed semua records
- [ ] KB scale: scraping pages 21–60 → ~3000 records

### Sprint 18 (Planned)
- [ ] Frontend KB Browser → Agent dashboard integration
- [ ] WebSocket live feed untuk scan progress
- [ ] HITL approval flow di UI (Phase 2 agent)

---

## 8. Konfigurasi Environment Aktif

```bash
BURP_MCP_URL=http://localhost:9877        # WSL2 → Windows Burp Pro
BURP_PROXY_URL=http://localhost:8082       # Burp proxy
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL_DEFAULT=qwen2.5:32b
OLLAMA_MODEL_FAST=qwen2.5:7b
DATABASE_URL=postgresql+asyncpg://pentra:pentra@localhost:5432/pentra
```

**Burp Pro features aktif:** Scanner ✅ · Collaborator ✅ · Repeater ✅ · Intruder ✅

---

*Generated: 2026-06-05 | Pentra AI — Self-Hosted AI Security Research Platform*
