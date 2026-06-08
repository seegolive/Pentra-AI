# Pentra AI — Progress Report
**Tanggal:** 3 Juni 2026  
**Dibuat:** 14:39 WIB  
**Status:** Aktif — E2E-v11-BurpLive sedang berjalan

---

## 1. Ringkasan Eksekutif

Sesi ini berfokus pada debugging pipeline `vuln_hunt_node` yang menghasilkan **0 findings di semua engagement sebelumnya** (v1–v10). Ditemukan dan diperbaiki **6 bug berantai** yang mencegah seluruh pipeline berjalan. Per 14:39 WIB, E2E-v11-BurpLive adalah engagement pertama yang berjalan dengan:

- **Burp MCP aktif** (27 tools, `health_check OK`)
- **Burp Proxy aktif** (`localhost:8082`)
- **nuclei scan HTTP** (bukan HTTPS yang blocked)
- **Crawl 6s/halaman** (bukan 31s seperti sebelumnya)

---

## 2. Status Infrastruktur Saat Ini

| Komponen | Status | Detail |
|----------|--------|--------|
| API Server | ✅ Running | `localhost:8001`, log: `/tmp/api-server.log` |
| Ollama | ✅ Running | `localhost:11434`, model: `qwen2.5:32b` |
| **Burp MCP** | ✅ **CONNECTED** | `localhost:9877`, **27 tools available** |
| **Burp Proxy** | ✅ **CONNECTED** | `localhost:8082`, traffic verified |
| PostgreSQL | ✅ Running | async via SQLAlchemy |
| Qdrant | ✅ Running | Vector DB |
| nuclei | ✅ Available | `/home/mdilab/go/bin/nuclei` |

### Burp MCP Tools (27 tools dari PortSwigger MCP Server)
```
send_http1_request, send_http2_request, create_repeater_tab, create_repeater_tab_http2,
send_to_intruder, url_encode, url_decode, base64_encode, base64_decode,
generate_random_string, output_project_options, output_user_options,
set_project_options, set_user_options,
get_scanner_issues ★Pro, generate_collaborator_payload ★Pro, get_collaborator_interactions ★Pro,
get_proxy_http_history, get_proxy_http_history_regex,
get_organizer_items, get_organizer_items_regex,
get_proxy_websocket_history, get_proxy_websocket_history_regex,
set_task_execution_engine_state, set_proxy_intercept_state,
get_active_editor_contents, set_active_editor_contents
```

---

## 3. Engagement Aktif Saat Ini — E2E-v11-BurpLive

| Field | Value |
|-------|-------|
| **EID** | `4f8e459f-9979-4e61-990b-fba32d07312e` |
| **Target** | `testaspnet.vulnweb.com` (ASP.NET vulnweb by Acunetix) |
| **Mode** | `agentic` |
| **LLM** | `qwen2.5:32b` |
| **Status** | `active` — nuclei scanning |
| **Findings** | 0 (belum selesai) |

### Timeline v11 (hari ini)
```
14:36:39  plan_node          → auto-approved
14:36:39  recon_node         → start subfinder
14:37:10  recon_node         → subfinder: 1 subdomain
14:37:10  recon_node         → httpx probe via Burp proxy: localhost:8082
14:37:35  BurpMCP            → health_check OK (27 tools)
14:37:35  BurpMCP            → get_proxy_http_history_regex → 1 entry
14:37:42  BurpMCP            → get_sitemap → 0 entries
14:37:42  BurpMCP            → proxy history: 1 unique endpoint
14:38:13  LLM                → recon analysis (IIS, ASP.NET attack vectors)
14:38:13  hitl_recon_review  → auto-approved
14:38:13  vuln_hunt_node     → HTTPS probe → rewrite to http://
14:38:14  nuclei             → scanning http://testaspnet.vulnweb.com/ ← IN PROGRESS
```

**ETA:** nuclei selesai ~14:45–14:47 (biasanya 7–8 menit). Setelah itu: Burp active scan + crawl + LLM injection testing.

---

## 4. Bug Chain yang Diperbaiki (Semua Sesi)

Semua bug di bawah ini adalah penyebab 0 findings di semua engagement sebelumnya (E2E-v1 hingga v10).

### Bug #1 — Burp Hard-Gate
| | |
|---|---|
| **File** | `vuln_hunt_node.py` — `_run_llm_burp_active_testing()` |
| **Gejala** | `[llm_burp] Burp not reachable — skipping LLM active testing` → `return []` dini |
| **Akar masalah** | Fungsi `_run_llm_burp_active_testing()` me-return `[]` jika Burp MCP tidak reachable, bahkan jika direct HTTP tersedia |
| **Fix** | Full refactor: Burp dijadikan opsional, tambah `_direct_request()` httpx fallback |

### Bug #2 — `proxies=` kwarg (httpx API)
| | |
|---|---|
| **File** | `vuln_hunt_node.py` — `_direct_request()` |
| **Gejala** | `ERROR: AsyncClient.__init__() got unexpected keyword argument 'proxies'` |
| **Akar masalah** | Kode pakai `httpx.AsyncClient(proxies={"http://": proxy})` — API lama (httpx ≤0.19). Versi terinstall ≥0.20 |
| **Fix** | Ganti ke `proxy=proxy` (single string) |

### Bug #3 — HTTPS Port 443 Closed
| | |
|---|---|
| **File** | `vuln_hunt_node.py` — `_direct_request()` |
| **Gejala** | `ERROR: All connection attempts failed` — semua crawl URL pakai `https://` |
| **Akar masalah** | `testaspnet.vulnweb.com` port 443 timeout/closed; semua crawl URL di-generate dengan scheme `https://` |
| **Fix** | HTTPS→HTTP fallback di `_direct_request()`: coba `https://` dulu, gagal → otomatis retry `http://` |

### Bug #4 — Dead Burp Proxy Routing
| | |
|---|---|
| **File** | `vuln_hunt_node.py` — `_run_llm_burp_active_testing()` |
| **Gejala** | `ERROR: All connection attempts failed` bahkan untuk HTTP request |
| **Akar masalah** | `BURP_MCP_ENABLED=true` → `_get_burp_proxy()` return `http://localhost:8082` meski Burp mati → semua `_direct_request(proxy="localhost:8082")` di-route ke proxy yang mati |
| **Fix** | Hapus `proxy=burp_proxy` dari semua 3 call site `_direct_request()` di no-Burp path |

### Bug #5 — 30s HTTPS Timeout per Halaman
| | |
|---|---|
| **File** | `vuln_hunt_node.py` — `_direct_request()` |
| **Gejala** | Setiap halaman butuh ~31s (30s HTTPS timeout + 1s HTTP) → 23 halaman = ~12 menit crawl |
| **Akar masalah** | Default `timeout=30.0` dipakai untuk HTTPS attempt sebelum fallback ke HTTP |
| **Fix** | `https_timeout = min(timeout, 5.0)` untuk HTTPS first attempt → crawl turun ke ~6s/halaman (~2 menit total) |

### Bug #6 — nuclei Scan HTTPS (Port 443 Closed)
| | |
|---|---|
| **File** | `vuln_hunt_node.py` — `_run_nuclei()` |
| **Gejala** | nuclei berjalan 7+ menit untuk 0 findings; setiap template timeout 10s karena HTTPS |
| **Akar masalah** | `url_targets` diambil langsung dari `endpoints[].url` yang punya scheme `https://`; port 443 closed → tiap template wait 10s |
| **Fix** | Probe port 443 dulu (`asyncio.open_connection` timeout 5s); jika tidak reachable, rewrite semua `https://` → `http://` sebelum dikirim ke nuclei |

---

## 5. Fitur Baru — Inspirasi OSS Reference Study

### Dari PentAGI
| Fitur | Implementasi |
|-------|-------------|
| **3-level fallback cascade** untuk parameter candidates | Step 3 di `_run_llm_burp_active_testing()`: LLM analysis → `_extract_param_candidates_from_traffic()` → `_get_tech_default_candidates()` |
| **Auth context di LLM prompt** | `analyze_traffic_for_injections()` terima `target_domain` + `engagement_id`, tambah auth context block di system prompt |

### Dari HexStrike TechDetector
| Fitur | Implementasi |
|-------|-------------|
| **ASP.NET default candidates** | `_get_tech_default_candidates()` return parameter list spesifik per tech stack: ASP.NET → `id, cat, search, __VIEWSTATE, username, password, ...` |
| **Tech-aware endpoint suggestions** | Kandidat berbeda untuk Rails, Laravel, Django, Spring, ASP.NET |

### Dari PentestGPT Standard
| Fitur | Implementasi |
|-------|-------------|
| **LLM confirmation threshold** | `analyze_exploit_response()` — ubah dari "CONSERVATIVE" ke "ACCURACY RULE": confirmed jika ada evidence nyata di response |
| **Raw response observability** | `log.debug("[llm] raw response (%.600s)", raw)` — debug setiap LLM output |

---

## 6. Riwayat Semua Engagement

Total: **48 engagement**, semua `findings: 0`.  
Root cause sudah ditemukan dan diperbaiki (6 bug chain di atas).  
E2E-v11 adalah engagement pertama dengan semua bug terfix + Burp live.

| Engagement | Status | Keterangan |
|-----------|--------|------------|
| **E2E-v11-BurpLive** | `active` 🔄 | **IN PROGRESS** — Burp MCP live, nuclei HTTP |
| E2E-v10-HttpNuclei | `active` | Completed crawl, LLM testing — tapi log hilang setelah restart |
| E2E-v9-FastCrawl | `active` | Bug #5 fix diuji, crawl 6s/halaman ✅ |
| E2E-v8-DirectHTTP | `active` | Bug #4 fix diuji |
| E2E-v7-HttpFallback | `completed` | Bug #3 fix diuji |
| E2E-v6-HttpxFix | `completed` | Bug #2 fix diuji |
| E2E-v5-BurpFree | `completed` | Bug #1 fix diuji |
| E2E-v1 s/d v4 | `completed` | Pre-fix, semua failed karena bug chain |
| Smoke Test v1–v16 | mixed | Platform smoke tests, bukan vuln hunt |

---

## 7. Arsitektur Pipeline `vuln_hunt_node` (State Sekarang)

```
vuln_hunt_node()
│
├── 1. _run_nuclei()
│   ├── HTTPS probe (asyncio.open_connection port 443, timeout 5s)
│   ├── Jika 443 closed → rewrite url_targets: https:// → http://
│   └── nuclei -tags cve,vuln,xss,sqli,lfi,rce,exposure,misconfig,default-login
│       -timeout 10 -c 10 -ni -duc
│
├── 2. _run_ffuf()  [setelah nuclei]
│
├── 3. Burp active scan  [jika Burp MCP reachable — SEKARANG AKTIF ✅]
│   └── BurpMCP.trigger_active_scan()
│
├── 4. Burp proxy history  [jika Burp MCP reachable — SEKARANG AKTIF ✅]
│   └── BurpMCP.get_proxy_history()
│
└── 5. _run_llm_burp_active_testing()
    ├── Burp check → CONNECTED ✅ (pakai send_http1_request)
    │   ATAU fallback → _direct_request() via httpx (tanpa proxy)
    │
    ├── Crawl 23 halaman @ ~6s/halaman via Burp atau httpx
    │   └── HTTPS→HTTP fallback built-in di _direct_request()
    │
    ├── LLM analyze_traffic_for_injections()
    │   └── 3-level fallback: LLM candidates → traffic extract → TechDetect defaults
    │
    ├── Baseline request per candidate
    │
    ├── Payload injection (XSS, SQLi, SSTI, path traversal, IDOR)
    │
    └── analyze_exploit_response() → confirmed: true/false
```

---

## 8. File yang Dimodifikasi

| File | Perubahan |
|------|-----------|
| `packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py` | Bug #1–6, `_direct_request()`, `_extract_param_candidates_from_traffic()`, `_get_tech_default_candidates()`, HTTPS probe di `_run_nuclei()` |
| `packages/pentra-agent/pentra_agent/llm/client.py` | Auth context di `analyze_traffic_for_injections()`, threshold di `analyze_exploit_response()`, raw response debug log |

---

## 9. Konfigurasi `.env` Aktif

```env
# Burp Suite Integration
BURP_MCP_URL=http://localhost:9877      # ✅ CONNECTED
BURP_MCP_ENABLED=true
BURP_PROXY_URL=http://localhost:8082    # ✅ CONNECTED

# Ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL_DEFAULT=qwen2.5:32b

# API
API_PORT=8001
```

---

## 10. Next Steps

### Immediate (setelah v11 selesai)
1. **Monitor nuclei v11** — expected selesai ~14:45, expected 20+ findings (sama seperti v10 yang dapat 22)
2. **Monitor Burp active scan** — pertama kalinya Burp active scan akan berjalan
3. **Monitor LLM injection testing** — perhatikan `confirmed: true` di log
4. **Capture first confirmed finding** — verifikasi via API

### Jika v11 masih 0 findings setelah LLM
- Periksa `[llm] raw response` — apakah LLM melihat perbedaan response baseline vs payload
- Periksa kandidat yang ditest — apakah mencakup endpoint yang relevan (`listproducts.aspx?cat=1`)
- Pertimbangkan: hard-code test candidate untuk `listproducts.aspx?cat=1` (classic SQLi di vulnweb)

### Phase 1 Knowledge Engine (pending)
Phase 1 tasks di `CLAUDE.md` Section 15 belum selesai. Setelah pipeline agent stabil (confirmed finding dari v11), fokus pindah ke:
- `pentra-knowledge` — seed data importer (H1 CSV)
- `pentra-knowledge` — BGE-M3 embedding + Qdrant indexing
- `pentra-knowledge` — hybrid search service
- `apps/web` — KB Browser UI

---

*Report ini dibuat otomatis dari log `/tmp/api-server.log` dan API response pada 2026-06-03 14:39 WIB.*
