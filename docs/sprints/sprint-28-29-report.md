# Sprint 27–29 Report — Test Suite Hardening & KB Expansion Prep

> Generated: 2026-06-12 | Branch: `main` | Pushed: `8c27c12..07a91ff`

---

## Ringkasan

Fokus sesi ini: bersihkan label status yang stale di `PROGRESS.md`, perbaiki bug
test suite yang menyebabkan hang/gagal, dan tambah test coverage untuk kode
produksi yang sebelumnya 0% tertest (Bugcrowd scraper, WebSocket live feed
manager).

**Hasil akhir test suite:**

| Package | Before | After |
|---------|--------|-------|
| pentra-tools | 165 passed, 3 skipped | 165 passed, 3 skipped |
| pentra-agent | 146 passed (5 e2e tests `--ignore`'d, hang) | **151 passed, 4 skipped** — no `--ignore` needed |
| apps/worker | 4 passed, 1 failed (5 total) | **18 passed, 0 failed** |
| apps/api | 51 passed | **63 passed** |

---

## Sprint 27 ✅ COMPLETE (2/2)

| Task | Detail | Commit |
|------|--------|--------|
| 27.1 | Fix label stale Sprint 23/24 (→ COMPLETE), preset count (5→6), vuln_hunt tool count (9→13), backlog cleanup | `725c216`, `28caf03` |
| 27.2 | Fair baseline benchmark pentra-ft vs base model: pentra-ft 8 confirmed findings vs 6 confirmed (fair timeout 1800s) | `725c216` |

Juga: fix bug `ReportViewer.tsx` (duplicate `const url` redeclaration) → `9e27585`,
dan tambah Sprint 21.7 (takeover detector mocks, 7/7 tests) + 21.8
(`learning_query`, 5/5 tests) → `207f4c4`.

---

## Sprint 28 ✅ COMPLETE (3/3)

### 28.1 — Fix `test_e2e_pipeline.py` network hang (`e093f74`)

**Masalah:** Full suite `pentra-agent` hang tanpa batas waktu di sandbox tanpa
internet. Root cause: 12 fungsi async di `recon_node` dan `vuln_hunt_node`
membuat koneksi network real ke `testaspnet.vulnweb.com` (terlihat sebagai
`SYN-SENT` ke `44.238.29.244:443`), tidak pernah di-mock di test.

**Fix:** Tambah `AsyncMock` patch untuk:
- `recon_node`: `probe_rate_limit`, `profile_waf`, `detect_subdomain_takeovers`
- `vuln_hunt_node` (9 scanner): extended checks, SOAP/XXE, GraphQL, race
  condition, CORS, JWT, second-order SQLi, business logic, SSRF

**Hasil:** `test_e2e_pipeline.py` 5 passed, 4 skipped (16-17s). Full
pentra-agent suite 151 passed, 4 skipped (~24s) — tanpa `--ignore`.

### 28.2 — KB alternative source: Bugcrowd scraper test coverage (`0338d61`)

`apps/worker/app/tasks/bugcrowd_scraper.py` ada sejak Sprint 12 tapi **0 tes,
0 record di KB**. Tambah `apps/worker/tests/test_bugcrowd_scraper.py` — 13 tes:
- `_guess_vuln_class` — 8 kasus kategori → vuln_class mapping
- `_SEVERITY_MAP` — p1–p5 dan severity bernama
- `_scrape_all` — pagination via `has_next_page`, `max_records` cap, empty
  page stop, HTTP error graceful stop (semua mocked `httpx`, no network)

**Catatan:** Menjalankan scrape sungguhan terhadap `bugcrowd.com/disclosures.json`
butuh akses internet — **belum bisa dilakukan di sandbox ini** (lihat backlog).

### 28.3 — Frontend WebSocket live feed stress test (`34a026c`)

`app/ws/manager.ConnectionManager` — broadcaster live feed produksi yang
dipakai semua node agent via `broadcast_and_persist` — **0 tes**. Tambah
`apps/api/tests/test_ws_connection_manager.py` — 12 tes:
- Replay history ke client baru saat connect
- Event `ping` tidak masuk buffer
- Fan-out ke 50 client sekaligus
- 600 event broadcast vs `BUFFER_SIZE=500` (cap + urutan terjaga)
- 200 broadcast concurrent — tidak ada event hilang/duplikat
- Dead-connection pruning di bawah load campuran alive/dead
- Isolasi per-engagement (broadcast eng-A tidak nyasar ke eng-B)
- `broadcast_and_persist` — skip DB untuk `ping`/`LLM_STREAM`, jalan tanpa DB

---

## Sprint 29 (1/1 known tasks)

### 29.1 — Fix bug `__wrapped__` di `test_embed_and_upsert_success` (`07a91ff`)

`_embed_and_upsert` adalah fungsi async biasa tanpa decorator, tapi test
mem-patch `_embed_and_upsert.__wrapped__` yang tidak pernah ada →
`AttributeError` saat collection. Hapus patch yang salah tersebut.

**Hasil:** apps/worker 18/18 passing (dari 17/18).

---

## Backlog Tersisa (Sprint 29)

| Item | Prioritas | Blocker |
|------|-----------|---------|
| Jalankan Bugcrowd scrape live untuk isi KB | Sedang | Butuh akses internet ke `bugcrowd.com` — tidak tersedia di sandbox ini |

---

## Commit Log Sesi Ini

```
07a91ff fix: Sprint 29.1 — remove bogus __wrapped__ patch in test_embed_and_upsert_success
34a026c test: Sprint 28.3 COMPLETE — add WebSocket live feed stress tests
0338d61 test: Sprint 28.2 — add Bugcrowd scraper test coverage
f3edb10 docs: Sprint 28 — record test_e2e_pipeline.py network hang fix
e093f74 fix: test_e2e_pipeline.py — mock all recon/vuln-hunt network probes
1c8a895 docs: fix stale labels Sprint 23+24, update Sprint 27
28caf03 docs: PROGRESS.md — link Sprint 21.7/21.8 to commit 207f4c4, bump git commit ref
207f4c4 test: add Sprint 21.7 takeover detector mocks, Task 21.8 learning_query tests, sprint planning docs
9e27585 fix: ReportViewer.tsx — resolve duplicate const url redeclaration
725c216 docs: Sprint 27 COMPLETE — fix stale labels Sprint 23+24, fair benchmark data
```

Pushed: `8c27c12..07a91ff` → `origin/main`
