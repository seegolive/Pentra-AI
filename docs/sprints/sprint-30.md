# Sprint 30 — Scan Quality Enhancement
> Target: Mendekati kualitas enterprise scanner (Acunetix / Invicti / Burp Suite Pro)
> Estimasi total: 6–8 hari development
> Prereq: Sprint 18–29 + UI-1/2/3 COMPLETE, v1.0.0 released

---

## Konteks & Motivasi

Enterprise tools unggul di 5 area yang Pentra AI belum miliki secara penuh:

| Area | Enterprise | Pentra AI Sekarang | Gap |
|------|-----------|-------------------|-----|
| Proof-based verification | Automated safe exploit | Hanya time delay | HIGH |
| WAF bypass / payload mutation | Unicode, double-encode, comment inject | Raw payload saja | HIGH |
| Behavioral response baseline | Multi-dimensional diff | Status code + timing saja | MEDIUM |
| JS/SPA crawling | Embedded browser engine | httpx static HTML only | MEDIUM |
| CVE auto-update | Daily 200K+ plugin update | Manual nuclei | LOW |

Sprint 30 menyelesaikan **3 dari 5** gap tersebut secara pragmatis menggunakan
tools yang sudah ada di stack (Playwright sudah ada, nuclei sudah ada, WAFProfiler sudah ada).

---

## Task List

### Task 30.1 — Nuclei Template Auto-Update ✅ Target: 3 jam

**File:** `apps/worker/app/tasks/maintenance.py` (buat baru atau tambah ke existing)

**Apa yang dibangun:**
- Celery beat task `update_nuclei_templates()` yang jalankan `nuclei -update-templates`
- Schedule: setiap malam jam 02:00 WIB
- Broadcast event `TEMPLATES_UPDATED` via WebSocket setelah selesai
- Log count templates sebelum dan sesudah update

**Acceptance criteria:**
- `uv run celery -A app.worker:celery_app call tasks.maintenance.update_nuclei_templates` berjalan tanpa error
- Celery beat schedule entry ditambahkan ke config
- Event `TEMPLATES_UPDATED` muncul di live feed jika WebSocket aktif
- Minimal 5 unit tests (mock subprocess, mock broadcast)

**File yang perlu diubah/dibuat:**
```
apps/worker/app/tasks/maintenance.py     ← buat baru
apps/worker/app/worker.py                ← tambah beat schedule entry
apps/worker/tests/test_maintenance.py    ← buat baru, minimal 5 tests
```

---

### Task 30.2 — Payload Mutation Engine ✅ Target: 1.5 hari

**File:** `packages/pentra-tools/pentra_tools/mutation/payload_mutator.py` (buat baru)

**Apa yang dibangun:**

`PayloadMutator` class yang generate variasi payload untuk bypass WAF,
berdasarkan WAF type yang sudah dideteksi WAFProfiler (Sprint 18).

**4 kategori mutasi yang wajib diimplementasikan:**

```
Kategori 1 — URL Encoding
  single encode:  ' → %27
  double encode:  ' → %2527
  partial encode: hanya encode karakter spesifik
  hex encode:     ' → 0x27

Kategori 2 — Case Variation (bypass keyword filter)
  UNION → UnIoN / uNiOn / UNION
  SELECT → SeLeCt / select / SELECT
  WAITFOR → wAiTfOr
  AND → aNd
  Randomized case per karakter

Kategori 3 — Comment Injection (bypass space filter)
  space → /**/ (SQL block comment)
  space → %09 (tab)
  space → %0a (newline)
  space → %0d%0a (CRLF)
  space → +  (URL encoded space)

Kategori 4 — WAF-Specific Bypass
  cloudflare: unicode fullwidth apostrophe, --+- suffix, \r substitution
  akamai:     chunked encoding hints, header manipulation hints
  f5:         %u0027 unicode escape, null byte injection
  imperva:    scientific notation for numbers, operator substitution
  generic:    HTML entity encoding, null byte (%00) injection
```

**Integrasi ke pipeline:**
- `vuln_hunt_node.py` — sebelum kirim setiap payload, run `PayloadMutator.mutate(payload, waf_type)`
- WAF type diambil dari `recon_result.waf_type` yang sudah ada
- Jika WAF tidak terdeteksi → gunakan generic mutations saja
- Deduplicate mutasi yang identik sebelum kirim

**Output contoh:**
```python
mutator = PayloadMutator()
payloads = mutator.mutate("1' AND SLEEP(5)--", waf_type="cloudflare")
# Returns:
# ["1' AND SLEEP(5)--",                    # original
#  "1%27%20AND%20SLEEP(5)--",              # url encoded
#  "1%2527%2520AND%2520SLEEP(5)--",        # double encoded
#  "1'/**/AND/**/SLEEP(5)--",              # comment inject
#  "1\u2019 AND SLEEP(5)--",               # unicode apostrophe (cf bypass)
#  "1' aNd SLEEP(5)--+--",                 # case + cf suffix
#  ...]
```

**Acceptance criteria:**
- Minimal 8 variasi output per payload untuk WAF yang diketahui
- Minimal 3 variasi untuk generic (tanpa WAF)
- Tidak ada duplikat dalam output
- Minimal 20 unit tests (test setiap kategori + WAF-specific + dedup)
- `pnpm build` dan `uv run pytest packages/pentra-tools -q` pass

**File yang perlu dibuat:**
```
packages/pentra-tools/pentra_tools/mutation/__init__.py
packages/pentra-tools/pentra_tools/mutation/payload_mutator.py
packages/pentra-tools/tests/test_payload_mutator.py   ← minimal 20 tests
```

**File yang perlu diubah:**
```
packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
  → import PayloadMutator
  → wrap payload generation dengan mutator
  → test semua variasi, return findings untuk variasi yang berhasil
```

---

### Task 30.3 — Behavioral Response Baseline ✅ Target: 1.5 hari

**File:** `packages/pentra-tools/pentra_tools/analysis/response_baseline.py` (buat baru)

**Apa yang dibangun:**

`ResponseBaseline` class yang establish fingerprint normal response per endpoint,
lalu bandingkan setiap test response untuk deteksi anomali secara multi-dimensional.

**Scoring system:**

```
Dimensi                          Skor jika anomali
─────────────────────────────────────────────────
Content length delta > 200 bytes    +30
Response time > 3× baseline avg     +40
Status code berubah                 +25
DB error string ditemukan           +50
Error page appeared (baru)          +20
Content hash berbeda signifikan     +15

Threshold konfirmasi: score >= 40
Di bawah threshold → jangan laporkan sebagai finding
```

**DB error patterns yang wajib dideteksi:**
```python
DB_ERROR_PATTERNS = [
    # MSSQL
    r"microsoft.*sql.*server",
    r"unclosed quotation mark",
    r"incorrect syntax near",
    r"conversion failed when converting",
    # MySQL
    r"you have an error in your sql syntax",
    r"warning.*mysql_",
    r"mysql_fetch_array",
    # PostgreSQL
    r"pg_query\(\):",
    r"psql.*error",
    r"unterminated quoted string",
    # Oracle
    r"ora-[0-9]{5}",
    r"oracle.*driver",
    # Generic
    r"sql syntax.*error",
    r"database error",
    r"odbc.*error",
]
```

**Integrasi ke pipeline:**
```python
# Di vuln_hunt_node.py — sebelum loop payload:
baseline = ResponseBaseline()
await baseline.establish(url, param, normal_value="1")

# Saat testing setiap payload:
response = await send_payload(url, param, payload)
anomaly = baseline.is_anomalous(url, response)

if anomaly.score >= 40:
    # Candidate finding — lanjut ke triage
    finding = Finding(
        confidence=anomaly.score,
        evidence=anomaly.evidence_detail,
        ...
    )
```

**Acceptance criteria:**
- `establish()` kirim 3 request, simpan average profile
- `is_anomalous()` return `AnomalyScore` dengan score (0–100) dan evidence detail
- Minimal 15 unit tests:
  - test timing anomaly detection
  - test content length delta detection
  - test DB error pattern matching (semua 4 database)
  - test status code change
  - test score calculation (kombinasi dimensi)
  - test threshold boundary (39 tidak trigger, 40 trigger)
- `uv run pytest packages/pentra-tools -q` pass

**File yang perlu dibuat:**
```
packages/pentra-tools/pentra_tools/analysis/__init__.py
packages/pentra-tools/pentra_tools/analysis/response_baseline.py
packages/pentra-tools/tests/test_response_baseline.py  ← minimal 15 tests
```

**File yang perlu diubah:**
```
packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
  → import ResponseBaseline
  → establish baseline per endpoint sebelum testing
  → ganti hard-coded time check dengan is_anomalous()
```

---

### Task 30.4 — Proof-Based SQLi Verification ✅ Target: 2 hari

**File:** `packages/pentra-tools/pentra_tools/scanners/sqli_prover.py` (buat baru)

**Apa yang dibangun:**

Layer verifikasi setelah SQLi candidate ditemukan — konfirmasi dengan
3 teknik proof yang berbeda, tanpa destructive action.

**3 teknik proof yang wajib diimplementasikan:**

```
Teknik 1 — Boolean Differential (paling reliable)
  Kirim 2 payload: true condition dan false condition
  True:  AND '1'='1   (selalu true)
  False: AND '1'='2   (selalu false)
  → Jika response true ≈ baseline DAN response false ≠ baseline
  → Confirmed boolean-based SQLi

Teknik 2 — Error-Based Proof (hanya jika error visible)
  MSSQL: CONVERT(int, 'pentra_sqli_proof')
         Expected: "Conversion failed when converting..."
  MySQL: extractvalue(1, concat(0x7e, 'pentra_sqli_proof'))
         Expected: XPATH syntax error
  → Jika error message mengandung string proof → Confirmed

Teknik 3 — Time Differential (sudah ada, enhance)
  Kirim 2 payload: delay=5s dan delay=0s
  → Jika response1 - response2 ≈ 5s (±1s) → Confirmed time-based
  → LEBIH RELIABLE daripada single timing check sekarang

Output ProofResult:
  confirmed: bool
  proof_type: "boolean_differential" | "error_based" | "time_differential"
  evidence: str  ← human-readable explanation
  confidence: int  ← 0-100
  request_count: int  ← berapa request digunakan untuk proof
```

**Integrasi ke pipeline:**
```
vuln_hunt_node.py:
  1. Deteksi SQLi candidate (sudah ada)
  2. Jalankan SQLiProver.prove(url, param, db_type)
  3. Hanya laporkan sebagai CONFIRMED jika proof berhasil
  4. Include proof_type dan evidence di finding
```

**Acceptance criteria:**
- Minimal 15 unit tests (mock HTTP responses)
- Test setiap proof technique untuk setiap DB type (MSSQL, MySQL, PostgreSQL)
- Test false positive scenarios (slow network bukan SQLi)
- Integration dengan vuln_hunt_node — finding hanya CONFIRMED jika proof pass
- E2E test: jalankan di testaspnet.vulnweb.com, konfirmasi findings lebih credible

**File yang perlu dibuat:**
```
packages/pentra-tools/pentra_tools/scanners/sqli_prover.py
packages/pentra-tools/tests/test_sqli_prover.py    ← minimal 15 tests
```

**File yang perlu diubah:**
```
packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
  → import SQLiProver
  → after SQLi candidate detected: run prover
  → only report CONFIRMED if prover returns confirmed=True
  → add proof_type and evidence to finding metadata
```

---

### Task 30.5 — JS/SPA Crawler Node ✅ Target: 2 hari

**File:** `packages/pentra-tools/pentra_tools/crawlers/js_crawler.py` (buat baru)

**Apa yang dibangun:**

Playwright-based crawler untuk discover endpoints di JavaScript-heavy apps
(React, Angular, Vue, Next.js). Playwright sudah ada di stack untuk E2E tests —
tinggal install Python side (`playwright` pip package).

**Yang harus dilakukan:**
```python
class JSCrawler:
    async def crawl(self, url: str, auth: AuthConfig, timeout: int = 30) -> CrawlResult:
        """
        1. Launch headless Chromium via Playwright
        2. Inject auth cookies/headers jika ada
        3. Intercept semua network requests (XHR, Fetch, WebSocket)
        4. Navigate ke URL
        5. Wait for network idle
        6. Click links, buttons yang visible (max 20 interactions)
        7. Fill dan submit forms yang ditemukan (dengan safe values)
        8. Return semua unique endpoints yang terdeteksi

        CrawlResult:
          endpoints: list[Endpoint]  ← URL + method + params
          forms: list[Form]          ← action + method + fields
          js_files: list[str]        ← untuk offline analysis
          api_calls: list[ApiCall]   ← XHR/fetch detected
        """
```

**Integrasi ke pipeline:**
```
Buat crawler_node.py baru di pentra_agent/nodes/
Pipeline order:
  osint_node → plan_node → recon_node → CRAWLER_NODE (baru) → vuln_hunt_node

crawler_node.py:
  - Terima scope dari recon result
  - Untuk setiap live host: jalankan JSCrawler
  - Merge JS-discovered endpoints dengan httpx-discovered endpoints
  - Pass combined list ke vuln_hunt_node
```

**Kondisi skip:**
- Jika target tidak punya `<script>` tags yang significant → skip JS crawler, pakai httpx saja
- Jika timeout → return partial result, jangan fail seluruh scan
- Jika headless tidak tersedia → graceful fallback ke httpx only

**Acceptance criteria:**
- `pip install playwright` + `playwright install chromium` berhasil
- JSCrawler return endpoints dari React-based app yang tidak ditemukan httpx
- Test menggunakan Juice Shop (React-based) sebagai target
- Minimal 10 unit tests (mock Playwright, test endpoint extraction)
- Graceful fallback jika Playwright tidak available
- Tidak break scan pipeline jika JS crawler timeout

**File yang perlu dibuat:**
```
packages/pentra-tools/pentra_tools/crawlers/__init__.py
packages/pentra-tools/pentra_tools/crawlers/js_crawler.py
packages/pentra-agent/pentra_agent/nodes/crawler_node.py
packages/pentra-tools/tests/test_js_crawler.py     ← minimal 10 tests
```

**File yang perlu diubah:**
```
packages/pentra-agent/pentra_agent/graph.py
  → tambah crawler_node setelah recon_node
  → update edge: recon_node → crawler_node → vuln_hunt_node

packages/pentra-agent/requirements.txt atau pyproject.toml
  → tambah playwright dependency
```

---

## Urutan Eksekusi

```
Hari 1:   Task 30.1 (3 jam)  → Task 30.2 mulai
Hari 2-3: Task 30.2 selesai  → Task 30.3 mulai
Hari 3-4: Task 30.3 selesai
Hari 5-6: Task 30.4 (Proof-based SQLi)
Hari 7-8: Task 30.5 (JS Crawler)
```

Lakukan `uv run pytest packages/ -q` setelah setiap task — harus 0 failed.

---

## Validation Checklist

```
[ ] Task 30.1 — Nuclei auto-update
    [ ] Celery task berjalan
    [ ] Beat schedule entry ada
    [ ] 5 unit tests pass

[ ] Task 30.2 — Payload Mutation Engine
    [ ] PayloadMutator.mutate() return >= 8 variasi untuk known WAF
    [ ] Cloudflare bypass payloads dihasilkan
    [ ] 20 unit tests pass
    [ ] Integrasi ke vuln_hunt_node

[ ] Task 30.3 — Behavioral Baseline
    [ ] ResponseBaseline.establish() kirim 3 baseline requests
    [ ] is_anomalous() return AnomalyScore dengan score + evidence
    [ ] DB error patterns detected (MSSQL, MySQL, PostgreSQL, Oracle)
    [ ] 15 unit tests pass
    [ ] Integrasi ke vuln_hunt_node

[ ] Task 30.4 — Proof-based SQLi
    [ ] 3 proof techniques: boolean diff, error-based, time diff
    [ ] false positive scenario tidak trigger (slow network)
    [ ] 15 unit tests pass
    [ ] E2E: testaspnet.vulnweb.com findings lebih credible

[ ] Task 30.5 — JS Crawler
    [ ] Playwright crawl discover API calls di Juice Shop
    [ ] Graceful fallback jika Playwright unavailable
    [ ] crawler_node masuk ke pipeline graph
    [ ] 10 unit tests pass

[ ] Final
    [ ] uv run pytest packages/ apps/ -q → 422+ passing, 0 failed
    [ ] npx playwright test → 90/90 pass
    [ ] E2E scan di testaspnet: lebih banyak findings vs pre-Sprint-30
    [ ] git commit -m "feat(scan): Sprint 30 — enterprise scan quality"
    [ ] Update PROGRESS.md
```

---

## Expected Impact

Setelah Sprint 30 selesai:

```
WAF Bypass:     payload yang sebelumnya diblock Cloudflare
                sekarang bisa sampai ke aplikasi

False Positives: findings lebih sedikit tapi lebih akurat
                 karena proof-based verification + behavioral baseline

SPA Coverage:   target React/Angular/Vue sekarang bisa di-crawl
                secara proper — endpoint tidak lagi invisible

CVE Coverage:   selalu up-to-date dengan nuclei templates terbaru
                tanpa manual update
```

Pentra AI setelah Sprint 30 akan berada di level yang sebanding dengan
Acunetix Community atau reNgine v2.2 dalam hal scan quality, dengan keunggulan
tambahan: self-hosted, domain fine-tuned LLM, dan AASE regulatory context.
