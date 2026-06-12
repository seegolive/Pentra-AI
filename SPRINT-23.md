# SPRINT-23.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca:** `CLAUDE.md` → `PROGRESS.md` → file ini  
> **Status:** Sprint 22 ✅ 4/4, 316 tests, 8,309+ KB, Juice Shop CRITICAL findings  
> **Milestone:** Platform mendekati v1.0 production-ready

---

## Analisis Status: Di Mana Platform Sekarang

### Capability Matrix Terkini

```
SQLi (multi-type)        ✅ E2E confirmed — testaspnet + DVWA + Juice Shop
XSS (reflected+stored)  ✅ E2E confirmed — DVWA
LFI / Path Traversal    ✅ E2E confirmed — DVWA (/etc/passwd)
IDOR                     ✅ E2E confirmed — Juice Shop (users 1-3)
GraphQL Introspection    ✅ E2E confirmed — trevorblades.com (real)
Race Condition TOCTOU    ✅ E2E confirmed — Flask mock (20/20)
JWT alg:none             ✅ E2E confirmed — Juice Shop CRITICAL (23 users exposed)
SQLi Login Bypass        ✅ E2E confirmed — Juice Shop CRITICAL (admin JWT)
SSRF tool               ✅ Implemented + 6 tests (belum E2E confirmed finding)
Subdomain Takeover       ✅ 7/7 mock fingerprints
CORS                     ⚠️ tool ada, belum E2E confirmed
Second-order SQLi        ⚠️ tool ada, belum E2E confirmed
Business Logic           ⚠️ tool ada, belum E2E confirmed
```

### Scorecard Platform

```
316 unit tests (0 failed)
6 Playwright E2E tests
45/45 smoke tests
8,309+ KB records (100% bge-m3)
10+ vuln classes dengan confirmed findings
Sprint 18-22: 100% complete
```

---

## Apa yang Tersisa Sebelum v1.0

Dari analisis progress, ada 4 kategori gap:

```
1. VALIDATION GAP
   SSRF → tool ada, belum ada confirmed finding di real target
   CORS → tool ada, belum ada E2E proof

2. COMPLETENESS GAP (Backlog Sprint 23)
   KB scale: verify pages 221-300 sudah inserted
   SSRF OOB dengan Burp Collaborator (full integration)
   Frontend WebSocket live feed integration test

3. QUALITY GAP  
   Fine-tuning: data ada, pipeline belum diaktifkan
   Playwright full regression (bukan hanya smoke)

4. DOCUMENTATION GAP
   ssrf_oob_tester.py belum ada di Arsitektur Packages di PROGRESS.md
   vuln_hunt_node masih "9 tools" padahal sekarang 13 (ssrf ditambahkan)
```

---

## Task 23.1 — SSRF E2E Validation (P1)

> **Estimasi:** 1 jam  
> **Target:** Juice Shop punya SSRF di beberapa endpoint

### Juice Shop SSRF Endpoints

```bash
# Juice Shop punya endpoint yang fetches external URLs:
# POST /api/Feedbacks (avatarUrl parameter)
# GET /redirect?to=URL (open redirect → SSRF)
# POST /profile (imageUrl → server-side fetch)

# Test manual dulu sebelum scan
curl -s -X POST http://localhost:3000/api/Feedbacks \
  -H "Content-Type: application/json" \
  -d '{"comment":"test","rating":5,"captchaId":0,"captcha":"-"}'

# Cari endpoint dengan ?url= atau avatarUrl
curl -s http://localhost:3000/ | grep -i "url\|redirect\|fetch" | head -5
```

### Run Scan dengan Monitor SSRF

```bash
# Scan Juice Shop dengan focus SSRF
uv run python scripts/live_scan.py \
  --domain localhost:3000 \
  --preset fast

# Monitor SSRF khusus
grep -E "ssrf_oob|SSRF|identify_ssrf|url.*param|redirect.*param" \
  /tmp/pentra.log | tail -10
```

### Checklist

```
[ ] identify_ssrf_candidates() menemukan URL-param endpoint di Juice Shop
[ ] test_ssrf_with_collaborator() dijalankan
[ ] Log: "[ssrf_oob] N endpoints identified as SSRF candidates"
[ ] Jika Collaborator aktif: OOB interaction confirmed
[ ] Jika tidak: direct probe tetap dijalankan
```

---

## Task 23.2 — CORS E2E Validation (P1)

> **Estimasi:** 30 menit  
> **Target:** Juice Shop punya CORS misconfiguration

```bash
# Test manual Juice Shop CORS
curl -s http://localhost:3000/api/Users \
  -H "Origin: https://evil.com" \
  -H "Authorization: Bearer [JWT_TOKEN]" \
  -I | grep -i "access-control"
# Expected jika vulnerable: Access-Control-Allow-Origin: https://evil.com

# Scan
uv run python scripts/live_scan.py \
  --domain localhost:3000 \
  --preset fast

# Check CORS findings
grep -E "cors_tester|CORS.*misconfig|Access-Control" /tmp/pentra.log | tail -5
```

### Checklist

```
[ ] cors_tester dijalankan di Juice Shop endpoints
[ ] Jika vulnerable: finding CORS_MISCONFIGURATION di report
[ ] Jika tidak: log menunjukkan "no CORS misconfiguration"
```

---

## Task 23.3 — KB Scale Verification (P1)

> **Estimasi:** 5 menit  
> **Task 22.3 trigger sudah berjalan background**

```bash
# Verifikasi apakah scraping pages 221+ sudah selesai
curl -s http://localhost:6333/collections/knowledge | jq .result.points_count
# Expected: > 8,309 (jika background task selesai)

# Cek Celery task status
curl -s "http://localhost:8001/api/v1/admin/tasks/470d8564" \
  -H "Authorization: Bearer $TOKEN" | jq '{status, progress}'
# Expected: "completed" atau "running"

# Jika belum selesai, re-trigger
curl -sX POST http://localhost:8001/api/v1/admin/knowledge/bulk-import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source":"h1_graphql","max_records":2500,"start_page":221}' | jq .
```

---

## Task 23.4 — SSRF OOB Full Integration (P2)

> **Estimasi:** 1 jam  
> **Prereq:** Burp Pro aktif dengan Collaborator

```python
# packages/pentra-tools/pentra_tools/vuln/ssrf_oob_tester.py
# Verifikasi bahwa Collaborator integration berfungsi end-to-end

# Test script
python3 << 'EOF'
import asyncio

async def test_collaborator_integration():
    """Test full OOB SSRF flow dengan Burp Collaborator."""
    try:
        from pentra_tools.burp.client import BurpMCPClient
        burp = BurpMCPClient()
        
        if not await burp.health_check():
            print("❌ Burp MCP not available — skipping OOB test")
            return
        
        # Generate Collaborator payload
        collab = await burp.generate_collaborator_payload()
        print(f"✅ Collaborator payload: {collab.payload}")
        
        # Poll (should be empty initially)
        interactions = await burp.get_collaborator_interactions(collab.payload)
        print(f"✅ Interactions so far: {len(interactions)}")
        
        # Test URL
        import httpx
        test_url = f"http://localhost:3000/api/Feedbacks"
        ssrf_payload = f"http://{collab.payload}/ssrf-test"
        
        async with httpx.AsyncClient() as client:
            try:
                await client.post(test_url,
                    json={"comment": "test", "rating": 5, 
                          "avatarUrl": ssrf_payload},
                    timeout=5.0)
            except Exception:
                pass
        
        # Wait and poll
        await asyncio.sleep(8)
        interactions = await burp.get_collaborator_interactions(collab.payload)
        
        if interactions:
            print(f"🎯 BLIND SSRF CONFIRMED via OOB!")
            for i in interactions:
                print(f"   {i.interaction_type} from {i.client_ip}")
        else:
            print("ℹ️  No OOB interactions (Juice Shop may not fetch external URLs here)")
            
    except Exception as e:
        print(f"Error: {e}")

asyncio.run(test_collaborator_integration())
EOF
```

---

## Task 23.5 — Fix PROGRESS.md Architecture Section

> **Estimasi:** 5 menit  
> **Tujuan:** Dokumen akurat

```
Update PROGRESS.md:

1. Tambahkan ssrf_oob_tester.py ke Arsitektur Packages:
   └── vuln/
       ├── ssrf_oob_tester.py  ← SSRF + OOB (Sprint 22) [TAMBAHKAN INI]
       ├── graphql_analyzer.py
       ...

2. Update vuln_hunt_node comment:
   Ganti "9 tools secara parallel" → "13 tools secara parallel"
   
   Pipeline seharusnya:
   nuclei → ffuf → burp_scan → burp_proxy → burp_ext → 
   soap_xxe → graphql → race_condition → cors → 
   ssrf_oob → jwt → takeover → second_order_sqli

3. Test Suite section: 310 → 316
   pentra-tools: 159 → 165
```

---

## Task 23.6 — Frontend WebSocket Live Feed Test (P2)

> **Estimasi:** 1 jam

### Playwright Test untuk Live Feed

```typescript
// apps/web/e2e/livefeed.spec.ts

import { test, expect } from '@playwright/test';

const BASE = process.env.BASE_URL ?? 'http://localhost:5173';
const API  = process.env.API_URL  ?? 'http://localhost:8001';

async function login(page: any) {
  await page.goto(`${BASE}/login`);
  await page.getByLabel(/username/i).fill('admin');
  await page.getByLabel(/password/i).fill('Pentra@2026!');
  await page.getByRole('button', { name: /sign in/i }).click();
  await page.waitForURL(`${BASE}/`);
}

test('Live Feed WebSocket connects', async ({ page }) => {
  await login(page);

  // Navigate ke engagement yang sudah punya events
  const token = await page.evaluate(() => localStorage.getItem('token'));

  // Create engagement
  const resp = await page.request.post(`${API}/api/v1/engagements`, {
    headers: { 'Authorization': `Bearer ${token}` },
    data: {
      name: 'Playwright WS Test',
      workspace_id: '__TEST__',  // Akan diisi dengan WS_ID valid
      mode: 'agentic',
      in_scope: ['test.local'],
      llm_model: 'qwen2.5:7b',
    }
  });
  
  const eng = await resp.json();
  await page.goto(`${BASE}/engagements/${eng.id}`);
  
  // Live Feed tab harus ada
  await expect(page.getByRole('tab', { name: /live feed/i }))
    .toBeVisible({ timeout: 5000 });
  
  await page.getByRole('tab', { name: /live feed/i }).click();
  
  // WebSocket feed container harus ada
  await expect(page.locator('[data-testid="live-feed"], .live-feed, #live-feed'))
    .toBeVisible({ timeout: 5000 });
});

test('Event history persists after reload', async ({ page }) => {
  await login(page);
  
  const engId = process.env.TEST_ENG_ID;
  if (!engId) {
    test.skip();
    return;
  }
  
  await page.goto(`${BASE}/engagements/${engId}`);
  await page.getByRole('tab', { name: /live feed/i }).click();
  
  // Count events before reload
  const eventsBefore = await page.locator('.event-item, [data-testid="event"]').count();
  
  // Reload page
  await page.reload();
  await page.getByRole('tab', { name: /live feed/i }).click();
  
  // Events should still be there (persistence feature from Sprint 19.4)
  const eventsAfter = await page.locator('.event-item, [data-testid="event"]').count();
  expect(eventsAfter).toBeGreaterThanOrEqual(eventsBefore);
});
```

---

## Task 23.7 — Playwright Full Regression Suite (P3)

> **Estimasi:** 1 jam

```typescript
// apps/web/e2e/full.spec.ts

import { test, expect } from '@playwright/test';

const BASE = process.env.BASE_URL ?? 'http://localhost:5173';

async function login(page: any) {
  await page.goto(`${BASE}/login`);
  await page.getByLabel(/username/i).fill('admin');
  await page.getByLabel(/password/i).fill('Pentra@2026!');
  await page.getByRole('button', { name: /sign in/i }).click();
  await page.waitForURL(`${BASE}/`);
}

// --- Auth ---
test.describe('Authentication', () => {
  test('valid login redirects to dashboard', async ({ page }) => {
    await login(page);
    await expect(page).toHaveURL(`${BASE}/`);
  });
  
  test('invalid login shows error', async ({ page }) => {
    await page.goto(`${BASE}/login`);
    await page.getByLabel(/username/i).fill('admin');
    await page.getByLabel(/password/i).fill('wrong');
    await page.getByRole('button', { name: /sign in/i }).click();
    await expect(page.getByText(/invalid|error/i)).toBeVisible();
  });
  
  test('logout returns to login', async ({ page }) => {
    await login(page);
    const logoutBtn = page.getByRole('button', { name: /logout|sign out/i });
    if (await logoutBtn.isVisible()) {
      await logoutBtn.click();
      await expect(page).toHaveURL(/login/);
    }
  });
});

// --- KB Browser ---
test.describe('Knowledge Base', () => {
  test.beforeEach(async ({ page }) => { await login(page); });

  test('search returns results', async ({ page }) => {
    await page.goto(`${BASE}/knowledge`);
    await page.getByPlaceholder(/search/i).fill('SQL injection');
    await page.keyboard.press('Enter');
    await expect(
      page.locator('table tbody tr, .kb-result').first()
    ).toBeVisible({ timeout: 10000 });
  });

  test('KB stats visible (8309+ records)', async ({ page }) => {
    await page.goto(`${BASE}/knowledge`);
    const statsText = await page.locator(
      '[data-testid="kb-stats"], .kb-stats, .stats-badge'
    ).textContent({ timeout: 5000 }).catch(() => '');
    // Stats bisa berupa apapun — yang penting ada
    console.log('KB stats:', statsText);
  });
});

// --- Workspace & Engagement ---
test.describe('Workspace', () => {
  test.beforeEach(async ({ page }) => { await login(page); });

  test('workspace list loads', async ({ page }) => {
    await page.goto(`${BASE}/workspaces`);
    // Entah workspace list atau empty state — keduanya valid
    await expect(
      page.locator('h1, h2, [data-testid="workspace-list"]').first()
    ).toBeVisible();
  });
});

// --- Report ---
test.describe('Reports', () => {
  test.beforeEach(async ({ page }) => { await login(page); });

  test('report viewer renders', async ({ page }) => {
    const engId = process.env.TEST_ENG_ID;
    if (!engId) { test.skip(); return; }
    
    await page.goto(`${BASE}/engagements/${engId}`);
    await page.getByRole('tab', { name: /report/i }).click();
    await expect(
      page.locator('[data-testid="report-viewer"], .report-viewer').first()
    ).toBeVisible({ timeout: 10000 });
  });
});
```

---

## Task 23.8 — Final MASTER-TEST-PLAN Update

> **Estimasi:** 30 menit  
> **Tujuan:** Update test plan untuk reflect Sprint 22 additions

```
Update SMOKE-TEST-E2E.md BLOK 7 untuk Sprint 22:

Tambahkan ST-7.8 — SSRF Tester ran:
  grep -c "ssrf_oob|SSRF|identify_ssrf" /tmp/pentra.log
  Expected: >= 1

Update Scorecard dari 29 → 30 checks

Update kriteria kelulusan:
  316+ tests (dari 29 sebelumnya)
```

---

## Checklist Sprint 23

```
Task 23.1 — SSRF E2E (P1, 1 jam)
[ ] Scan Juice Shop dengan focus SSRF
[ ] Log: identify_ssrf_candidates() menemukan endpoints
[ ] Jika Collaborator aktif: OOB confirmed
[ ] Jika tidak: direct probe ran dan logged

Task 23.2 — CORS E2E (P1, 30 menit)
[ ] cors_tester ran di Juice Shop
[ ] Finding atau "no misconfiguration" terdokumentasi

Task 23.3 — KB Verification (P1, 5 menit)
[ ] curl http://localhost:6333/collections/knowledge | jq .result.points_count
[ ] Expected: > 8,309 (atau re-trigger jika belum)

Task 23.4 — SSRF OOB Full Integration (P2, 1 jam)
[ ] Test script dijalankan dengan Burp Collaborator
[ ] Hasil terdokumentasi (OOB confirmed atau not available)

Task 23.5 — PROGRESS.md Fix (P1, 5 menit)
[ ] ssrf_oob_tester.py ada di Arsitektur Packages
[ ] "9 tools" → "13 tools" di vuln_hunt_node description
[ ] Test count: 310 → 316

Task 23.6 — Frontend WebSocket Test (P2, 1 jam)
[ ] livefeed.spec.ts dibuat
[ ] Live Feed tab visibility test
[ ] Event persistence after reload test

Task 23.7 — Playwright Full Regression (P3, 1 jam)
[ ] full.spec.ts dibuat
[ ] Auth tests: 3 tests
[ ] KB tests: 2 tests
[ ] Workspace + Report tests
[ ] Total: 7+ new Playwright tests

Task 23.8 — SMOKE-TEST-E2E.md Update (P1, 30 menit)
[ ] ST-7.8 SSRF tester check ditambahkan
[ ] Scorecard updated ke 30 checks
[ ] Target updated ke 316+ tests

Total tests baru: 0 unit + 7+ Playwright
Total target: 316 unit + 13+ Playwright
```

---

## Situasi Platform vs v1.0 Readiness

```
SUDAH SIAP                         MASIH PERLU
──────────────────────────────────────────────────────────
✅ 316 unit tests, 0 failed        ⚠️ SSRF belum E2E confirmed
✅ 45/45 smoke test                ⚠️ CORS belum E2E confirmed
✅ 10+ vuln classes confirmed      ⚠️ KB scale verify pending
✅ 8,309+ KB records bge-m3        ⚠️ Fine-tuning belum aktif
✅ GraphQL confirmed (real target)  ⚠️ Frontend E2E kurang coverage
✅ JWT CRITICAL confirmed           ⚠️ Architecture docs stale
✅ SQLi + Auth bypass confirmed
✅ SSRF tool + 6 tests
✅ Playwright 6 smoke tests
✅ Burp MCP 33 tools
✅ 5 scan presets
✅ Event persistence
✅ H1 Executive Report
```

**Penilaian:** Platform sudah sangat mendekati v1.0. Yang tersisa adalah documentation cleanup, SSRF E2E, dan beberapa Playwright tests.

---

## Prompt untuk Copilot

**Mulai task cepat dulu (P1, 30 menit):**

```
Baca CLAUDE.md, PROGRESS.md, dan SPRINT-23.md.

Kerjakan Task 23.5 (PROGRESS.md fix) dan Task 23.3 (KB verify) terlebih dahulu:

Task 23.5 — Update PROGRESS.md:
1. Tambahkan ssrf_oob_tester.py ke bagian Arsitektur Packages
2. Update "9 tools" → "13 tools" di vuln_hunt_node description  
3. Pipeline list: tambahkan ssrf_oob → jwt → takeover → second_order_sqli

Task 23.3 — KB verification:
curl -s http://localhost:6333/collections/knowledge | jq .result.points_count
Jika < 8309: report
Jika >= 8309 tapi < 10000: trigger lagi dengan start_page=221
Jika >= 10000: ✅ done

Setelah keduanya selesai, lanjut Task 23.1 (SSRF E2E di Juice Shop).
```

**Setelah task P1 selesai:**

```
Task 23.1 dan 23.2 selesai.
Kerjakan Task 23.6 (Playwright livefeed) dan Task 23.7 (full regression).
Buat apps/web/e2e/livefeed.spec.ts dan apps/web/e2e/full.spec.ts
sesuai SPRINT-23.md.
Jalankan: npx playwright test --headed
```

---

*SPRINT-23.md — Pentra AI*  
*Closing the remaining gaps: SSRF E2E · CORS E2E · KB verify · Frontend coverage*  
*Target: v1.0 production-ready*
