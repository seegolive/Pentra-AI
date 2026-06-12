# SPRINT-21.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `PROGRESS.md` → file ini  
> **Status:** Sprint 20 ✅, 302 tests, 45/45 smoke, 8,309 KB records  
> **Filosofi Sprint 21:** Validasi > Fitur Baru

---

## Mengapa Sprint 21 Fokus Validasi

```
Sprint 18: Authenticated Scan — belum pernah tested di target nyata
Sprint 19: GraphQL, Race Condition, JWT — belum ada confirmed finding
Sprint 19: CORS Tester — berjalan tapi belum ada E2E proof
Sprint 20: Subdomain Takeover — berjalan tapi belum ada confirmed finding

Masalah yang ditemukan smoke test:
  Bug #1: datetime tz-aware → crash saat start engagement   → FIXED ✅
  Bug #2: silent exception → engagement stuck status active  → FIXED ✅

Kesimpulan: Platform perlu lebih banyak E2E validation
            di berbagai target sebelum tambah fitur baru
```

---

## Task 21.1 — Fix PROGRESS.md Inconsistencies (5 menit)

```bash
# Update bagian Test Suite di PROGRESS.md
# Ganti "268 passing" → "302 passing"
# Update Phase 1 bge-m3 line
# Update smoke test dari 43/45 → 45/45

sed -i 's/268 passing/302 passing/g' PROGRESS.md
sed -i 's/2,757\/2,758/8,309\/8,309/g' PROGRESS.md
```

Atau via Copilot:
```
Update PROGRESS.md:
1. Test Suite section: 268 → 302 (tools: 156, agent: 146)
2. Phase 1 bge-m3 line: 2,757/2,758 → 8,309/8,309
3. Smoke test: 43/45 → 45/45 PASS (kedua bug sudah difix)
4. Add note di Sprint 20: "Bug fixes: datetime tz (a8d29d7), 
   silent exception handler (cf5cee7)"
```

---

## Task 21.2 — DVWA Setup + Authenticated Scan E2E

> **Estimasi:** 1-2 jam  
> **Validates:** Sprint 18.6 (Authenticated Scan) + IDOR + business logic

### Setup DVWA

```bash
# Option A: Docker (paling cepat)
docker run -d \
  --name dvwa \
  -p 8080:80 \
  vulnerables/web-dvwa

# Tunggu sampai up
sleep 10
curl -s http://localhost:8080/login.php | grep -i "dvwa"
# Expected: ada "DVWA" di response

# DVWA default credentials: admin / password
# Setup: http://localhost:8080/setup.php → Create/Reset Database
```

### Run Authenticated Scan

```bash
# Via CLI dengan auto-login
uv run python scripts/live_scan.py \
  --domain localhost:8080 \
  --preset authenticated \
  --auth-login-url "http://localhost:8080/login.php" \
  --auth-user admin \
  --auth-pass password

# Monitor log
tail -f /tmp/pentra.log | grep -E \
  "auth.*session|cookie.*inject|idor.*candidate|\
  sqli.*confirmed|xss.*confirmed|authenticated"
```

### Checklist E2E DVWA

```
[ ] Agent login berhasil (session cookie diperoleh)
[ ] Recon menemukan /dvwa/* endpoints
[ ] GF patterns match: ?id=, ?page=, ?file= (DVWA punya semua ini)
[ ] Vuln hunt berjalan dengan auth headers ter-inject
[ ] SQLi ditemukan di /vulnerabilities/sqli/?id=
[ ] XSS ditemukan di /vulnerabilities/xss_r/?name=
[ ] LFI ditemukan di /vulnerabilities/fi/?page=
[ ] IDOR ditemukan di /vulnerabilities/idor/?id=
[ ] Business logic: price manipulation atau duplicate action
[ ] Findings >= 5 (DVWA adalah deliberately vulnerable)
[ ] Report PDF berhasil generate dengan authenticated findings
```

- [ ] PASS / [ ] FAIL

---

## Task 21.3 — GraphQL E2E Validation

> **Estimasi:** 30 menit  
> **Target:** Server dengan GraphQL endpoint yang aktif

### Option A: Public GraphQL target (legal)

```bash
# GraphQL Hotels — public test API
# https://countries.trevorblades.com/

uv run python scripts/live_scan.py \
  --domain countries.trevorblades.com \
  --preset fast

# Expected findings:
# - Introspection enabled (low)
# - Mungkin batch query abuse (medium)
```

### Option B: Self-hosted GraphQL via Docker

```bash
# DVWA punya GraphQL? Cek
# Atau pakai vulnerable-graphql:
docker run -d -p 4000:4000 dolevf/damn-vulnerable-graphql-application

curl -s -X POST http://localhost:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}' | jq .
# Expected: {"data":{"__typename":"Query"}}

# Run scan
uv run python scripts/live_scan.py \
  --domain localhost:4000 \
  --preset fast
```

### Checklist GraphQL E2E

```
[ ] detect_graphql_endpoints() menemukan /graphql
[ ] extract_schema() berhasil (introspection enabled)
[ ] test_introspection_enabled() → finding LOW severity
[ ] test_batch_query_attack() dijalankan
[ ] test_sqli_via_graphql() dijalankan
[ ] Log: "[graphql] N findings at endpoint"
[ ] Findings muncul di report dengan vuln_class: INFORMATION_DISCLOSURE
```

- [ ] PASS / [ ] FAIL

---

## Task 21.4 — Race Condition E2E Validation

> **Estimasi:** 30 menit  
> **Target:** DVWA atau endpoint yang punya race-prone pattern

### Setup di DVWA

```bash
# DVWA punya endpoint yang bisa di-test race condition:
# - /vulnerabilities/csrf/ — form submission
# - Atau buat simple Flask app untuk test

# Simple race condition test server
python3 << 'EOF'
from flask import Flask, request, jsonify
import threading

app = Flask(__name__)
voucher_used = {}
lock = threading.Lock()

@app.route('/redeem', methods=['POST'])
def redeem():
    code = request.json.get('code', '')
    # Bug: tidak pakai atomic lock → race condition
    if code not in voucher_used:
        voucher_used[code] = True
        return jsonify({"success": True, "discount": "50%"})
    return jsonify({"success": False, "message": "Already used"})

app.run(port=5555)
EOF
```

```bash
# Test dengan Pentra AI
curl -s localhost:5555/redeem \
  -H "Content-Type: application/json" \
  -d '{"code":"PROMO2026"}'
# Should return success first time

# Scan dengan live_scan (akan detect /redeem sebagai race candidate)
uv run python scripts/live_scan.py \
  --domain localhost:5555 \
  --preset fast

# Check log
grep "race_condition\|concurrent.*burst\|RACE_CONDITION" /tmp/pentra.log
```

### Checklist Race Condition E2E

```
[ ] identify_race_candidates() menemukan /redeem sebagai candidate
[ ] test_race_condition() mengirim 15 concurrent requests
[ ] success_count > 1 (race condition terdeteksi)
[ ] Finding dengan vuln_class: RACE_CONDITION muncul
[ ] Severity: high atau medium
```

- [ ] PASS / [ ] FAIL

---

## Task 21.5 — JWT E2E Validation

> **Estimasi:** 30 menit  
> **Target:** App dengan JWT auth

### Setup simple JWT-vulnerable server

```bash
python3 << 'EOF'
from flask import Flask, request, jsonify
import base64, json

app = Flask(__name__)

def decode_jwt_unsafe(token):
    """Deliberately unsafe - no signature verification"""
    try:
        parts = token.split('.')
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        return payload
    except:
        return None

@app.route('/api/me', methods=['GET'])
def me():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({"error": "Unauthorized"}), 401
    
    # BUG: no signature verification!
    payload = decode_jwt_unsafe(auth[7:])
    if payload:
        return jsonify({"user": payload})  # Returns ANY payload!
    return jsonify({"error": "Invalid token"}), 401

@app.route('/api/login', methods=['POST'])
def login():
    # Return a simple JWT
    import base64, json
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b'=').decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub":"user1","role":"user"}).encode()).rstrip(b'=').decode()
    return jsonify({"token": f"{header}.{payload}.fakesig"})

app.run(port=5556)
EOF
```

```bash
# Get token dulu
TOKEN_TEST=$(curl -s -X POST http://localhost:5556/api/login | jq -r .token)
echo "JWT: $TOKEN_TEST"

# Scan
uv run python scripts/live_scan.py \
  --domain localhost:5556 \
  --preset fast

# Expected: JWT none algorithm bypass ditemukan
grep "jwt_tester\|none algorithm\|JWT_VULNERABILITY\|Invalid.*signature" /tmp/pentra.log
```

### Checklist JWT E2E

```
[ ] extract_jwt_from_response() mendapat token dari /api/login
[ ] forge_none_algorithm() menghasilkan token dengan alg=none
[ ] Server menerima forged token → confirmed critical finding
[ ] Finding: "JWT None Algorithm Authentication Bypass"
[ ] Severity: critical
[ ] cvss_vector: CVSS:3.1/AV:N/...
```

- [ ] PASS / [ ] FAIL

---

## Task 21.6 — Frontend Playwright Tests

> **Estimasi:** 1 jam  
> **Target:** Tutup gap frontend E2E testing

```bash
# Setup Playwright
cd apps/web
pnpm add -D @playwright/test
npx playwright install chromium

# Buat test file
cat > e2e/smoke.spec.ts << 'EOF'
import { test, expect } from '@playwright/test';

const BASE = 'http://localhost:5173';

test.describe('ST-6.1 Login Flow', () => {
  test('login valid → dashboard', async ({ page }) => {
    await page.goto(`${BASE}/login`);
    await page.getByLabel(/username/i).fill('admin');
    await page.getByLabel(/password/i).fill('Pentra@2026!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await expect(page).toHaveURL(`${BASE}/`);
  });

  test('login invalid → error', async ({ page }) => {
    await page.goto(`${BASE}/login`);
    await page.getByLabel(/username/i).fill('admin');
    await page.getByLabel(/password/i).fill('wrong');
    await page.getByRole('button', { name: /sign in/i }).click();
    await expect(page.getByText(/invalid|incorrect|error/i)).toBeVisible();
  });

  test('protected route → redirect to login', async ({ page }) => {
    await page.goto(`${BASE}/workspaces`);
    await expect(page).toHaveURL(/login/);
  });
});

test.describe('ST-6.2 Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE}/login`);
    await page.getByLabel(/username/i).fill('admin');
    await page.getByLabel(/password/i).fill('Pentra@2026!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(`${BASE}/`);
  });

  test('dashboard shows stats', async ({ page }) => {
    await expect(page.getByText(/engagement|finding|knowledge/i).first()).toBeVisible();
  });
});

test.describe('ST-6.3 KB Browser', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE}/login`);
    await page.getByLabel(/username/i).fill('admin');
    await page.getByLabel(/password/i).fill('Pentra@2026!');
    await page.getByRole('button', { name: /sign in/i }).click();
  });

  test('KB search returns results', async ({ page }) => {
    await page.goto(`${BASE}/knowledge`);
    await page.getByPlaceholder(/search/i).fill('SQL injection');
    await page.keyboard.press('Enter');
    await expect(page.locator('table tbody tr, [data-testid="kb-result"]').first())
      .toBeVisible({ timeout: 10000 });
  });
});
EOF

# Run
npx playwright test e2e/smoke.spec.ts --headed
```

### Checklist Frontend

```
[ ] Login valid → dashboard
[ ] Login invalid → error message
[ ] Protected route → redirect
[ ] Dashboard loads (stats visible)
[ ] KB search returns results
[ ] Playwright report: 5/5 tests pass
```

- [ ] PASS / [ ] FAIL

---

## Task 21.7 — Subdomain Takeover E2E

> **Estimasi:** 15 menit  
> **Target:** Buat CNAME record yang dangling (test environment)

```bash
# Simulasi: Mock DNS yang return CNAME ke github.io
# Tidak perlu real DNS — test logic saja

python3 << 'EOF'
import asyncio
from pentra_tools.recon.takeover_detector import check_takeover_fingerprint
from unittest.mock import AsyncMock, MagicMock

async def test():
    # Simulate: subdomain dengan CNAME ke github.io
    # Dan response berisi GitHub Pages fingerprint
    mock_resp = MagicMock()
    mock_resp.text = "<h1>There isn't a GitHub Pages site here.</h1>"
    mock_resp.status_code = 404
    
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    
    result = await check_takeover_fingerprint(
        "old-blog.target.com",
        "target-org.github.io",
        mock_client
    )
    
    if result:
        print(f"✅ Takeover detected: {result.service} (confidence: {result.confidence})")
    else:
        print("❌ No takeover detected (unexpected)")

asyncio.run(test())
EOF
```

- [ ] PASS / [ ] FAIL

---

## Task 21.8 — EngagementLearning in plan_node (Sprint 20 P2 sisa)

> **Estimasi:** 2 jam  
> **Impact:** Agent plan lebih kontekstual dari history

Dari Sprint 20 backlog:

```python
# packages/pentra-agent/pentra_agent/nodes/plan_node.py
# Tambahkan query learnings SEBELUM generate plan:

from pentra_agent.utils.learning_query import query_similar_learnings

async def plan_node(state: PentraState) -> dict:
    domain = state["target"]["domain"]
    tech_stack = state.get("tech_stack", [])
    
    # Query past learnings
    past_learnings = await query_similar_learnings(
        tech_stack=tech_stack,
        db_url=os.getenv("DATABASE_URL"),
        limit=3,
    )
    
    if past_learnings:
        learning_context = "\n".join(
            f"Past similar engagement found {l.findings_count} findings. "
            f"Effective: {l.effective_tools}. "
            f"High-value patterns: {[ep.get('pattern') for ep in l.high_value_endpoints[:3]]}"
            for l in past_learnings
        )
        logger.info("[plan_node] %d past learnings injected", len(past_learnings))
    else:
        learning_context = ""
    
    # Pass ke LLM
    plan = await llm.plan_engagement(
        target=state["target"],
        scope=state["scope"],
        knowledge_hints=knowledge,
        learning_context=learning_context,
    )
```

```python
# Tests
# packages/pentra-agent/tests/test_plan_node_learning.py

@pytest.mark.asyncio
async def test_plan_node_injects_learning_context():
    """plan_node harus inject learning context ke LLM jika ada past learnings."""
    from unittest.mock import AsyncMock, patch
    
    mock_learning = MagicMock()
    mock_learning.findings_count = 8
    mock_learning.effective_tools = ["nuclei", "burp"]
    mock_learning.high_value_endpoints = [{"pattern": "/products?id="}]
    
    with patch('pentra_agent.utils.learning_query.query_similar_learnings',
               return_value=[mock_learning]):
        with patch('pentra_agent.nodes.plan_node.LLMClient') as MockLLM:
            mock_llm = AsyncMock()
            mock_llm.plan_engagement = AsyncMock(return_value="Test plan")
            MockLLM.return_value = mock_llm
            
            # Capture the learning_context passed to LLM
            calls = []
            async def capture_plan(**kwargs):
                calls.append(kwargs)
                return "Test plan"
            mock_llm.plan_engagement = capture_plan
            
            from pentra_agent.nodes.plan_node import plan_node
            state = {
                "target": {"domain": "target.com", "ip_ranges": [], "base_urls": []},
                "scope": {"in_scope": ["target.com"], "out_of_scope": []},
                "llm_model": "qwen2.5:7b",
                "tech_stack": ["ASP.NET"],
                "knowledge_context": [],
                "messages": [],
            }
            await plan_node(state)
    
    assert any('learning_context' in str(c) for c in calls), \
        "learning_context should be passed to plan_engagement"


def test_query_similar_learnings_empty_db():
    """Harus return empty list jika DB tidak tersedia."""
    import asyncio
    from pentra_agent.utils.learning_query import query_similar_learnings
    result = asyncio.run(query_similar_learnings(
        tech_stack=["ASP.NET"],
        db_url=None,  # No DB
    ))
    assert result == []
```

---

## Checklist Sprint 21

```
Task 21.1 — Fix PROGRESS.md (5 menit)
[ ] Test count: 268 → 302
[ ] bge-m3: 2,757/2,758 → 8,309/8,309
[ ] Smoke test: 43/45 → 45/45
[ ] Bug fix notes ditambahkan

Task 21.2 — DVWA Authenticated Scan E2E (1-2 jam)
[ ] DVWA running via Docker
[ ] Auto-login berhasil (session cookie)
[ ] SQLi/XSS/LFI ditemukan di DVWA
[ ] Authenticated findings di report
[ ] >= 5 confirmed findings

Task 21.3 — GraphQL E2E (30 menit)
[ ] GraphQL endpoint terdeteksi
[ ] Introspection finding (LOW) confirmed
[ ] Batch query test ran

Task 21.4 — Race Condition E2E (30 menit)
[ ] /redeem endpoint terdeteksi sebagai candidate
[ ] Concurrent burst test ran (15 requests)
[ ] Race condition confirmed

Task 21.5 — JWT E2E (30 menit)
[ ] JWT diperoleh dari /api/login
[ ] None algorithm bypass confirmed
[ ] Critical finding di report

Task 21.6 — Playwright Frontend (1 jam)
[ ] 5 tests pass: login, error, redirect, dashboard, KB search

Task 21.7 — Takeover E2E Mock (15 menit)
[ ] check_takeover_fingerprint() confirmed dengan mock

Task 21.8 — EngagementLearning di plan_node (2 jam)
[ ] learning_query.py diimplementasi
[ ] plan_node inject learning context ke LLM
[ ] 2 unit tests pass
[ ] Log: "[plan_node] N past learnings injected"

Total tests baru: 2-5 tests
Total tests target: 302 + 5 = 307+
```

---

## Prompt untuk Copilot

**Mulai Task 21.1 (cepat, 5 menit):**

```
Baca CLAUDE.md dan PROGRESS.md.

Task 21.1: Update PROGRESS.md untuk fix inconsistencies:
1. Test Suite section: ganti 268 → 302 (pentra-tools: 156, pentra-agent: 146)
2. Phase 1 bge-m3 line: ganti 2,757/2,758 → 8,309/8,309
3. Sprint 20 smoke test line: tambahkan "45/45 PASS (bugs fixed: a8d29d7, cf5cee7)"

Setelah update, commit: "docs: update PROGRESS.md metrics to current state"
```

**Mulai Task 21.2 (utama):**

```
Baca CLAUDE.md, PROGRESS.md, dan SPRINT-21.md.

Task 21.2: E2E Authenticated Scan dengan DVWA.

1. Setup DVWA via Docker: docker run -d --name dvwa -p 8080:80 vulnerables/web-dvwa
2. Verifikasi DVWA up: curl -s http://localhost:8080/login.php | grep -i dvwa
3. Run scan: uv run python scripts/live_scan.py --domain localhost:8080 
   --preset authenticated --auth-login-url http://localhost:8080/login.php 
   --auth-user admin --auth-pass password
4. Monitor log dan laporkan findings
5. Expected: SQLi/XSS/LFI confirmed di /vulnerabilities/*
```

**Setelah 21.2 done, lanjut 21.3 + 21.4 + 21.5:**

```
Task 21.2 selesai. Kerjakan Task 21.3, 21.4, dan 21.5 secara berurutan:
- 21.3: GraphQL via countries.trevorblades.com atau damn-vulnerable-graphql Docker
- 21.4: Race condition via Flask test server di port 5555
- 21.5: JWT via Flask test server di port 5556
Setup server, run scan, verifikasi findings, laporkan hasil.
```

---

*SPRINT-21.md — Pentra AI*  
*Fokus: Validasi fitur Sprint 18-20 di berbagai target*  
*Tidak ada fitur baru — hanya membuktikan yang sudah ada benar-benar bekerja*
