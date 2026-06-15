# MASTER-TEST-PLAN.md — Pentra AI
> **Versi:** 1.0  
> **Coverage:** Sprint 1–16 (semua fitur yang pernah dibangun)  
> **Target:** 35/35 smoke test, E2E-v16 validated  
> **Estimasi total:** 4–6 jam (termasuk waktu agent berjalan)

---

## Rekomendasi: Testing Dulu, Bukan Pengembangan

**Kenapa testing sekarang lebih penting dari fitur baru:**

```
Sprint 14 menambah: EngagementLearning, ReAct, CVSS
Sprint 15 menambah: OSINT node, Playbooks, RateLimitDetector,
                     VulnerabilityCorrelator, ChainSummarizer
Sprint 16 menambah: Triage Gate, Anomaly Detection, Dev Psychology

E2E terakhir yang valid: Sprint 12 (v11 — 18 findings)
Artinya: 3 sprint fitur BELUM PERNAH DITEST di kondisi nyata.
```

Tanpa testing, kita tidak tahu:
- Apakah OSINT node tidak crash saat crt.sh timeout?
- Apakah Triage Gate KILL findings yang benar?
- Apakah semua node masih berantai dengan benar setelah rebuild?
- Apakah frontend masih berfungsi dengan DB schema yang berubah 3x?

**Aturan: Jangan tambah fitur sampai testing selesai dan hasilnya didokumentasikan.**

---

## Cara Membaca Dokumen Ini

```
Setiap test case punya:
  ID      → format T-{BLOK}.{NOMOR} (e.g., T-1.1)
  Status  → [ ] belum / [✅] pass / [❌] fail
  Target  → apa yang divalidasi
  Command → command yang dijalankan
  Expected → output yang diharapkan
  Action jika fail → langkah perbaikan
```

Jalankan semua test secara berurutan dari atas ke bawah. Jika ada yang fail, perbaiki dulu sebelum lanjut ke blok berikutnya.

---

## Persiapan Global

```bash
# Jalankan SEKALI sebelum mulai semua test

# 1. Apply semua migrations
cd apps/api
uv run alembic upgrade head
echo "Migration: $(uv run alembic current)"
# Expected: a28fd25517b3 (head)

# 2. Start API
nohup uv run uvicorn app.main:app \
  --host 0.0.0.0 --port 8001 \
  &>/tmp/pentra-test.log &
sleep 3

# 3. Verifikasi API up
curl -s http://localhost:8001/health | jq -r .status
# Expected: "ok"

# 4. Simpan token (dipakai di semua test)
export TOKEN=$(curl -sX POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Pentra@2026!"}' | jq -r .access_token)
echo "TOKEN: ${TOKEN:0:30}..."
# Expected: token dimulai dengan "ey..."

# 5. Buat resources untuk testing
export WS_ID=$(curl -sX POST http://localhost:8001/api/v1/workspaces \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Master Test '$(date +%Y%m%d-%H%M)'"}' | jq -r .id)
echo "WS_ID: $WS_ID"
# Expected: UUID

export ENG_ID=$(curl -sX POST http://localhost:8001/api/v1/engagements \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Test Engagement v$(date +%Y%m%d-%H%M)\",
    \"workspace_id\": \"$WS_ID\",
    \"mode\": \"semi_auto\",
    \"in_scope\": [\"testaspnet.vulnweb.com\"],
    \"out_of_scope\": [],
    \"llm_model\": \"qwen2.5-coder:32b\"
  }" | jq -r .id)
echo "ENG_ID: $ENG_ID"
# Expected: UUID
```

---

## BLOK 1 — Infrastruktur Dasar

### T-1.1 API Health Check
```bash
curl -s http://localhost:8001/health | jq .
```
- Expected: `{"status": "ok"}`
- [ ] Pass / [ ] Fail

### T-1.2 Database Connected
```bash
curl -s http://localhost:8001/api/v1/setup/status \
  -H "Authorization: Bearer $TOKEN" | jq '{is_configured, requires_setup}'
```
- Expected: `is_configured: true, requires_setup: false`
- [ ] Pass / [ ] Fail

### T-1.3 Migration Head Benar
```bash
cd apps/api && uv run alembic current 2>&1 | tail -1
```
- Expected: `a28fd25517b3 (head)`
- [ ] Pass / [ ] Fail

### T-1.4 OpenAPI Docs Accessible
```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/docs
curl -s http://localhost:8001/openapi.json | jq '.info.title'
```
- Expected: `200` dan `"Pentra AI API"`
- [ ] Pass / [ ] Fail

### T-1.5 Ollama Connected + Models
```bash
curl -s http://localhost:11434/api/tags | jq '[.models[].name]'
```
- Expected: list berisi minimal `bge-m3` dan `qwen2.5-coder:32b` (atau model lain)
- [ ] Pass / [ ] Fail

### T-1.6 Qdrant Running
```bash
curl -s http://localhost:6333/healthz
```
- Expected: `healthz` atau HTTP 200
- [ ] Pass / [ ] Fail

### T-1.7 Redis Running
```bash
redis-cli ping
```
- Expected: `PONG`
- [ ] Pass / [ ] Fail

### T-1.8 StartupValidator di Log
```bash
grep -i "startup\|validator\|✅\|WARNING" /tmp/pentra-test.log | head -10
```
- Expected: Log menunjukkan StartupValidator berjalan, semua checks pass
- [ ] Pass / [ ] Fail

**BLOK 1 Score: __ / 8**

---

## BLOK 2 — Authentication & Authorization

### T-2.1 Login Valid
```bash
curl -sX POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Pentra@2026!"}' | \
  jq '{has_token: (.access_token != null), token_type}'
```
- Expected: `has_token: true, token_type: "bearer"`
- [ ] Pass / [ ] Fail

### T-2.2 Login Invalid → 401
```bash
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}'
```
- Expected: `401`
- [ ] Pass / [ ] Fail

### T-2.3 Protected Endpoint Tanpa Token → 401
```bash
curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:8001/api/v1/workspaces
```
- Expected: `401`
- [ ] Pass / [ ] Fail

### T-2.4 Workspace Isolation (User B tidak bisa lihat workspace User A)
```bash
# Buat user B
curl -sX POST http://localhost:8001/api/v1/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"test_userb","email":"b@test.local","password":"Test@2026!","role":"operator"}'

# Login user B
TOKEN_B=$(curl -sX POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test_userb","password":"Test@2026!"}' | jq -r .access_token)

# User B list workspaces
curl -s http://localhost:8001/api/v1/workspaces \
  -H "Authorization: Bearer $TOKEN_B" | jq length
```
- Expected: `0` (User B tidak punya workspace sendiri)
- [ ] Pass / [ ] Fail

### T-2.5 Internal API Token Protection
```bash
# Tanpa header → 422
CODE1=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:8001/api/v1/internal/engagements/$ENG_ID/findings/bulk \
  -H "Content-Type: application/json" \
  -d '{"findings":[]}')

# Token salah → 403
CODE2=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:8001/api/v1/internal/engagements/$ENG_ID/findings/bulk \
  -H "X-Internal-Token: wrong" \
  -H "Content-Type: application/json" \
  -d '{"findings":[]}')

echo "No token: $CODE1 (expect 422), Wrong token: $CODE2 (expect 403)"
```
- Expected: `422` dan `403`
- [ ] Pass / [ ] Fail

### T-2.6 Rate Limiting Aktif
```bash
for i in $(seq 1 25); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    http://localhost:8001/api/v1/workspaces \
    -H "Authorization: Bearer $TOKEN"
done | sort | uniq -c
```
- Expected: beberapa `429` setelah N requests
- [ ] Pass / [ ] Fail

### T-2.7 Audit Log Tidak Bisa Dihapus
```bash
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE "http://localhost:8001/api/v1/engagements/$ENG_ID/audit/1" \
  -H "Authorization: Bearer $TOKEN")
echo "DELETE audit: $CODE (expect 404 or 405)"
```
- Expected: `404` atau `405` (endpoint tidak ada)
- [ ] Pass / [ ] Fail

**BLOK 2 Score: __ / 7**

---

## BLOK 3 — Knowledge Base

### T-3.1 KB Search Basic
```bash
curl -s "http://localhost:8001/knowledge/search?q=SQL+injection&top_k=3" \
  -H "Authorization: Bearer $TOKEN" | jq '.results | length'
```
- Expected: `3` (atau > 0)
- [ ] Pass / [ ] Fail

### T-3.2 KB Quality Score > 0
```bash
curl -s "http://localhost:8001/knowledge/search?q=XSS&top_k=5" \
  -H "Authorization: Bearer $TOKEN" | \
  jq '[.results[] | select(.quality_score > 0)] | length'
```
- Expected: `5` (semua punya quality_score)
- [ ] Pass / [ ] Fail

### T-3.3 KB Search dengan Filter VulnClass
```bash
curl -s "http://localhost:8001/knowledge/search?q=IDOR&vuln_class=IDOR&top_k=3" \
  -H "Authorization: Bearer $TOKEN" | jq '.results[0].vuln_class'
```
- Expected: `"IDOR"`
- [ ] Pass / [ ] Fail

### T-3.4 KB Total Records
```bash
curl -s "http://localhost:8001/api/v1/admin/stats" \
  -H "Authorization: Bearer $TOKEN" | jq .total_records
```
- Expected: `> 100` (ada seed data)
- [ ] Pass / [ ] Fail

### T-3.5 KB Manual Inject via URL
```bash
JOB=$(curl -sX POST http://localhost:8001/api/v1/knowledge/inject/url \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://portswigger.net/web-security/sql-injection"}' | jq -r .job_id)
echo "Inject job: $JOB"
```
- Expected: UUID string (bukan null)
- [ ] Pass / [ ] Fail

### T-3.6 KB Inject Job Pollable
```bash
sleep 5
curl -s "http://localhost:8001/api/v1/knowledge/inject/jobs/$JOB" \
  -H "Authorization: Bearer $TOKEN" | jq .status
```
- Expected: `"processing"` atau `"done"` (bukan null/error)
- [ ] Pass / [ ] Fail

**BLOK 3 Score: __ / 6**

---

## BLOK 4 — Agent Pipeline (Sprint 14–16 Core)

> **Blok paling penting — validasi semua fitur Sprint 14-16 bekerja bersama**

### T-4.1 WebSocket Connection
```bash
# Install wscat: npm install -g wscat
timeout 5 wscat -c "ws://localhost:8001/ws/engagements/$ENG_ID/feed?token=$TOKEN" 2>&1 | head -3
```
- Expected: `Connected` (bukan error 4001)
- [ ] Pass / [ ] Fail

### T-4.2 WebSocket Reject Invalid Token
```bash
timeout 3 wscat -c "ws://localhost:8001/ws/engagements/$ENG_ID/feed?token=invalid" 2>&1
```
- Expected: `4001` atau connection closed
- [ ] Pass / [ ] Fail

### T-4.3 Start Agent → 202 Accepted
```bash
curl -sX POST http://localhost:8001/api/v1/engagements/$ENG_ID/start \
  -H "Authorization: Bearer $TOKEN" | jq '{status, ws_url}'
```
- Expected: `{"status": "started", "ws_url": "..."}`
- [ ] Pass / [ ] Fail

### T-4.4 OSINT Node Berjalan (Sprint 15.5)
```bash
sleep 15
grep "osint_node\|crt\.sh\|h1_program" /tmp/pentra-test.log | head -5
```
- Expected: Log `[osint_node] Starting passive OSINT for testaspnet.vulnweb.com`
- [ ] Pass / [ ] Fail

### T-4.5 Plan Node Berjalan
```bash
grep "plan_node\|plan_engagement\|pentest plan" /tmp/pentra-test.log | head -3
```
- Expected: Log menunjukkan plan_node aktif
- [ ] Pass / [ ] Fail

### T-4.6 HITL Plan — AWAITING_APPROVAL Event
```bash
# Monitor selama 2 menit untuk plan HITL
timeout 120 bash -c "
  while true; do
    STATUS=$(curl -s http://localhost:8001/api/v1/engagements/$ENG_ID \
      -H 'Authorization: Bearer $TOKEN' | jq -r .status)
    echo \"Status: \$STATUS\"
    [[ \"\$STATUS\" == \"active\" ]] && break
    sleep 5
  done
"
# Approve plan HITL
curl -sX POST http://localhost:8001/api/v1/engagements/$ENG_ID/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"approve"}' | jq .status
```
- Expected: approve return `"resumed"`
- [ ] Pass / [ ] Fail

### T-4.7 Recon Node — RateLimitDetector Berjalan (Sprint 15.1)
```bash
# Tunggu recon selesai (5-10 menit)
sleep 30
grep "rate_limit_detector\|safe_rps\|rate_limit" /tmp/pentra-test.log | head -3
```
- Expected: `[rate_limit_detector] ... safe_rps=20` (atau nilai lain)
- [ ] Pass / [ ] Fail

### T-4.8 Recon Node — Subfinder + Httpx Berjalan
```bash
grep "subfinder\|httpx\|recon_node.*subdomain" /tmp/pentra-test.log | head -5
```
- Expected: Log menunjukkan subfinder menemukan subdomain
- [ ] Pass / [ ] Fail

### T-4.9 HITL Recon Approval
```bash
# Approve recon HITL (tunggu AWAITING_APPROVAL hitl_recon)
# Monitor log untuk signal
grep "hitl_recon\|AWAITING_APPROVAL" /tmp/pentra-test.log | tail -3

# Approve
curl -sX POST http://localhost:8001/api/v1/engagements/$ENG_ID/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"approve"}' | jq .status
```
- Expected: `"resumed"`
- [ ] Pass / [ ] Fail

### T-4.10 Vuln Hunt — Attack Playbooks Berjalan (Sprint 15.3)
```bash
grep "playbook\|sqli_error\|xss_reflected\|Running.*playbook" /tmp/pentra-test.log | head -5
```
- Expected: `[vuln_hunt] Running playbook 'SQL Injection — Error Based'`
- [ ] Pass / [ ] Fail

### T-4.11 Vuln Hunt — Anomaly Detection Berjalan (Sprint 16.4)
```bash
grep "ANOMALY\|SIZE_ANOMALY\|ERROR_DISCLOSURE\|REFLECTION\|anomaly" /tmp/pentra-test.log | head -5
```
- Expected: `ANOMALY SIGNALS:` muncul minimal 1x saat payload test
- [ ] Pass / [ ] Fail

### T-4.12 ReAct Loop — Thoughts di Audit Log (Sprint 14.2)
```bash
grep "react_thought\|test_injection\|skip_candidate" /tmp/pentra-test.log | head -5
```
- Expected: `[react_thought] Thought: ... Action: test_injection/skip_candidate`
- [ ] Pass / [ ] Fail

### T-4.13 Triage Gate Berjalan (Sprint 16.1)
```bash
grep "triage\|KILL\|DOWNGRADE\|PASS\|Triage complete" /tmp/pentra-test.log | head -10
```
- Expected: `[triage] Triage complete: N passed, M killed, K downgraded`
- [ ] Pass / [ ] Fail

### T-4.14 Report Node — CVSS Enrichment (Sprint 14.3)
```bash
grep "CVSS\|cvss_vector\|cvss_score\|calculate_cvss" /tmp/pentra-test.log | head -5
```
- Expected: `[report_node] CVSS enrichment: N findings`
- [ ] Pass / [ ] Fail

### T-4.15 EngagementLearning Tersimpan (Sprint 14.1)
```bash
# Setelah engagement complete
sleep 5
curl -s http://localhost:8001/api/v1/engagements/$ENG_ID/learning \
  -H "Authorization: Bearer $TOKEN" | jq '{findings_count, tech_stack}'
```
- Expected: `findings_count` > 0, `tech_stack` terisi
- [ ] Pass / [ ] Fail

### T-4.16 Findings Tersimpan di DB
```bash
curl -s "http://localhost:8001/api/v1/engagements/$ENG_ID/findings" \
  -H "Authorization: Bearer $TOKEN" | jq 'length'
```
- Expected: `> 0`
- [ ] Pass / [ ] Fail

### T-4.17 CVSS Vector ada di Semua Findings
```bash
TOTAL=$(curl -s "http://localhost:8001/api/v1/engagements/$ENG_ID/findings" \
  -H "Authorization: Bearer $TOKEN" | jq 'length')
WITH_CVSS=$(curl -s "http://localhost:8001/api/v1/engagements/$ENG_ID/findings" \
  -H "Authorization: Bearer $TOKEN" | jq '[.[] | select(.cvss_vector != null)] | length')
echo "Total: $TOTAL, With CVSS vector: $WITH_CVSS"
```
- Expected: `Total == With CVSS vector` (100%)
- [ ] Pass / [ ] Fail

### T-4.18 ENGAGEMENT_COMPLETED Event
```bash
grep "ENGAGEMENT_COMPLETED\|engagement.*complete\|report_node.*done" /tmp/pentra-test.log | head -3
```
- Expected: Log menunjukkan engagement selesai
- [ ] Pass / [ ] Fail

**BLOK 4 Score: __ / 18**

---

## BLOK 5 — Report Generation

### T-5.1 Markdown Report
```bash
curl -s "http://localhost:8001/api/v1/reports/engagements/$ENG_ID?format=markdown" \
  -H "Authorization: Bearer $TOKEN" | head -20
```
- Expected: Markdown dengan `#` headers dan findings sections
- [ ] Pass / [ ] Fail

### T-5.2 HTML Report
```bash
DIVCOUNT=$(curl -s "http://localhost:8001/api/v1/reports/engagements/$ENG_ID?format=html" \
  -H "Authorization: Bearer $TOKEN" | grep -c "<div")
echo "HTML div count: $DIVCOUNT"
```
- Expected: `> 5`
- [ ] Pass / [ ] Fail

### T-5.3 PDF Report Valid
```bash
curl -s "http://localhost:8001/api/v1/reports/engagements/$ENG_ID?format=pdf" \
  -H "Authorization: Bearer $TOKEN" \
  --output /tmp/test-report.pdf
SIZE=$(wc -c < /tmp/test-report.pdf)
TYPE=$(file /tmp/test-report.pdf | grep -o "PDF")
echo "Size: ${SIZE} bytes, Type: $TYPE"
```
- Expected: Size `> 10000` bytes dan Type `PDF`
- [ ] Pass / [ ] Fail

### T-5.4 H1 Format Report
```bash
curl -s "http://localhost:8001/api/v1/reports/engagements/$ENG_ID?format=h1" \
  -H "Authorization: Bearer $TOKEN" | jq '.[0] | keys | sort'
```
- Expected: List keys termasuk `title`, `severity`, `cvss_score`, `cvss_vector`, `steps`
- [ ] Pass / [ ] Fail

### T-5.5 CVSS Vector di H1 Report
```bash
TOTAL_H1=$(curl -s "http://localhost:8001/api/v1/reports/engagements/$ENG_ID?format=h1" \
  -H "Authorization: Bearer $TOKEN" | jq 'length')
WITH_VEC=$(curl -s "http://localhost:8001/api/v1/reports/engagements/$ENG_ID?format=h1" \
  -H "Authorization: Bearer $TOKEN" | \
  jq '[.[] | select(.cvss_vector | startswith("CVSS:3.1"))] | length')
echo "Total: $TOTAL_H1, With valid vector: $WITH_VEC"
```
- Expected: `Total == With valid vector` (100% punya valid CVSS vector)
- [ ] Pass / [ ] Fail

**BLOK 5 Score: __ / 5**

---

## BLOK 6 — Frontend UI (Manual Browser Test)

> **Prerequisite:** `cd apps/web && pnpm dev`  
> **Browser:** http://localhost:5173

### T-6.1 Login Flow
```
[ ] Buka /login → form tampil dalam dark mode
[ ] Input admin / Pentra@2026! → Sign In → redirect ke /
[ ] Dashboard menampilkan workspace "Master Test ..."
[ ] Sign out → kembali ke /login
[ ] Akses /workspaces tanpa login → redirect ke /login
```
- 5 checks: [ ] Pass / [ ] Fail

### T-6.2 Engagement Create + Live Feed
```
[ ] Buat workspace baru dari UI
[ ] Buat engagement: target testaspnet.vulnweb.com, Semi-Auto, qwen2.5-coder:32b
[ ] Tombol "Start Agent" tampil dan bisa diklik
[ ] Klik Start → Live Feed menampilkan events (biru=NODE_START)
[ ] HITL dialog muncul saat agent meminta approval
[ ] Dialog tampilkan: phase, message, data context preview
[ ] Approve dari dialog → agent lanjut (live feed berlanjut)
[ ] Status badge: Idle → Running → Waiting → Running → Completed
[ ] Refresh tab → WebSocket reconnect otomatis
[ ] Events dari sebelum refresh masih tampil (tidak hilang)
```
- 10 checks: [ ] Pass / [ ] Fail

### T-6.3 FindingsTable
```
[ ] Tab "Findings" tampilkan findings dari engagement test
[ ] Severity pills (critical/high/medium/low) dengan count
[ ] Klik severity pill → filter aktif
[ ] Search box filter by title real-time

[ ] Expand finding row → detail tampil:
    [ ] CVSS Vector (format CVSS:3.1/...) dalam monospace font
    [ ] CVE badges dengan link ke NVD (jika cve_ids ada)
    [ ] Reproduction steps sebagai numbered list
    [ ] HTTP Request/Response (truncated di 800 chars)
    [ ] Attack Chains section (jika chains tidak kosong)

[ ] Klik "Confirm" → status badge berubah ke "confirmed" hijau
[ ] Klik "False Positive" → status badge berubah
[ ] Klik "Add to KB" → success toast / tidak error
[ ] Count di footer akurat
```
- 13 checks: [ ] Pass / [ ] Fail

### T-6.4 ReportViewer
```
[ ] Tab "Report" tampilkan ReportViewer (bukan hanya tombol download)
[ ] Default: Markdown tab aktif
[ ] Markdown view: teks report dalam pre-formatted block
[ ] Switch ke HTML tab: render dalam iframe (tidak blank/error)
[ ] Tombol "Download MD" → file ter-download
[ ] Tombol "Download PDF" → file ter-download, valid dibuka
[ ] Tombol "Refresh" → report di-regenerate
```
- 7 checks: [ ] Pass / [ ] Fail

### T-6.5 Knowledge Base Browser
```
[ ] Navigasi ke /knowledge
[ ] Search "SQL injection" → hasil muncul dalam 5 detik
[ ] Filter severity "high" → filter aktif, count berkurang
[ ] Filter vuln_class "IDOR" → hanya IDOR records
[ ] Klik result → detail panel dengan key_insight dan quality_score
[ ] "Add Knowledge" button → form/modal tampil
[ ] Submit URL inject → job created (tidak error)
```
- 7 checks: [ ] Pass / [ ] Fail

**BLOK 6 Score: __ / 42**

---

## BLOK 7 — Monitoring & Admin

### T-7.1 Monitoring Schedule Set
```bash
curl -sX POST "http://localhost:8001/api/v1/engagements/$ENG_ID/monitoring/schedule" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "interval_hours": 24}' | jq .updated
```
- Expected: `true`
- [ ] Pass / [ ] Fail

### T-7.2 Monitoring Alerts Endpoint
```bash
curl -s "http://localhost:8001/api/v1/engagements/$ENG_ID/monitoring/alerts" \
  -H "Authorization: Bearer $TOKEN" | jq 'if type == "array" then length else "error" end'
```
- Expected: number (bukan error)
- [ ] Pass / [ ] Fail

### T-7.3 Recon Snapshot Tersimpan
```bash
curl -s "http://localhost:8001/api/v1/engagements/$ENG_ID/monitoring/snapshots" \
  -H "Authorization: Bearer $TOKEN" | jq 'if type == "array" then length else 0 end'
```
- Expected: `>= 1` setelah recon selesai
- [ ] Pass / [ ] Fail

### T-7.4 Worker Health
```bash
curl -s http://localhost:8001/api/v1/admin/worker/health \
  -H "Authorization: Bearer $TOKEN" | jq '{healthy, worker_count}'
```
- Expected: `healthy` true/false (tidak error), `worker_count` number
- [ ] Pass / [ ] Fail

### T-7.5 Admin Stats
```bash
curl -s http://localhost:8001/api/v1/admin/stats \
  -H "Authorization: Bearer $TOKEN" | jq '{total_knowledge_records, total_engagements}'
```
- Expected: kedua fields berisi angka
- [ ] Pass / [ ] Fail

### T-7.6 Admin Users List
```bash
curl -s http://localhost:8001/api/v1/admin/users \
  -H "Authorization: Bearer $TOKEN" | jq '[.[] | .username]'
```
- Expected: list berisi `["admin", "test_userb"]`
- [ ] Pass / [ ] Fail

### T-7.7 Backup Trigger
```bash
curl -sX POST http://localhost:8001/api/v1/admin/backup/trigger \
  -H "Authorization: Bearer $TOKEN" | jq .status
```
- Expected: `"triggered"` (tidak error)
- [ ] Pass / [ ] Fail

**BLOK 7 Score: __ / 7**

---

## BLOK 8 — Export / Import

### T-8.1 Engagement Export
```bash
EXPORT=$(curl -s "http://localhost:8001/api/v1/engagements/$ENG_ID/export" \
  -H "Authorization: Bearer $TOKEN")
echo $EXPORT | jq '{name: .engagement.name, findings: (.findings | length)}'
```
- Expected: `name` ada, `findings` >= 0
- [ ] Pass / [ ] Fail

### T-8.2 Export ke File
```bash
echo $EXPORT > /tmp/test-export.json
SIZE=$(wc -c < /tmp/test-export.json)
echo "Export size: $SIZE bytes"
```
- Expected: `> 500` bytes
- [ ] Pass / [ ] Fail

### T-8.3 Import ke Workspace Baru
```bash
WS2=$(curl -sX POST http://localhost:8001/api/v1/workspaces \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Import Test"}' | jq -r .id)

IMPORTED=$(curl -sX POST http://localhost:8001/api/v1/engagements/import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"workspace_id\": \"$WS2\", \"bundle\": $(cat /tmp/test-export.json), \"new_name\": \"Imported Test\"}")

echo $IMPORTED | jq '{id, name}'
```
- Expected: `id` ada (UUID), `name` = "Imported Test"
- [ ] Pass / [ ] Fail

### T-8.4 Imported Findings Sama
```bash
IMP_ID=$(echo $IMPORTED | jq -r .id)
ORIG_COUNT=$(curl -s "http://localhost:8001/api/v1/engagements/$ENG_ID/findings" \
  -H "Authorization: Bearer $TOKEN" | jq 'length')
IMP_COUNT=$(curl -s "http://localhost:8001/api/v1/engagements/$IMP_ID/findings" \
  -H "Authorization: Bearer $TOKEN" | jq 'length')
echo "Original: $ORIG_COUNT, Imported: $IMP_COUNT"
```
- Expected: `Original == Imported`
- [ ] Pass / [ ] Fail

**BLOK 8 Score: __ / 4**

---

## BLOK 9 — Unit Tests

### T-9.1 pentra-tools Suite
```bash
cd packages/pentra-tools
uv run pytest tests/ -q --tb=short 2>&1 | tail -5
```
- Expected: `81 passed` (atau lebih), `0 failed`
- [ ] Pass / [ ] Fail

### T-9.2 pentra-agent Suite
```bash
cd packages/pentra-agent
uv run pytest tests/ -q --tb=short 2>&1 | tail -5
```
- Expected: `38 passed` (atau lebih), `0 failed`
- [ ] Pass / [ ] Fail

### T-9.3 apps/api Suite
```bash
cd apps/api
uv run pytest tests/ -q --tb=short 2>&1 | tail -5
```
- Expected: `51 passed` (atau lebih), `0 failed`
- [ ] Pass / [ ] Fail

### T-9.4 Total Test Count
```bash
TOTAL=$(
  (cd packages/pentra-tools && uv run pytest tests/ -q --tb=no 2>&1 | grep "passed" | grep -o "[0-9]* passed") &&
  (cd packages/pentra-agent && uv run pytest tests/ -q --tb=no 2>&1 | grep "passed" | grep -o "[0-9]* passed") &&
  (cd apps/api && uv run pytest tests/ -q --tb=no 2>&1 | grep "passed" | grep -o "[0-9]* passed")
)
echo "$TOTAL"
```
- Expected: Total `>= 170`
- [ ] Pass / [ ] Fail

### T-9.5 Sprint 14-16 Specific Tests
```bash
# CVSS Calculator
python3 -c "
from pentra_shared.utils.cvss import calculate_cvss
score, vec = calculate_cvss('SQL_INJECTION', auth_required=False)
assert score == 9.8 and 'CVSS:3.1' in vec, f'FAIL: {score} {vec}'
score2, vec2 = calculate_cvss('RCE', auth_required=False)
assert score2 == 10.0, f'FAIL RCE: {score2}'
print('CVSS Calculator ✅')
"

# ReAct Parser
python3 -c "
from pentra_agent.llm.client import parse_react_output
r = parse_react_output('Thought: Integer ID param\nAction: test_injection\nAction Input: {\"p\":\"cat\"}')
assert r.action == 'test_injection', f'FAIL: {r.action}'
print('ReAct Parser ✅')
"

# Playbook Registry
python3 -c "
from pentra_agent.playbooks import get_playbook_for_context
result = get_playbook_for_context(['ASP.NET','MSSQL'], 'http://t.com/products', 'cat')
assert any('SQL' in p.name for p in result), 'FAIL: SQLi playbook not found'
print('Attack Playbooks ✅')
"

# Anomaly Detection
python3 -c "
from pentra_agent.nodes.vuln_hunt_node import detect_anomalies
anomalies = detect_anomalies('normal response body', 'mysql error: syntax', \"'\")
assert any('ERROR_DISCLOSURE' in a for a in anomalies), f'FAIL: {anomalies}'
print('Anomaly Detection ✅')
"
```
- Expected: Semua print ✅ tanpa error
- [ ] Pass / [ ] Fail

**BLOK 9 Score: __ / 5**

---

## BLOK 10 — Celery Worker Tasks

### T-10.1 Registered Tasks
```bash
cd apps/worker
uv run celery -A app.worker inspect registered 2>/dev/null | grep "tasks\." | head -10
```
- Expected: List berisi `tasks.agent.run_engagement`, `tasks.agent.resume_engagement`, `tasks.backup.*`, `tasks.monitoring.*`
- [ ] Pass / [ ] Fail

### T-10.2 Knowledge Update Task
```bash
# Trigger dengan max_pages kecil untuk test cepat
curl -sX POST http://localhost:8001/api/v1/admin/knowledge/bulk-import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source": "h1_graphql", "max_records": 10}' | jq .
```
- Expected: response dengan status/job_id (tidak error)
- [ ] Pass / [ ] Fail

### T-10.3 CVSS Calculator di Module Level
```bash
python3 -c "
import sys
sys.path.insert(0, 'packages/pentra-shared')
from pentra_shared.utils.cvss import calculate_cvss, _CVSS_TABLE
print(f'CVSS table entries: {len(_CVSS_TABLE)}')
assert len(_CVSS_TABLE) >= 20, 'Too few CVSS entries'
print('CVSS module ✅')
"
```
- Expected: `CVSS table entries: >= 20`
- [ ] Pass / [ ] Fail

**BLOK 10 Score: __ / 3**

---

## BLOK 11 — Sprint 15 Specific Features

### T-11.1 OSINT Node Config di Graph
```bash
python3 -c "
from pentra_agent.graph.builder import build_pentra_graph
from langgraph.checkpoint.memory import MemorySaver
g = build_pentra_graph(MemorySaver())
nodes = list(g.nodes.keys())
assert 'osint' in nodes, f'osint node not in graph: {nodes}'
print(f'Graph nodes: {nodes}')
print('OSINT node in graph ✅')
"
```
- Expected: `osint` ada di graph nodes
- [ ] Pass / [ ] Fail

### T-11.2 Triage Node di Graph
```bash
python3 -c "
from pentra_agent.graph.builder import build_pentra_graph
from langgraph.checkpoint.memory import MemorySaver
g = build_pentra_graph(MemorySaver())
nodes = list(g.nodes.keys())
assert 'triage' in nodes, f'triage node not in graph: {nodes}'
print('Triage node in graph ✅')
"
```
- Expected: `triage` ada di graph nodes
- [ ] Pass / [ ] Fail

### T-11.3 RateLimitDetector Module
```bash
python3 -c "
from pentra_tools.recon.rate_limit_detector import probe_rate_limit, RateLimitResult
import inspect
assert asyncio.iscoroutinefunction(probe_rate_limit), 'Should be async'
print('RateLimitDetector ✅')
" 2>/dev/null || python3 -c "
import asyncio
from pentra_tools.recon.rate_limit_detector import probe_rate_limit
print('RateLimitDetector ✅')
"
```
- Expected: `RateLimitDetector ✅`
- [ ] Pass / [ ] Fail

### T-11.4 ChainSummarizer Module
```bash
python3 -c "
from pentra_agent.llm.summarizer import maybe_summarize, SUMMARIZE_THRESHOLD
print(f'Summarize threshold: {SUMMARIZE_THRESHOLD}')
assert SUMMARIZE_THRESHOLD == 40, f'Expected 40, got {SUMMARIZE_THRESHOLD}'
print('ChainSummarizer ✅')
"
```
- Expected: `Summarize threshold: 40`
- [ ] Pass / [ ] Fail

### T-11.5 VulnerabilityCorrelator di report_node
```bash
grep -l "correlate_findings" packages/pentra-agent/pentra_agent/nodes/report_node.py
```
- Expected: file path (file exists dan contains correlate_findings)
- [ ] Pass / [ ] Fail

**BLOK 11 Score: __ / 5**

---

## BLOK 12 — Sprint 16 Specific Features

### T-12.1 Triage Node Menghasilkan Verdicts
```bash
python3 -c "
# Test triage gate dengan mock LLM
from unittest.mock import AsyncMock, patch, MagicMock
import asyncio

async def test():
    with patch('pentra_agent.nodes.triage_node.LLMClient') as MockLLM:
        mock_llm = AsyncMock()
        mock_llm.complete_json.return_value = {
            'verdict': 'KILL',
            'final_severity': 'info',
            'reason': 'No real impact — theoretical only'
        }
        MockLLM.return_value = mock_llm

        from pentra_agent.nodes.triage_node import triage_node
        state = {
            'findings': [{'title': 'Test', 'severity': 'medium', 'vuln_class': 'INFO',
                          'target_url': 'http://t.com', 'description': 'Info only',
                          'request_raw': '', 'response_raw': ''}],
            'llm_model': 'test',
        }
        result = await triage_node(state)
        assert len(result['findings']) == 0, f'KILL verdict should remove finding: {result[\"findings\"]}'
        print('Triage KILL verdict ✅')

asyncio.run(test())
"
```
- Expected: `Triage KILL verdict ✅`
- [ ] Pass / [ ] Fail

### T-12.2 Developer Psychology di vuln_hunt_node
```bash
python3 -c "
from pentra_agent.nodes.vuln_hunt_node import DEVELOPER_PSYCHOLOGY_HEURISTICS
assert len(DEVELOPER_PSYCHOLOGY_HEURISTICS) > 100, 'Too short'
assert 'API' in DEVELOPER_PSYCHOLOGY_HEURISTICS, 'Missing API heuristic'
assert 'integer' in DEVELOPER_PSYCHOLOGY_HEURISTICS.lower() or 'ID' in DEVELOPER_PSYCHOLOGY_HEURISTICS, 'Missing integer ID heuristic'
print(f'Dev Psychology length: {len(DEVELOPER_PSYCHOLOGY_HEURISTICS)} chars ✅')
"
```
- Expected: `Dev Psychology length: N chars ✅`
- [ ] Pass / [ ] Fail

### T-12.3 Anomaly Detection → ERROR_DISCLOSURE
```bash
python3 -c "
from pentra_agent.nodes.vuln_hunt_node import detect_anomalies
anomalies = detect_anomalies(
    baseline_body='Welcome to Products',
    test_body='mysql error: syntax error near SELECT',
    test_payload=\"'\"
)
assert any('ERROR_DISCLOSURE' in a for a in anomalies), f'Missing ERROR_DISCLOSURE: {anomalies}'
print('Anomaly ERROR_DISCLOSURE ✅')
"
```
- Expected: `Anomaly ERROR_DISCLOSURE ✅`
- [ ] Pass / [ ] Fail

### T-12.4 Anomaly Detection → SIZE_ANOMALY
```bash
python3 -c "
from pentra_agent.nodes.vuln_hunt_node import detect_anomalies
baseline = 'x' * 1000  # 1000 bytes
test = 'x' * 100       # 100 bytes — 90% reduction
anomalies = detect_anomalies(baseline, test, 'payload')
assert any('SIZE_ANOMALY' in a or 'EMPTY' in a for a in anomalies), f'Missing SIZE anomaly: {anomalies}'
print('Anomaly SIZE_ANOMALY ✅')
"
```
- Expected: `Anomaly SIZE_ANOMALY ✅`
- [ ] Pass / [ ] Fail

### T-12.5 Triage DOWNGRADE Verdict
```bash
python3 -c "
import asyncio
from unittest.mock import AsyncMock, patch

async def test():
    with patch('pentra_agent.nodes.triage_node.LLMClient') as MockLLM:
        mock_llm = AsyncMock()
        mock_llm.complete_json.return_value = {
            'verdict': 'DOWNGRADE',
            'final_severity': 'low',
            'reason': 'Impact is lower than initially assessed'
        }
        MockLLM.return_value = mock_llm

        from pentra_agent.nodes.triage_node import triage_node
        state = {
            'findings': [{'title': 'XSS', 'severity': 'high', 'vuln_class': 'XSS',
                          'target_url': 'http://t.com', 'description': 'Reflected XSS',
                          'request_raw': '', 'response_raw': ''}],
            'llm_model': 'test',
        }
        result = await triage_node(state)
        assert len(result['findings']) == 1, 'DOWNGRADE should keep finding'
        assert result['findings'][0]['severity'] == 'low', f'Severity not downgraded: {result[\"findings\"][0][\"severity\"]}'
        print('Triage DOWNGRADE verdict ✅')

asyncio.run(test())
"
```
- Expected: `Triage DOWNGRADE verdict ✅`
- [ ] Pass / [ ] Fail

**BLOK 12 Score: __ / 5**

---

## BLOK 13 — E2E Live Target Validation

> **Target:** testaspnet.vulnweb.com  
> **Mode:** semi_auto  
> **Ini adalah test terpenting — validasi semua fitur Sprint 14-16 di kondisi nyata**

### Persiapan E2E
```bash
# Buat engagement khusus E2E validation
E2E_ID=$(curl -sX POST http://localhost:8001/api/v1/engagements \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"E2E-Sprint16-$(date +%H%M)\",
    \"workspace_id\": \"$WS_ID\",
    \"mode\": \"semi_auto\",
    \"in_scope\": [\"testaspnet.vulnweb.com\"],
    \"out_of_scope\": [],
    \"llm_model\": \"qwen2.5-coder:32b\"
  }" | jq -r .id)
echo "E2E_ID: $E2E_ID"

# Monitor log di terminal terpisah
tail -f /tmp/pentra-test.log | grep -E \
  "osint_node|triage|KILL|DOWNGRADE|CHAIN|ANOMALY|playbook|react_thought|CVSS|learning" &
LOG_PID=$!
```

### T-13.1 OSINT Phase Log
```bash
curl -sX POST http://localhost:8001/api/v1/engagements/$E2E_ID/start \
  -H "Authorization: Bearer $TOKEN" | jq .status

sleep 20
grep "osint_node" /tmp/pentra-test.log | tail -3
```
- Expected: `[osint_node] Starting passive OSINT for testaspnet.vulnweb.com`
- [ ] Pass / [ ] Fail

### T-13.2 crt.sh Query Log
```bash
grep "crt\.sh\|certificate transparency\|subdomains via" /tmp/pentra-test.log | tail -3
```
- Expected: log menunjukkan crt.sh di-query (berhasil atau graceful fallback)
- [ ] Pass / [ ] Fail

### T-13.3 Plan HITL + Approve
```bash
# Tunggu AWAITING_APPROVAL
timeout 120 bash -c '
  while true; do
    STATUS=$(curl -s http://localhost:8001/api/v1/engagements/'$E2E_ID' \
      -H "Authorization: Bearer '$TOKEN'" | jq -r .status)
    [[ "$STATUS" != "planning" ]] && break
    sleep 5
    echo -n "."
  done
  echo " Status: $STATUS"
'

# Approve plan
curl -sX POST http://localhost:8001/api/v1/engagements/$E2E_ID/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"approve"}' | jq .status
```
- Expected: `"resumed"`
- [ ] Pass / [ ] Fail

### T-13.4 Rate Limit Detection Log
```bash
sleep 60  # Tunggu recon mulai
grep "rate_limit_detector\|safe_rps" /tmp/pentra-test.log | tail -3
```
- Expected: `safe_rps` value di log
- [ ] Pass / [ ] Fail

### T-13.5 Recon HITL + Approve
```bash
# Approve recon
curl -sX POST http://localhost:8001/api/v1/engagements/$E2E_ID/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"approve"}' | jq .status
```
- Expected: `"resumed"`
- [ ] Pass / [ ] Fail

### T-13.6 Playbook Execution Log
```bash
sleep 120  # Tunggu vuln hunt mulai
grep "playbook\|sqli_error\|xss_reflected" /tmp/pentra-test.log | head -5
```
- Expected: `[vuln_hunt] Running playbook` atau playbook name di log
- [ ] Pass / [ ] Fail

### T-13.7 Anomaly Signal Log
```bash
grep "ANOMALY\|ERROR_DISCLOSURE\|REFLECTION\|TIME_ANOMALY" /tmp/pentra-test.log | head -5
```
- Expected: minimal 1 anomaly signal (target vulnweb.com punya SQL error responses)
- [ ] Pass / [ ] Fail

### T-13.8 ReAct Thoughts Log
```bash
grep "react_thought\|test_injection\|skip_candidate" /tmp/pentra-test.log | head -5
```
- Expected: beberapa `react_thought` entries
- [ ] Pass / [ ] Fail

### T-13.9 Triage Gate Log
```bash
# Tunggu vuln hunt + triage selesai (~15 menit dari start)
sleep 600  # 10 menit
grep "triage\|KILL\|DOWNGRADE\|Triage complete" /tmp/pentra-test.log | head -10
```
- Expected: `Triage complete: N passed, M killed, K downgraded`
- [ ] Pass / [ ] Fail

### T-13.10 CVSS Enrichment Log
```bash
grep "CVSS\|cvss_vector\|cvss enrichment" /tmp/pentra-test.log | head -5
```
- Expected: `CVSS enrichment: N findings` di log report_node
- [ ] Pass / [ ] Fail

### T-13.11 EngagementLearning Saved
```bash
sleep 10  # Tunggu report selesai
curl -s http://localhost:8001/api/v1/engagements/$E2E_ID/learning \
  -H "Authorization: Bearer $TOKEN" | jq '{findings_count, tech_stack}'
```
- Expected: `findings_count > 0`, `tech_stack` terisi (tidak empty)
- [ ] Pass / [ ] Fail

### T-13.12 Findings Lebih Sedikit dari Raw (Triage Filter)
```bash
# Bandingkan raw findings vs triaged
FINDINGS=$(curl -s "http://localhost:8001/api/v1/engagements/$E2E_ID/findings" \
  -H "Authorization: Bearer $TOKEN" | jq 'length')
echo "Final findings in DB: $FINDINGS"

# Check triage stats dari log
grep "Triage complete" /tmp/pentra-test.log | tail -1
# Expected: killed > 0 (minimal 1 informational finding di-kill)
```
- Expected: final findings < raw nuclei output (triage KILL bekerja)
- [ ] Pass / [ ] Fail

### T-13.13 CVSS Vector 100%
```bash
TOTAL=$(curl -s "http://localhost:8001/api/v1/engagements/$E2E_ID/findings" \
  -H "Authorization: Bearer $TOKEN" | jq 'length')
WITH_CVSS=$(curl -s "http://localhost:8001/api/v1/engagements/$E2E_ID/findings" \
  -H "Authorization: Bearer $TOKEN" | \
  jq '[.[] | select(.cvss_vector | if . != null then startswith("CVSS:3.1") else false end)] | length')
echo "Total: $TOTAL, CVSS vector: $WITH_CVSS"
```
- Expected: `Total == WITH_CVSS` (100%)
- [ ] Pass / [ ] Fail

### T-13.14 PDF Report Valid dengan CVSS
```bash
curl -s "http://localhost:8001/api/v1/reports/engagements/$E2E_ID?format=pdf" \
  -H "Authorization: Bearer $TOKEN" \
  --output /tmp/e2e-v16.pdf
SIZE=$(wc -c < /tmp/e2e-v16.pdf)
echo "PDF size: $SIZE bytes"
file /tmp/e2e-v16.pdf
```
- Expected: Size `> 10000`, Type `PDF document`
- [ ] Pass / [ ] Fail

### T-13.15 Cleanup Log Monitor
```bash
kill $LOG_PID 2>/dev/null
echo "E2E-v16 complete. E2E_ID=$E2E_ID"
```

**BLOK 13 Score: __ / 14**

---

## Scorecard Final

```
BLOK 1  — Infrastruktur Dasar      __ / 8
BLOK 2  — Authentication            __ / 7
BLOK 3  — Knowledge Base            __ / 6
BLOK 4  — Agent Pipeline            __ / 18
BLOK 5  — Report Generation         __ / 5
BLOK 6  — Frontend UI (Manual)      __ / 42
BLOK 7  — Monitoring & Admin        __ / 7
BLOK 8  — Export/Import             __ / 4
BLOK 9  — Unit Tests                __ / 5
BLOK 10 — Celery Worker             __ / 3
BLOK 11 — Sprint 15 Features        __ / 5
BLOK 12 — Sprint 16 Features        __ / 5
BLOK 13 — E2E Live Target           __ / 14
──────────────────────────────────────────
TOTAL                               __ / 129
```

---

## Kriteria Kelulusan

### ✅ Platform Siap (Lanjut Sprint 17 / v1.0 prep)
```
BLOK 1-5    : 100% (44/44) — infrastruktur harus sempurna
BLOK 6      : 35/42 (83%) — frontend boleh ada minor issues
BLOK 9      : 100% (5/5) — unit tests harus semua pass
BLOK 11-12  : 90% (9/10) — fitur baru harus mostly work
BLOK 13     : 10/14 (71%) — E2E harus mostly pass
TOTAL       : 110/129 (85%)
```

### ⚠️ Perlu Perbaikan (Stop development, fix bugs dulu)
```
Jika BLOK 4 < 14/18 — agent pipeline bermasalah
Jika BLOK 9 ada failure — unit tests broken
Jika BLOK 13 < 8/14 — E2E tidak berfungsi
```

### ❌ Critical Failure (Rollback ke sprint sebelumnya)
```
Jika BLOK 1 < 6/8 — infrastruktur rusak
Jika BLOK 9 > 3 failures — banyak regression
Jika T-4.16 fail (findings 0) — pipeline mati
```

---

## Apa yang Dilakukan Jika Ada Failure

### Pattern yang Paling Sering

**T-4.4 OSINT node tidak muncul di log:**
```bash
# Cek graph structure
python3 -c "
from pentra_agent.graph.builder import build_pentra_graph
from langgraph.checkpoint.memory import MemorySaver
g = build_pentra_graph(MemorySaver())
print('Nodes:', list(g.nodes.keys()))
"
# Jika osint tidak ada → cek builder.py apakah node sudah didaftarkan
```

**T-4.12 ReAct tidak muncul:**
```bash
# Cek apakah react_step() dipanggil
grep "react_step\|ReActOutput" packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py | head -5
```

**T-4.13 Triage tidak muncul:**
```bash
# Cek graph edges
python3 -c "
from pentra_agent.graph.builder import build_pentra_graph
from langgraph.checkpoint.memory import MemorySaver
g = build_pentra_graph(MemorySaver())
# Print edges
for edge in g.edges:
    print(edge)
"
```

**T-9.x Unit test failure:**
```bash
# Run dengan verbose untuk debug
cd packages/pentra-agent
uv run pytest tests/ -v --tb=long 2>&1 | head -50
```

**T-13.9 Triage gate killed 0 findings:**
Ini mungkin acceptable — nuclei sudah filter ke `cve,vuln,xss,sqli,lfi` tags. Cek apakah `theoretical-only` info findings masuk. Jika semua findings genuine, triage KILL = 0 adalah benar.

---

## Prompt untuk Copilot

Setelah menjalankan test, jika ada failure:

```
Baca CLAUDE.md, PROGRESS.md, dan MASTER-TEST-PLAN.md.

Test T-[NOMOR] failed dengan hasil:
[paste output test yang gagal]

Expected: [apa yang seharusnya terjadi]
Actual: [apa yang terjadi]

Diagnosa root cause dan fix masalah ini.
Setelah fix, jalankan: uv run pytest packages/pentra-agent/tests/ -q
untuk pastikan tidak ada regresi.
```

---

*MASTER-TEST-PLAN.md — Pentra AI*  
*129 test cases mencakup Sprint 1–16*  
*Run ini sebelum melanjutkan development apapun*
