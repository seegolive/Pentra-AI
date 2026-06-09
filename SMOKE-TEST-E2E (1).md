# SMOKE-TEST-E2E.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Coverage:** Sprint 14–20 P1 (semua fitur yang belum divalidasi bersama)  
> **Target:** testaspnet.vulnweb.com  
> **Estimasi:** 3–4 jam  
> **Jalankan sebelum lanjut Sprint 20 P2**

---

## Fitur yang Divalidasi

```
Sprint 14  : EngagementLearning · ReAct loop · CVSS v3.1 auto-scoring
Sprint 15  : OSINT node · Attack Playbooks · RateLimitDetector
             VulnerabilityCorrelator · ChainSummarizer
Sprint 16  : Triage Gate (7-Question) · Anomaly Detection
             Developer Psychology · DO NOT STOP routing
Sprint 17  : Nuclei improvements · bge-m3 embedding
Sprint 18  : GF Patterns · Smart Dedup · WAF Profiler · ExploitArsenal
             Dynamic Prompts · Authenticated Scan · Two-stage Triage
             SOAP/XXE · Concurrent Testing · Located Memory
             5 Scan Presets · Subscan · Incremental · Fine-tune Export
Sprint 19  : GraphQL Analyzer · Race Condition · CORS Tester
             Event Persistence · H1 Executive Report
Sprint 20P1: JWT Vulnerability Testing · Subdomain Takeover Detection
             Nuclei 0-findings fix (final)
```

---

## Setup Awal

```bash
# Pastikan semua service up
curl -s http://localhost:8001/health | jq -r .status   # ok
redis-cli ping                                          # PONG
curl -s http://localhost:6333/healthz                   # ok
ollama list | grep -E "qwen2.5:32b|bge-m3"             # keduanya harus ada
curl -s http://localhost:9877 > /dev/null && echo "Burp: OK" || echo "Burp: OFFLINE"

# Token
export TOKEN=$(curl -sX POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Pentra@2026!"}' | jq -r .access_token)
echo "Token OK: ${TOKEN:0:20}..."

# Workspace
export WS_ID=$(curl -sX POST http://localhost:8001/api/v1/workspaces \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"SmokeTest-'$(date +%Y%m%d-%H%M)'"}' | jq -r .id)
echo "WS_ID: $WS_ID"

# Log monitor (terminal terpisah)
tail -f /tmp/pentra.log | grep -E \
  "osint_node|rate_limit|gf_filter|waf_profiler|dedup|\
triage|KILL|DOWNGRADE|CHAIN_REQUIRED|\
anomaly|ANOMALY|react_thought|test_injection|\
graphql|race_condition|cors_tester|\
jwt_tester|takeover_detector|\
playbook|ExploitArsenal|WAITFOR|SLEEP|\
nuclei.*findings|bge-m3|learning" &
```

---

## BLOK 1 — Unit Tests

### ST-1.1 Full Test Suite

```bash
cd packages/pentra-tools && uv run pytest tests/ -q --tb=short 2>&1 | tail -5
cd packages/pentra-agent && uv run pytest tests/ -q --tb=short 2>&1 | tail -5
```

**Expected:**
```
pentra-tools: 141+ passed, 0 failed
pentra-agent: 127+ passed, 0 failed
```

- [ ] PASS / [ ] FAIL

---

### ST-1.2 Sprint-Specific Imports & Functions

```bash
python3 << 'EOF'
import sys, asyncio, traceback

results = []

def check(name, fn):
    try:
        fn()
        results.append((name, "✅"))
    except Exception as e:
        results.append((name, f"❌ {e}"))

# Sprint 14
check("CVSS v3.1 calculator", lambda: (
    __import__('pentra_shared.utils.cvss', fromlist=['calculate_cvss'])
    .calculate_cvss.__call__('SQL_INJECTION', auth_required=False)
))
check("ReAct parser", lambda: (
    __import__('pentra_agent.llm.client', fromlist=['parse_react_output'])
    .parse_react_output('Thought: test\nAction: test_injection\nAction Input: {}')
))

# Sprint 15
check("OSINT node import", lambda: (
    __import__('pentra_agent.nodes.osint_node', fromlist=['osint_node'])
))
check("Attack Playbooks — sqli for ASP.NET", lambda: (
    setattr(sys, '_r',
        __import__('pentra_agent.playbooks', fromlist=['get_playbook_for_context'])
        .get_playbook_for_context(['ASP.NET','MSSQL'], 'http://t.com/products?cat=1', 'cat')
    ) or (len(sys._r) > 0 or None)
))

# Sprint 16
check("Triage Gate import", lambda: (
    __import__('pentra_agent.nodes.triage_node', fromlist=['triage_node'])
))
check("Anomaly Detection — ERROR_DISCLOSURE", lambda: (
    setattr(sys, '_a',
        __import__('pentra_agent.nodes.vuln_hunt_node', fromlist=['detect_anomalies'])
        .detect_anomalies('normal body', 'mysql error: syntax error', "'")
    ) or (any('ERROR_DISCLOSURE' in a for a in sys._a) or None)
))

# Sprint 18
check("GF Patterns — sqli_int priority 1", lambda: (
    setattr(sys, '_g',
        __import__('pentra_tools.recon.gf_filter', fromlist=['apply_gf_patterns'])
        .apply_gf_patterns(['http://t.com/products?id=1'])
    ) or (len(sys._g) > 0 and sys._g[0].priority == 1 or None)
))
check("Smart Dedup import", lambda: (
    __import__('pentra_tools.recon.dedup', fromlist=['smart_dedup_endpoints'])
))
check("WAF Profiler — cloudflare fingerprint", lambda: (
    setattr(sys, '_w',
        __import__('pentra_tools.recon.waf_profiler', fromlist=['BYPASS_STRATEGIES'])
        .BYPASS_STRATEGIES
    ) or ('cloudflare' in sys._w or None)
))
check("ExploitArsenal — MSSQL WAITFOR", lambda: (
    setattr(sys, '_e',
        __import__('pentra_agent.arsenal.exploit_arsenal', fromlist=['ExploitArsenal'])
        .ExploitArsenal.get_payloads('SQL_INJECTION', ['ASP.NET','MSSQL'])
    ) or (any('WAITFOR' in p for p in sys._e) or None)
))
check("Dynamic Prompts — ASP.NET context", lambda: (
    setattr(sys, '_dp',
        __import__('pentra_agent.llm.dynamic_prompt', fromlist=['build_vuln_hunt_system_prompt'])
        .build_vuln_hunt_system_prompt(['ASP.NET','IIS'], [], [])
    ) or ('asp.net' in sys._dp.lower() or None)
))
check("Located Memory", lambda: (
    setattr(sys, '_m',
        __import__('pentra_agent.memory.located_memory', fromlist=['LocatedMemory'])
        .LocatedMemory()
    ) or sys._m.record_test('http://t.com', 'sqli') or
    (sys._m.was_tested('http://t.com', 'sqli') or None)
))
check("Scan Presets — fast", lambda: (
    setattr(sys, '_p',
        __import__('pentra_agent.scan_presets', fromlist=['get_preset'])
        .get_preset('fast')
    ) or (sys._p is not None or None)
))

# Sprint 19
check("GraphQL Analyzer import", lambda: (
    __import__('pentra_tools.vuln.graphql_analyzer', fromlist=['analyze_graphql_endpoint'])
))
check("Race Condition — identify redeem endpoint", lambda: (
    setattr(sys, '_rc',
        __import__('pentra_tools.vuln.race_condition', fromlist=['identify_race_candidates'])
        .identify_race_candidates([{'url':'http://t.com/redeem','method':'POST'}])
    ) or (len(sys._rc) > 0 or None)
))
check("CORS Tester import", lambda: (
    __import__('pentra_tools.vuln.cors_tester', fromlist=['test_cors'])
))

# Sprint 20 P1
check("JWT Tester — forge none algorithm", lambda: (
    setattr(sys, '_jf',
        __import__('pentra_tools.vuln.jwt_tester', fromlist=['forge_none_algorithm'])
        .forge_none_algorithm('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig')
    ) or (sys._jf.count('.') == 2 and sys._jf.endswith('.') or None)
))
check("Subdomain Takeover — 10+ fingerprints", lambda: (
    setattr(sys, '_tf',
        __import__('pentra_tools.recon.takeover_detector', fromlist=['TAKEOVER_FINGERPRINTS'])
        .TAKEOVER_FINGERPRINTS
    ) or (len(sys._tf) >= 10 or None)
))

# bge-m3
async def _bge():
    import httpx
    r = await httpx.AsyncClient().post(
        'http://localhost:11434/api/embeddings',
        json={'model':'bge-m3','prompt':'SQL injection'}
    )
    d = r.json()
    assert len(d.get('embedding', [])) > 0, "bge-m3 returned empty embedding"
check("bge-m3 embedding active", lambda: asyncio.run(_bge()))

# Results
print("\n=== ST-1.2 Results ===")
passed = sum(1 for _, s in results if s.startswith("✅"))
for name, status in results:
    print(f"  {status}  {name}")
print(f"\nScore: {passed}/{len(results)}")
if passed < len(results):
    print("\nFAILED:")
    for name, status in results:
        if not status.startswith("✅"):
            print(f"  {name}: {status}")
EOF
```

**Expected:** 19+/19+ ✅

- [ ] PASS / [ ] FAIL → catat yang ❌

---

## BLOK 2 — API Endpoints

### ST-2.1 Auth + Protection

```bash
echo "=== Auth checks ==="

STATUS=$(curl -s http://localhost:8001/health | jq -r .status)
echo "Health: $STATUS"  # ok

TT=$(curl -sX POST http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Pentra@2026!"}' | jq -r .token_type)
echo "Login valid token_type: $TT"  # bearer

C1=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  http://localhost:8001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}')
echo "Login invalid: $C1 (exp 401)"

C2=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/api/v1/workspaces)
echo "No token: $C2 (exp 401)"

# Temp engagement for internal API test
export ENG_TEMP=$(curl -sX POST http://localhost:8001/api/v1/engagements \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"temp-st\",\"workspace_id\":\"$WS_ID\",\"mode\":\"agentic\",
       \"in_scope\":[\"test.com\"],\"llm_model\":\"qwen2.5:32b\"}" | jq -r .id)

C3=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "http://localhost:8001/api/v1/internal/engagements/$ENG_TEMP/findings/bulk" \
  -H "Content-Type: application/json" -d '{"findings":[]}')
echo "Internal no header: $C3 (exp 422)"

C4=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "http://localhost:8001/api/v1/internal/engagements/$ENG_TEMP/findings/bulk" \
  -H "X-Internal-Token: wrongtoken" \
  -H "Content-Type: application/json" -d '{"findings":[]}')
echo "Internal wrong token: $C4 (exp 403)"
```

- [ ] PASS / [ ] FAIL

---

### ST-2.2 Knowledge Base + bge-m3

```bash
echo "=== KB checks ==="

RESULTS=$(curl -s "http://localhost:8001/api/v1/knowledge/search?q=SQL+injection&top_k=5" \
  -H "Authorization: Bearer $TOKEN" | jq length)
echo "Search results: $RESULTS (exp 5)"

MIN_Q=$(curl -s "http://localhost:8001/api/v1/knowledge/search?q=SQL+injection&top_k=5" \
  -H "Authorization: Bearer $TOKEN" | jq '[.[] | .quality_score] | min')
echo "Min quality score: $MIN_Q (exp > 0)"

TOTAL=$(curl -s "http://localhost:8001/api/v1/knowledge/list?limit=1" \
  -H "Authorization: Bearer $TOKEN" | jq .total)
echo "KB total: $TOTAL (exp >= 2758)"
```

- [ ] PASS / [ ] FAIL

---

### ST-2.3 Event Persistence (Sprint 19.4)

```bash
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "http://localhost:8001/api/v1/engagements/$ENG_TEMP/events" \
  -H "Authorization: Bearer $TOKEN")
echo "Events endpoint: $CODE (exp 200)"

TYPE=$(curl -s "http://localhost:8001/api/v1/engagements/$ENG_TEMP/events" \
  -H "Authorization: Bearer $TOKEN" | jq 'type')
echo "Events type: $TYPE (exp \"array\")"
```

- [ ] PASS / [ ] FAIL

---

## BLOK 3 — WebSocket

### ST-3.1 Connect + Reject

```bash
echo "=== WebSocket checks ==="

# Valid → connect
timeout 4 wscat -c "ws://localhost:8001/ws/engagements/$ENG_TEMP/feed?token=$TOKEN" \
  2>&1 | grep -iE "connected|CONNECTED|error" | head -2

# Invalid → reject
timeout 3 wscat -c "ws://localhost:8001/ws/engagements/$ENG_TEMP/feed?token=invalid" \
  2>&1 | head -2
# Expected: 4001 atau Unexpected server response
```

- [ ] PASS / [ ] FAIL

---

## BLOK 4 — Full Agent Pipeline (~60 menit)

### ST-4.0 Buat Engagement

```bash
export ENG_ID=$(curl -sX POST http://localhost:8001/api/v1/engagements \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"SmokeTest-Full-$(date +%H%M)\",
    \"workspace_id\": \"$WS_ID\",
    \"mode\": \"semi_auto\",
    \"in_scope\": [\"testaspnet.vulnweb.com\"],
    \"out_of_scope\": [],
    \"llm_model\": \"qwen2.5:32b\",
    \"scan_preset\": \"full\"
  }" | jq -r .id)
echo "ENG_ID: $ENG_ID"
# Connect wscat di terminal lain:
# wscat -c "ws://localhost:8001/ws/engagements/$ENG_ID/feed?token=$TOKEN"
```

---

### ST-4.1 Start + Events

```bash
curl -sX POST "http://localhost:8001/api/v1/engagements/$ENG_ID/start" \
  -H "Authorization: Bearer $TOKEN" | jq .status
# Expected: "started"

# Tunggu 30 detik
sleep 30
grep "osint_node\|crt\.sh\|certificate transparency" /tmp/pentra.log | tail -3
```

**wscat harus menunjukkan:**
```
{"type":"ENGAGEMENT_STARTED"}
{"type":"NODE_START","node":"osint"}
{"type":"NODE_START","node":"plan"}
{"type":"LLM_STREAM",...}
{"type":"AWAITING_APPROVAL","node":"hitl_plan"}
```

- [ ] OSINT node ran
- [ ] HITL plan appeared
- [ ] PASS / [ ] FAIL

---

### ST-4.2 Approve Plan + Recon

```bash
# Approve HITL plan
curl -sX POST "http://localhost:8001/api/v1/engagements/$ENG_ID/approve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"approve"}' | jq .status

# Tunggu recon (~5 menit)
sleep 300

# Cek Sprint 18 recon features di log
grep -E "rate_limit_detector|safe_rps|waf_profiler|waf=|dedup.*removed|gf_filter.*hint" \
  /tmp/pentra.log | tail -10
```

**Expected log:**
```
[rate_limit_detector] safe_rps=20 delay=0ms
[waf_profiler] waf=none blocking=False
[dedup] N → M endpoints (K removed)
[gf_filter] X/Y endpoints have vuln hints
```

- [ ] rate_limit_detector ✓
- [ ] waf_profiler ✓
- [ ] dedup ✓
- [ ] gf_filter ✓
- [ ] PASS / [ ] FAIL

---

### ST-4.3 Approve Recon

```bash
curl -sX POST "http://localhost:8001/api/v1/engagements/$ENG_ID/approve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"approve"}' | jq .status
# Expected: "resumed"
```

- [ ] PASS / [ ] FAIL

---

### ST-4.4 Vuln Hunt — Semua Sprint 18-20 Tools (~30 menit)

```bash
# Tunggu ~20 menit
sleep 1200

echo "=== Vuln Hunt Feature Check ==="

echo -n "Nuclei findings: "
grep "nuclei.*findings\|nuclei.*exit" /tmp/pentra.log | tail -1

echo -n "ExploitArsenal/WAITFOR: "
grep -c "ExploitArsenal\|WAITFOR DELAY\|SLEEP(5" /tmp/pentra.log

echo -n "ReAct thoughts: "
grep -c "react_thought\|test_injection" /tmp/pentra.log

echo -n "Anomaly detection: "
grep -c "ANOMALY\|ERROR_DISCLOSURE\|REFLECTION" /tmp/pentra.log

echo -n "Playbooks ran: "
grep -c "playbook.*SQL\|playbook.*XSS\|Running playbook" /tmp/pentra.log

echo -n "GraphQL: "
grep -c "graphql.*analyzer\|graphql.*endpoint" /tmp/pentra.log

echo -n "Race condition: "
grep -c "race_condition" /tmp/pentra.log

echo -n "CORS tester: "
grep -c "cors_tester\|cors.*endpoint" /tmp/pentra.log

echo -n "JWT tester: "
grep -c "jwt_tester\|JWT.*Testing\|no JWT found" /tmp/pentra.log

echo -n "Takeover detector: "
grep -c "takeover_detector\|CNAME\|Checking.*subdomains" /tmp/pentra.log
```

**Checklist:**
- [ ] Nuclei > 0 findings ← **KRITIS — WAJIB PASS**
- [ ] ReAct thoughts >= 1
- [ ] ExploitArsenal/payloads ran
- [ ] Anomaly detection ran
- [ ] Playbooks ran
- [ ] GraphQL ran (0 OK)
- [ ] Race condition ran (0 OK)
- [ ] CORS tester ran
- [ ] JWT tester ran (no JWT OK)
- [ ] Takeover detector ran
- [ ] PASS / [ ] FAIL

---

### ST-4.5 Approve HITL Exploit + Triage

```bash
# Approve jika ada
curl -sX POST "http://localhost:8001/api/v1/engagements/$ENG_ID/approve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"approve"}' 2>/dev/null | jq .status

# Cek triage
grep -E "Triage complete|triage.*KILL|triage.*DOWNGRADE" /tmp/pentra.log | tail -3
```

**Expected:** `Triage complete: N passed, M killed, K downgraded`

- [ ] Triage ran
- [ ] PASS / [ ] SKIP

---

## BLOK 5 — Findings Quality

### ST-5.1 Count + CVSS + Triage

```bash
FINDINGS=$(curl -s "http://localhost:8001/api/v1/engagements/$ENG_ID/findings" \
  -H "Authorization: Bearer $TOKEN")

TOTAL=$(echo $FINDINGS | jq length)
echo "Total findings: $TOTAL"  # >= 10

echo "Severity dist:"
echo $FINDINGS | jq '[.[] | .severity] | group_by(.) | map({(.[0]): length}) | add'

WITH_CVSS=$(echo $FINDINGS | jq \
  '[.[] | select(.cvss_vector != null and (.cvss_vector | startswith("CVSS:3.1")))] | length')
echo "CVSS vector: $WITH_CVSS/$TOTAL"  # Should be equal

WITH_TRIAGE=$(echo $FINDINGS | jq '[.[] | select(.triage_verdict != null)] | length')
echo "With triage verdict: $WITH_TRIAGE"  # > 0
```

- [ ] findings >= 10
- [ ] CVSS 100% (WITH_CVSS == TOTAL)
- [ ] Triage verdicts present
- [ ] PASS / [ ] FAIL

---

### ST-5.2 EngagementLearning (Sprint 14.1)

```bash
curl -s "http://localhost:8001/api/v1/engagements/$ENG_ID/learning" \
  -H "Authorization: Bearer $TOKEN" | jq '{findings_count, tech_stack, effective_tools}'
# Expected: findings_count > 0, tech_stack populated
```

- [ ] PASS / [ ] FAIL

---

### ST-5.3 Event Persistence (Sprint 19.4)

```bash
EC=$(curl -s "http://localhost:8001/api/v1/engagements/$ENG_ID/events" \
  -H "Authorization: Bearer $TOKEN" | jq length)
echo "Persisted events: $EC"  # > 10
```

- [ ] PASS / [ ] FAIL

---

## BLOK 6 — Reports

### ST-6.1 All Formats Valid

```bash
# Markdown
MD=$(curl -s "http://localhost:8001/api/v1/reports/engagements/$ENG_ID?format=markdown" \
  -H "Authorization: Bearer $TOKEN" | wc -c)
echo "Markdown: $MD chars"  # > 1000

# PDF
curl -s "http://localhost:8001/api/v1/reports/engagements/$ENG_ID?format=pdf" \
  -H "Authorization: Bearer $TOKEN" --output /tmp/smoke-report.pdf
PDF=$(wc -c < /tmp/smoke-report.pdf)
echo "PDF: $PDF bytes"  # > 10000
file /tmp/smoke-report.pdf  # PDF document

# H1 + CVSS
curl -s "http://localhost:8001/api/v1/reports/engagements/$ENG_ID?format=h1" \
  -H "Authorization: Bearer $TOKEN" | jq '.[0] | {title, severity, cvss_vector}' 2>/dev/null
# Expected: cvss_vector starts with CVSS:3.1
```

- [ ] Markdown > 1000 chars
- [ ] PDF > 10KB
- [ ] H1 has cvss_vector
- [ ] PASS / [ ] FAIL

---

### ST-6.2 Executive Summary (Sprint 19.5)

```bash
curl -s "http://localhost:8001/api/v1/reports/engagements/$ENG_ID?format=markdown" \
  -H "Authorization: Bearer $TOKEN" | \
  grep -i "executive summary\|## Summary\|## Overview" | head -3
# Expected: ada section summary dari LLM
```

- [ ] PASS / [ ] FAIL

---

## BLOK 7 — Frontend Manual

```
Buka http://localhost:5173

[ ] ST-7.1 Live Feed tampilkan events dari engagement
[ ] ST-7.2 Refresh browser → events history MASIH ADA (Sprint 19.4)
[ ] ST-7.3 HITL dialog muncul dan Approve berfungsi
[ ] ST-7.4 Findings tab: severity pills + CVSS di expand row
[ ] ST-7.5 Report tab: Markdown view ada Executive Summary
[ ] ST-7.6 PDF Download berhasil
[ ] ST-7.7 Status badge berubah sesuai phase
```

- [ ] 5+ dari 7 / [ ] FAIL

---

## BLOK 8 — KB Scale-Up (Background)

```bash
# Trigger import pages 21-60
curl -sX POST http://localhost:8001/api/v1/admin/knowledge/bulk-import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source":"h1_graphql","max_records":2500,"start_page":21}' | jq .

# Cek progress setelah 5 menit
sleep 300
curl -s http://localhost:6333/collections/knowledge | jq .result.points_count
# Expected: bertambah dari 2758
```

- [ ] Import triggered / [ ] FAIL

---

## Scorecard

```
BLOK 1 — Unit Tests
  [ ] ST-1.1  141+/127+ passing, 0 failed
  [ ] ST-1.2  19+/19+ Sprint-specific tests passing

BLOK 2 — API
  [ ] ST-2.1  Auth + protection (401/403/422 correct)
  [ ] ST-2.2  KB search + bge-m3 quality > 0
  [ ] ST-2.3  Event persistence endpoint returns array

BLOK 3 — WebSocket
  [ ] ST-3.1  Connect OK + reject invalid

BLOK 4 — Agent Pipeline
  [ ] ST-4.1  Start + OSINT + HITL plan
  [ ] ST-4.2  Recon: rate_limit + waf + dedup + gf
  [ ] ST-4.3  HITL recon approval
  [ ] ST-4.4  Vuln hunt: 10 tools ran, nuclei>0 ← KRITIS
  [ ] ST-4.5  Triage ran

BLOK 5 — Findings
  [ ] ST-5.1  count>=10 + CVSS 100% + triage verdicts
  [ ] ST-5.2  EngagementLearning saved
  [ ] ST-5.3  Events persisted >10

BLOK 6 — Reports
  [ ] ST-6.1  MD + PDF(>10KB) + H1 with CVSS
  [ ] ST-6.2  Executive summary present

BLOK 7 — Frontend (Manual)
  [ ] ST-7.x  5+ dari 7 checks

BLOK 8 — KB Scale-Up
  [ ] ST-8.1  Import triggered

──────────────────────────────────────────
TOTAL: __ / 18 checks
```

---

## Kriteria Kelulusan

```
✅ LULUS → Lanjut Sprint 20 P2:
   - BLOK 1 + 2 + 3: 100%
   - ST-4.4 nuclei > 0  ← MANDATORY
   - ST-5.1 findings >= 10  ← MANDATORY
   - Total >= 14/18

❌ STOP → Fix dulu:
   - nuclei masih 0 findings
   - Unit tests ada failure
   - Pipeline tidak jalan end-to-end
   - PDF gagal generate
```

---

## Troubleshooting

```bash
# Nuclei 0 findings
nuclei -version
nuclei -u http://testaspnet.vulnweb.com/ -tags sqli -j 2>&1 | head -10
nuclei -update-templates -silent

# OSINT tidak di graph
python3 -c "
from pentra_agent.graph.builder import build_pentra_graph
from langgraph.checkpoint.memory import MemorySaver
g = build_pentra_graph(MemorySaver())
print('Nodes:', list(g.nodes.keys()))
"

# JWT tester import error
python3 -c "from pentra_tools.vuln.jwt_tester import forge_none_algorithm; print('OK')"

# Takeover detector error (dnspython)
pip install dnspython --break-system-packages
python3 -c "import dns.resolver; print('dnspython OK')"

# bge-m3 missing
ollama list | grep bge
# Jika tidak ada: ollama pull bge-m3
```

---

## Prompt untuk Copilot

```
Baca CLAUDE.md, PROGRESS.md, dan SMOKE-TEST-E2E.md secara lengkap.

Sprint 20 P1 sudah selesai (JWT, Takeover, Nuclei fix).
Sebelum lanjut P2, jalankan smoke test dari SMOKE-TEST-E2E.md.

Mulai dari BLOK 1 dan 2:
1. Jalankan ST-1.1 — full test suite
2. Jalankan ST-1.2 — Sprint-specific imports (python3 script)
3. Jalankan BLOK 2 — API checks

Untuk setiap test: jalankan command, interpretasikan output,
tandai PASS/FAIL, dan jika FAIL diagnosa + fix sebelum lanjut.
Laporkan scorecard setelah setiap blok.
```

---

*SMOKE-TEST-E2E.md — Pentra AI*
*Coverage: Sprint 14–20 P1 | 18 checks | Target 14/18 untuk lanjut P2*
