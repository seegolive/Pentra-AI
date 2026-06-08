# SPRINT-17-FIXES.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `PROGRESS_REPORT.md` → file ini  
> **Status:** 10 HIGH findings confirmed, 144 tests, 33/33 Burp tools  
> **Tujuan:** Fix 3 issues dari E2E run + install bge-m3

---

## Konteks E2E Run Terakhir

Run pertama pada `testaspnet.vulnweb.com` menghasilkan:
- **10 HIGH findings** (SQLi ×7, Deserialization, IDOR, Host Header Injection)
- **Nuclei: 0 findings** padahal target deliberately vulnerable
- **LFI candidate** pada `NewsAd` parameter tidak di-confirm
- **Severity mismatch**: CRITICAL di log → HIGH di report

---

## Fix 1 — Nuclei 0 Findings (WAJIB)

### Diagnosa Dulu (manual di terminal)

```bash
# Step 1: Verifikasi nuclei binary
which nuclei && nuclei -version
# Expected: nuclei x.x.x (path valid)

# Step 2: Update templates
nuclei -update-templates -silent
echo "Templates updated: $(ls ~/.local/nuclei-templates/ | wc -l) template dirs"

# Step 3: Test manual pada target
nuclei -u http://testaspnet.vulnweb.com/ \
  -tags sqli,xss,lfi,rce -timeout 10 -c 5 -silent 2>&1 | head -20
# Expected: minimal beberapa findings SQLi atau exposure

# Step 4: Cek HTTPS vs HTTP issue (ini pernah terjadi sebelumnya)
nuclei -u https://testaspnet.vulnweb.com/ \
  -tags sqli -timeout 10 -silent 2>&1 | head -5
nuclei -u http://testaspnet.vulnweb.com/ \
  -tags sqli -timeout 10 -silent 2>&1 | head -5
# Bandingkan: HTTP vs HTTPS mana yang return findings

# Step 5: Cek JSON output parsing
nuclei -u http://testaspnet.vulnweb.com/ \
  -tags sqli -timeout 10 -silent -json 2>&1 | head -5
# Pastikan output JSON valid (bukan empty)
```

### Root Cause yang Paling Mungkin

Berdasarkan pattern dari Sprint 12 (bug #6 sebelumnya), nuclei kemungkinan masih menggunakan HTTPS targets padahal port 443 closed.

**Cek di `vuln_hunt_node.py`:**

```python
# Cari bagian _run_nuclei() atau setara
# Pastikan ada logic ini:

# HTTPS probe sebelum nuclei
try:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, 443), timeout=5.0
    )
    writer.close()
    https_reachable = True
except Exception:
    https_reachable = False

# Jika HTTPS tidak reachable, rewrite ke HTTP
if not https_reachable:
    url_targets = [url.replace("https://", "http://") for url in url_targets]
    logger.info("[nuclei] HTTPS port 443 closed — rewrote to HTTP: %s", url_targets[:3])
```

**Jika logic ini sudah ada tapi nuclei masih 0:**

```python
# Tambahkan verbose logging untuk debug
logger.debug("[nuclei] Running with targets: %s", url_targets)
logger.debug("[nuclei] Command: %s", " ".join(nuclei_cmd))

# Setelah nuclei selesai, log output
logger.debug("[nuclei] stdout (first 500): %s", stdout[:500])
logger.debug("[nuclei] stderr (first 500): %s", stderr[:500])
logger.debug("[nuclei] exit code: %d", exit_code)
logger.debug("[nuclei] findings before parse: %d lines", len(stdout.splitlines()))
```

### Fix yang Perlu Dilakukan

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Di fungsi nuclei runner, pastikan:

# 1. HTTPS→HTTP fallback sudah ada
# 2. Template tags yang dipakai mencakup target ASP.NET
NUCLEI_TAGS_HTTP = [
    "sqli", "xss", "lfi", "rce", "ssrf",
    "exposure", "misconfig", "default-login",
    "cve",              # CVE templates — banyak ASP.NET CVE
    "iis",              # IIS-specific templates
    "asp",              # ASP.NET templates
    "deserialization",  # ViewState deserialization
]

# 3. Jangan exit early jika nuclei return kosong — log verbose
if not findings:
    logger.warning(
        "[nuclei] 0 findings. targets=%s tags=%s stdout_len=%d stderr=%s",
        url_targets[:3], tags, len(stdout), stderr[:200]
    )

# 4. Tambahkan -include-tags untuk tidak skip deprecated templates
nuclei_cmd = [
    nuclei_bin,
    "-u", primary_target,
    "-tags", ",".join(tags),
    "-timeout", "15",      # Naikan dari 10 ke 15
    "-c", "10",
    "-json",
    "-silent",
    "-ni",                 # No interactsh (butuh internet)
    "-duc",                # Disable update check
]
```

**Tests untuk nuclei fix:**

```python
# packages/pentra-agent/tests/test_nuclei.py

@pytest.mark.asyncio
async def test_nuclei_https_fallback_to_http():
    """Jika port 443 closed, URL harus direwrite ke HTTP."""
    # Mock asyncio.open_connection untuk simulate 443 closed
    with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
        from pentra_agent.nodes.vuln_hunt_node import _prepare_nuclei_targets
        targets = ["https://testaspnet.vulnweb.com/"]
        result = await _prepare_nuclei_targets(targets)
        assert all(t.startswith("http://") for t in result), \
            "All targets should be HTTP when 443 is closed"


def test_nuclei_tags_include_iis_asp():
    """ASP.NET target harus include IIS dan ASP tags."""
    from pentra_agent.nodes.vuln_hunt_node import _get_nuclei_tags
    tags = _get_nuclei_tags(tech_stack=["IIS", "ASP.NET"])
    assert "iis" in tags or "asp" in tags, \
        "IIS/ASP tech stack should add iis/asp tags"
```

---

## Fix 2 — LFI `NewsAd` Tidak Di-confirm

### Konteks

Anomaly yang ditemukan:
```
PATH_INCLUSION pada NewsAd → <iframe src="../web.config">
LLM tidak confirm sebagai finding
```

`web.config` berisi connection strings, API keys, app secrets. Ini **high impact** jika confirmed.

### Root Cause

LLM mungkin tidak trigger path traversal test karena `NewsAd` tidak terdeteksi sebagai parameter yang vulnerable. Threshold `analyze_exploit_response()` mungkin terlalu ketat untuk LFI.

### Fix

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Di bagian PATH_INCLUSION anomaly handling:

# Jika PATH_INCLUSION anomaly terdeteksi, tambahkan specific LFI tests
if "PATH_INCLUSION" in [a.split(":")[0] for a in anomalies]:
    logger.info(
        "[vuln_hunt] PATH_INCLUSION detected on %s — running LFI confirmation",
        url
    )

    LFI_PAYLOADS = [
        "../web.config",
        "../../web.config",
        "..\\web.config",
        "%2e%2e%2fweb.config",
        "....//web.config",
    ]

    for lfi_payload in LFI_PAYLOADS:
        try:
            resp = await _direct_request(
                url=url.replace(current_param_value, lfi_payload),
                timeout=10.0,
            )
            # Cek apakah web.config content terexpose
            if any(
                indicator in resp.get("body", "").lower()
                for indicator in [
                    "<connectionstrings>",
                    "<appsettings>",
                    "data source=",
                    "server=",
                    "password=",
                    "secret",
                ]
            ):
                logger.info(
                    "[vuln_hunt] LFI CONFIRMED on %s — web.config content exposed!",
                    url
                )
                confirmed_findings.append({
                    "title": "Local File Inclusion — web.config Exposed",
                    "severity": "critical",  # web.config exposure adalah critical
                    "vuln_class": "PATH_TRAVERSAL",
                    "target_url": url,
                    "description": (
                        f"LFI confirmed: parameter '{param}' allows "
                        "path traversal to web.config. "
                        "Connection strings and application secrets may be exposed."
                    ),
                    "request_raw": f"GET {url}?{param}={lfi_payload}",
                    "response_raw": resp.get("body", "")[:500],
                    "source": "lfi_confirmation",
                })
                break
        except Exception:
            continue
```

**Tambahkan juga ke LLM prompt untuk LFI confirmation:**

```python
# packages/pentra-agent/pentra_agent/llm/client.py
# Di analyze_exploit_response() — tambahkan LFI indicators

LFI_CONFIRMATION_INDICATORS = [
    "<connectionstrings>",
    "<appsettings>",
    "data source=",
    "initial catalog=",
    "user id=",
    "password=",
    "[fonts]",          # windows win.ini
    "root:x:0:0",      # /etc/passwd
    "daemon:",          # /etc/passwd
    "[boot loader]",    # boot.ini
]

# Jika response mengandung salah satu indicator di atas,
# verdict CONFIRMED regardless of LLM analysis
```

---

## Fix 3 — Severity Normalization CRITICAL→HIGH Mismatch

### Konteks

Log menunjukkan `severity=CRITICAL` tapi report menampilkan `HIGH`. Ini bisa membuat researcher salah prioritas.

### Fix

```python
# packages/pentra-agent/pentra_agent/nodes/report_node.py
# atau packages/pentra-shared/pentra_shared/utils/severity.py

SEVERITY_NORMALIZE = {
    # Lowercase mappings
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    "information": "info",

    # Uppercase/mixed case
    "CRITICAL":    "critical",
    "HIGH":        "high",
    "MEDIUM":      "medium",
    "LOW":         "low",
    "INFO":        "info",
    "INFORMATION": "info",

    # Nuclei specific
    "critical_severity": "critical",
    "high_severity":     "high",
    "medium_severity":   "medium",
    "low_severity":      "low",
    "info_severity":     "info",

    # CVSS-based
    "none":     "info",
    "unknown":  "medium",   # Default ke medium jika unknown
}

def normalize_severity(raw: str) -> str:
    """
    Normalize severity string ke lowercase standard.
    Fallback ke 'medium' jika tidak dikenal.
    """
    if not raw:
        return "medium"
    normalized = SEVERITY_NORMALIZE.get(raw) or SEVERITY_NORMALIZE.get(raw.lower())
    if not normalized:
        logger.warning("[severity] Unknown severity '%s' → defaulting to 'medium'", raw)
        return "medium"
    return normalized
```

**Pastikan `normalize_severity()` dipanggil di setiap titik yang set severity:**

```bash
# Cari semua tempat severity di-set tanpa normalize
grep -rn '"severity"' packages/pentra-agent/ --include="*.py" | \
  grep -v "normalize_severity" | grep -v "#" | head -20
```

---

## Fix 4 — Install bge-m3 (5 Menit, Manual)

```bash
# Jalankan di terminal
ollama pull bge-m3

# Verifikasi
ollama list | grep bge-m3
# Expected: bge-m3  Q8_0  XXXX MB

# Test embedding
python3 -c "
import httpx, json, asyncio

async def test():
    resp = await httpx.AsyncClient().post(
        'http://localhost:11434/api/embeddings',
        json={'model': 'bge-m3', 'prompt': 'SQL injection test'}
    )
    data = resp.json()
    embed_len = len(data.get('embedding', []))
    print(f'bge-m3 embedding dimension: {embed_len}')
    assert embed_len > 0, 'Embedding failed'
    print('bge-m3 ✅')

asyncio.run(test())
"
```

Setelah bge-m3 terinstall, trigger re-embed:

```bash
curl -sX POST http://localhost:8001/api/v1/admin/knowledge/reembed \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "bge-m3", "batch_size": 50}'
```

---

## Fix 5 — LFI Parameter Detection di LLM Prompt

Saat ini LLM tidak secara eksplisit diarahkan untuk test path-like parameters. Perbaiki dengan menambahkan heuristics:

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py

LFI_PRONE_PARAM_NAMES = [
    "file", "path", "page", "template", "include", "load", "read",
    "doc", "document", "view", "news", "article", "feed", "content",
    "NewsAd", "ad", "src", "source", "dir", "folder", "location",
]

def _is_lfi_candidate(param: str, value: str) -> bool:
    """
    Cek apakah parameter adalah kandidat LFI.
    True jika: nama param mengandung path-like keywords,
               atau value mengandung path separators.
    """
    param_lower = param.lower()

    # Cek nama parameter
    if any(lfi in param_lower for lfi in [p.lower() for p in LFI_PRONE_PARAM_NAMES]):
        return True

    # Cek value — jika mengandung path separator atau ekstensi file
    if any(c in value for c in ["/", "\\", ".asp", ".php", ".html", ".txt", ".xml"]):
        return True

    return False

# Gunakan di _run_llm_burp_active_testing():
for param, value in candidates:
    if _is_lfi_candidate(param, value):
        # Force include LFI playbook untuk param ini
        playbooks_to_run.append("path_traversal")
        logger.info("[vuln_hunt] LFI candidate: %s=%s — adding path_traversal playbook", param, value)
```

---

## Fix 6 — Nuclei Verbose Debug Mode

Untuk debugging nuclei 0 findings di production:

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Tambahkan flag DEBUG_NUCLEI via env var

import os
NUCLEI_DEBUG = os.getenv("NUCLEI_DEBUG", "false").lower() == "true"

# Di _run_nuclei():
if NUCLEI_DEBUG:
    nuclei_cmd.extend(["-v", "-debug"])
    logger.debug("[nuclei] DEBUG MODE — verbose output enabled")

# Log full output jika debug
if NUCLEI_DEBUG or not findings:
    logger.warning(
        "[nuclei] Full stdout (first 2000 chars):\n%s",
        stdout[:2000]
    )
    logger.warning(
        "[nuclei] Full stderr (first 1000 chars):\n%s",
        stderr[:1000]
    )
```

```bash
# Jalankan dengan debug
NUCLEI_DEBUG=true \
  uv run uvicorn app.main:app --host 0.0.0.0 --port 8001
```

---

## Checklist Sprint 17 Fixes

```
Fix 1 — Nuclei 0 Findings
[ ] Diagnosa manual: nuclei -u http://testaspnet.vulnweb.com/ -tags sqli -silent
[ ] Verifikasi HTTPS→HTTP fallback ada di _run_nuclei()
[ ] Tambahkan IIS/ASP tags ke default tags
[ ] Naikan timeout dari 10 ke 15 detik
[ ] Tambahkan verbose logging jika 0 findings
[ ] Test: test_nuclei_https_fallback_to_http pass
[ ] Test: test_nuclei_tags_include_iis_asp pass
[ ] Verifikasi: nuclei return > 0 findings pada testaspnet.vulnweb.com

Fix 2 — LFI NewsAd
[ ] _is_lfi_candidate() function dibuat
[ ] LFI_PRONE_PARAM_NAMES list mencakup "NewsAd"
[ ] PATH_INCLUSION anomaly trigger LFI confirmation sequence
[ ] LFI_CONFIRMATION_INDICATORS list dibuat
[ ] LFI CRITICAL finding muncul jika web.config content terexpose
[ ] Verifikasi: /ReadNews.aspx?NewsAd=../web.config di-test otomatis

Fix 3 — Severity Normalization
[ ] normalize_severity() function dibuat
[ ] SEVERITY_NORMALIZE mapping lengkap (all variants)
[ ] Dipanggil di semua titik yang set severity
[ ] Verifikasi: log dan report menampilkan severity yang sama

Fix 4 — bge-m3
[ ] ollama pull bge-m3 berhasil
[ ] embedding dimension > 0
[ ] Re-embed 1000+ records dengan bge-m3 triggered
[ ] Search quality improvement terasa (cek dengan query "ASP.NET SQLi")

Fix 5 — LFI Detection Improvement
[ ] _is_lfi_candidate() check di candidate selection loop
[ ] path_traversal playbook auto-added untuk LFI candidates

Fix 6 — Nuclei Debug Mode
[ ] NUCLEI_DEBUG env var support
[ ] Full stdout/stderr logged jika 0 findings

Test Coverage
[ ] 2 tests baru untuk nuclei fix pass
[ ] Total: 144 + 4 baru = 148+ tests, 0 failed

E2E Validation
[ ] Jalankan engagement baru setelah semua fix
[ ] Nuclei harus return > 0 findings
[ ] LFI pada NewsAd harus di-confirm atau di-reject dengan alasan jelas
[ ] Severity konsisten antara log dan report
```

---

## Prompt untuk Copilot

**Mulai Fix 1 (Nuclei):**
```
Baca CLAUDE.md, PROGRESS_REPORT.md, dan SPRINT-17-FIXES.md.

Issue: E2E run pada testaspnet.vulnweb.com menghasilkan nuclei 0 findings
padahal target deliberately vulnerable (ASP.NET + IIS + MSSQL).

Lakukan Fix 1 dari SPRINT-17-FIXES.md:

1. Cari fungsi nuclei runner di vuln_hunt_node.py
2. Verifikasi HTTPS→HTTP fallback ada
3. Tambahkan IIS/ASP-specific tags ke NUCLEI_TAGS
4. Naikan timeout ke 15 detik
5. Tambahkan verbose logging jika 0 findings
6. Buat packages/pentra-agent/tests/test_nuclei.py dengan 2 tests
7. Jalankan tests

Laporkan: baris mana di vuln_hunt_node.py nuclei runner berada,
dan apa root cause nuclei 0 findings.
```

**Mulai Fix 2 (LFI) setelah Fix 1 selesai:**
```
Fix 1 selesai. Sekarang Fix 2 — LFI NewsAd.

1. Buat _is_lfi_candidate(param, value) function
2. Buat LFI_PRONE_PARAM_NAMES list (include "NewsAd")
3. Update PATH_INCLUSION anomaly handling untuk trigger LFI confirmation
4. Test manual: apakah /ReadNews.aspx?NewsAd=../web.config
   menghasilkan finding di engagement berikutnya
```

**Fix 3 + 4 (cepat):**
```
Fix 1+2 selesai. Kerjakan Fix 3 dan Fix 4 secara berurutan:

Fix 3: Buat normalize_severity() function dan pastikan
       semua severity assignment memanggil fungsi ini.

Fix 4 (manual, bukan Copilot):
  ollama pull bge-m3
  curl POST /api/v1/admin/knowledge/reembed

Setelah selesai, jalankan full test suite:
  uv run pytest packages/ -q
```

---

## Setelah Semua Fix — E2E Validation Run

```bash
# Buat engagement baru untuk validasi
ENG_ID=$(curl -sX POST http://localhost:8001/api/v1/engagements \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "E2E-Sprint17-Fixes-Validation",
    "workspace_id": "'"$WS_ID"'",
    "mode": "semi_auto",
    "in_scope": ["testaspnet.vulnweb.com"],
    "llm_model": "qwen2.5:32b"
  }' | jq -r .id)

# Monitor log khusus untuk issues yang di-fix
tail -f /tmp/pentra.log | grep -E \
  "nuclei.*findings|HTTPS.*HTTP|fallback|LFI|NewsAd|PATH_INCLUSION|\
severity.*CRITICAL|severity.*critical|normalize"
```

**Expected setelah fix:**
```
[nuclei] 15+ findings (bukan 0)
[vuln_hunt] LFI candidate: NewsAd → adding path_traversal playbook
[vuln_hunt] LFI CONFIRMED on /ReadNews.aspx — web.config content exposed!
[severity] normalized: critical → critical (consistent)
Total findings: 12+ (10 dari before + nuclei + LFI)
```

---

*SPRINT-17-FIXES.md — Pentra AI*  
*Fix 6 issues dari E2E run: nuclei 0 findings, LFI unconfirmed, severity mismatch*  
*Target: 148+ tests, nuclei >0 findings, LFI confirmed*
