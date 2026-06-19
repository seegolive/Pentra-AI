# BURP-PRO-MCP-SETUP.md — Pentra AI
> **Untuk:** Setup dan validasi Burp Suite Pro + MCP integration dengan Pentra AI  
> **Prereq:** Burp Suite Pro sudah terinstall dan berlisensi  
> **Tujuan:** Aktifkan BurpMCPClient yang sudah ada di kode agar benar-benar terhubung ke Burp Pro

---

## Gambaran Arsitektur

```
Pentra AI (Docker)          Host Machine
─────────────────           ────────────────────────────────
pentra-agent                Burp Suite Pro
  │                           │
  │  HTTP ke                  │  MCP Extension (JAR)
  │  host.docker.internal      │  berjalan di dalam Burp
  │  port 9876                 │  expose SSE server
  └──────────────────────────► http://127.0.0.1:9876
                               │
                          Browser / Target
```

Burp Pro berjalan di **host machine** (bukan di Docker).  
MCP server expose SSE endpoint di `http://127.0.0.1:9876`.  
Agent di Docker mengakses via `http://host.docker.internal:9876`.

---

## Langkah 1 — Install MCP Extension di Burp Suite Pro

### 1a. Via BApp Store (paling mudah)

Install BApps langsung dari dalam Burp via BApp Store di Extender tool.

1. Buka **Burp Suite Professional**
2. Klik tab **Extensions** (atau Extender di versi lama)
3. Klik **BApp Store**
4. Search: **"MCP Server"**
5. Klik **Install**
6. Tunggu hingga selesai — tab **MCP** akan muncul di header Burp

### 1b. Manual via JAR file (jika BApp Store tidak tersedia)

Extension didistribusikan sebagai satu JAR file bernama `burp-mcp-all.jar` yang berisi semua dependencies dan embedded MCP proxy server.

```bash
# Prerequisites: Java + jar command harus ada di PATH
java --version   # verifikasi Java ada
jar --version    # verifikasi jar ada

# Clone dan build
git clone https://github.com/PortSwigger/mcp-server.git
cd mcp-server
./gradlew shadowJar
# JAR ada di: build/libs/burp-mcp-all.jar
```

Load ke Burp:

Buka Burp Suite → Extensions tab → klik Add → Set Extension Type ke Java → pilih file `burp-mcp-all.jar` → klik Next untuk load extension.

---

## Langkah 2 — Konfigurasi MCP Extension

Konfigurasi extension dilakukan melalui Burp Suite UI di tab MCP:
- **Toggle MCP Server**: checkbox Enabled mengontrol apakah MCP server aktif
- **Enable config editing**: checkbox ini mengizinkan MCP server expose tools yang bisa edit konfigurasi Burp
- **Advanced options**: bisa konfigurasi port dan host untuk MCP server

**Yang perlu dikonfigurasi:**

1. Buka tab **MCP** di Burp
2. Centang **Enabled** → MCP server mulai berjalan
3. Catat **port** yang digunakan (default: `9876`)
4. Opsional: centang **Enable tools that can edit your config**

**Verifikasi MCP server aktif:**

```bash
# Dari host machine
curl http://127.0.0.1:9876

# Jika berhasil → response berupa SSE stream atau HTTP 200
# Jika gagal → cek apakah checkbox Enabled sudah dicentang
```

---

## Langkah 3 — Update Environment Variables Pentra AI

Update file `.env` di root repo:

```bash
# .env

# Burp MCP — aktifkan dengan URL yang benar
BURP_MCP_URL=http://host.docker.internal:9876
BURP_MCP_ENABLED=true

# Dari dalam Docker container, gunakan host.docker.internal
# Dari host machine langsung, gunakan http://127.0.0.1:9876
```

**Jika bukan Docker (development langsung di host):**

```bash
BURP_MCP_URL=http://127.0.0.1:9876
```

---

## Langkah 4 — Test Koneksi dari Pentra AI

### 4a. Test manual via Python

```bash
# Dari apps/api atau packages/pentra-tools
cd packages/pentra-tools
uv run python -c "
import asyncio
import httpx

async def test_burp():
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get('http://127.0.0.1:9876')
            print(f'Status: {resp.status_code}')
            print(f'Headers: {dict(resp.headers)}')
            print('✅ Burp MCP server reachable')
    except Exception as e:
        print(f'❌ Cannot reach Burp MCP: {e}')

asyncio.run(test_burp())
"
```

### 4b. Test via BurpMCPClient yang sudah ada

```bash
# Enable Burp integration test
BURP_MCP_ENABLED=true \
  uv run pytest packages/pentra-tools/tests/test_burp_mcp.py -v \
  -k "test_health_check"
```

### 4c. Test dari dalam Docker (jika pakai Docker Compose)

```bash
# Exec ke container api
docker compose exec api python -c "
import asyncio, httpx

async def test():
    url = 'http://host.docker.internal:9876'
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(url)
            print(f'✅ Connected: {r.status_code}')
    except Exception as e:
        print(f'❌ Failed: {e}')

asyncio.run(test())
"
```

---

## Langkah 5 — Aktifkan Tests Burp MCP yang Di-skip

Saat ini test Burp MCP di-skip karena `BURP_MCP_ENABLED` belum di-set.
Sekarang dengan Burp Pro aktif, jalankan full test suite:

```bash
# Set env var dan jalankan tests
BURP_MCP_ENABLED=true \
  uv run pytest packages/pentra-tools/tests/test_burp_mcp.py -v

# Expected: 24 tests pass (health_check, proxy_history, sitemap, dll)
```

---

## Langkah 6 — Validasi Fitur per Fitur

Jalankan validasi ini satu per satu dengan Burp Pro aktif dan sudah punya beberapa traffic di proxy:

### 6a. Health Check

```python
# Script: scripts/validate_burp_mcp.py

import asyncio
import os
import sys
sys.path.insert(0, "packages/pentra-tools")

from pentra_tools.burp.client import BurpMCPClient

BURP_URL = os.getenv("BURP_MCP_URL", "http://127.0.0.1:9876")

async def validate_all():
    client = BurpMCPClient(base_url=BURP_URL)
    results = {}

    # 1. Health check
    print("Testing health_check()...")
    try:
        ok = await client.health_check()
        results["health_check"] = "✅ PASS" if ok else "❌ FAIL (returned False)"
    except Exception as e:
        results["health_check"] = f"❌ ERROR: {e}"

    # 2. Proxy history
    print("Testing get_proxy_history()...")
    try:
        history = await client.get_proxy_history(limit=10)
        count = len(history)
        results["proxy_history"] = f"✅ PASS ({count} entries)"
    except Exception as e:
        results["proxy_history"] = f"❌ ERROR: {e}"

    # 3. Sitemap
    print("Testing get_sitemap()...")
    try:
        sitemap = await client.get_sitemap()
        count = len(sitemap)
        results["sitemap"] = f"✅ PASS ({count} entries)"
    except Exception as e:
        results["sitemap"] = f"❌ ERROR: {e}"

    # 4. Collaborator (Pro only)
    print("Testing generate_collaborator_payload()...")
    try:
        payload = await client.generate_collaborator_payload()
        if payload and payload.payload:
            results["collaborator"] = f"✅ PASS (payload: {payload.payload[:30]}...)"
        else:
            results["collaborator"] = "❌ FAIL (empty payload)"
    except Exception as e:
        results["collaborator"] = f"❌ ERROR: {e}"

    # Print summary
    print("\n" + "="*50)
    print("BURP MCP VALIDATION RESULTS")
    print("="*50)
    for feature, result in results.items():
        print(f"{feature:30} {result}")
    print("="*50)

    passed = sum(1 for r in results.values() if r.startswith("✅"))
    print(f"\n{passed}/{len(results)} features working\n")

asyncio.run(validate_all())
```

```bash
# Jalankan
BURP_MCP_URL=http://127.0.0.1:9876 \
  uv run python scripts/validate_burp_mcp.py
```

---

## Langkah 7 — Update CLAUDE.md dan .env.example

Setelah validasi berhasil, update dua file ini:

### Update `.env.example`

```bash
# .env.example — update section Burp:

# Burp Suite Pro MCP Integration
# Install extension dari BApp Store: Extensions → BApp Store → "MCP Server"
# Atau build manual dari: https://github.com/PortSwigger/mcp-server
# Default port setelah extension aktif: 9876
BURP_MCP_URL=http://host.docker.internal:9876   # dari Docker
# BURP_MCP_URL=http://127.0.0.1:9876            # dari host langsung
BURP_MCP_ENABLED=true
```

### Update `CLAUDE.md` Section 12 (Environment Variables)

Tambahkan note bahwa Burp MCP sekarang **required** (bukan opsional):

```markdown
# CLAUDE.md — update di Section 12:

# Burp Suite MCP — REQUIRED jika Burp Pro tersedia
BURP_MCP_URL=http://host.docker.internal:9876
BURP_MCP_ENABLED=true
# MCP server di-enable via Burp UI: Extensions → MCP tab → centang Enabled
# Port default: 9876. Bisa diubah di MCP tab → Advanced options
```

---

## Langkah 8 — Integrasi ke Agent (Sprint 10/11)

Setelah Burp MCP tervalidasi, pastikan `vuln_hunt_node` dan `recon_node` menggunakan Burp secara aktif.

### Update `recon_node.py` — tambahkan Burp sitemap analysis

```python
# packages/pentra-agent/pentra_agent/nodes/recon_node.py
# Tambahkan setelah nmap scan:

# ── Burp Sitemap Analysis ──────────────────────────────────
import os
burp_url = os.getenv("BURP_MCP_URL")
burp_enabled = os.getenv("BURP_MCP_ENABLED", "false").lower() == "true"

if burp_url and burp_enabled:
    try:
        from pentra_tools.burp.client import BurpMCPClient
        burp = BurpMCPClient(base_url=burp_url)
        if await burp.health_check():
            # Ambil sitemap untuk tambahan endpoint discovery
            sitemap = await burp.get_sitemap(
                url_prefix=f"https://{domain}"
            )
            for entry in sitemap:
                if scope.is_allowed(entry.url):
                    all_endpoints.append({
                        "url": entry.url,
                        "method": entry.method,
                        "source": "burp_sitemap",
                    })

            # Ambil proxy history untuk analisis traffic pattern
            history = await burp.get_proxy_history(
                filter_regex=domain,
                limit=100,
            )
            # Kirim ke LLM untuk analisis endpoint yang menarik
            if history:
                interesting = [
                    h for h in history
                    if h.response_status in (200, 201, 301, 302, 403, 500)
                    and scope.is_allowed(h.url)
                ]
                # Simpan di tool_outputs untuk analisis LLM berikutnya
                burp_summary = {
                    "source": "burp_proxy",
                    "total_requests": len(history),
                    "interesting_requests": len(interesting),
                    "sample_urls": [h.url for h in interesting[:10]],
                }
    except Exception:
        pass  # Burp tidak tersedia — graceful fallback
```

### Update `vuln_hunt_node.py` — aktifkan Burp active scan

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Tambahkan Burp active scan (hanya setelah HITL approval untuk target sensitif):

async def _run_burp_active_scan(
    target_url: str,
    scope: ScopeEnforcer,
) -> list[dict]:
    """
    Trigger Burp active scan dan poll hasilnya.
    Ini bisa memakan waktu beberapa menit.
    """
    import os
    burp_url = os.getenv("BURP_MCP_URL")
    if not burp_url or os.getenv("BURP_MCP_ENABLED", "false").lower() != "true":
        return []

    try:
        from pentra_tools.burp.client import BurpMCPClient
        burp = BurpMCPClient(base_url=burp_url)

        if not await burp.health_check():
            return []

        scope.validate_or_raise(target_url)

        # Trigger scan
        scan_task = await burp.trigger_active_scan(
            url=target_url,
            scope=scope.in_scope,
        )

        # Poll hingga selesai (max 5 menit)
        import asyncio
        for _ in range(30):  # 30 x 10s = 5 menit
            await asyncio.sleep(10)
            results = await burp.get_scan_results(scan_task.scan_id)
            if results:
                break

        # Convert ke finding format
        return [
            {
                "title": issue.issue_type,
                "severity": issue.severity,
                "target_url": issue.url,
                "description": issue.detail,
                "source": "burp_active_scan",
                "request_raw": issue.request or "",
                "response_raw": issue.response or "",
            }
            for issue in results
            if issue.confidence in ("certain", "firm")
        ]

    except Exception:
        return []
```

### Tambahkan Burp Collaborator untuk SSRF/Blind XSS

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Tambahkan helper untuk generate Collaborator payload:

async def _get_collaborator_payload() -> str | None:
    """
    Generate Burp Collaborator payload untuk OOB testing.
    Return payload string (e.g., "xyz123.oastify.com") atau None.
    """
    import os
    burp_url = os.getenv("BURP_MCP_URL")
    if not burp_url or os.getenv("BURP_MCP_ENABLED", "false").lower() != "true":
        return None
    try:
        from pentra_tools.burp.client import BurpMCPClient
        burp = BurpMCPClient(base_url=burp_url)
        result = await burp.generate_collaborator_payload()
        return result.payload if result else None
    except Exception:
        return None

# Penggunaan di vuln_hunt_node:
# collab_payload = await _get_collaborator_payload()
# if collab_payload:
#     # Inject ke payload generator sebagai blind XSS / SSRF endpoint
#     # Misalnya: <script src="//xyz123.oastify.com/x"></script>
#     ...
```

---

## Troubleshooting

### Problem: `Connection refused` ke port 9876

```
Solusi:
1. Pastikan Burp Pro sudah dibuka dan berjalan
2. Pastikan extension MCP Server sudah ter-load (ada di Extensions → Installed)
3. Pastikan checkbox Enabled di tab MCP sudah dicentang
4. Cek apakah port 9876 sudah dipakai proses lain:
   lsof -i :9876
5. Coba ganti port di MCP tab → Advanced options
```

### Problem: Extension ter-load tapi tidak ada tab MCP

```
Solusi:
1. Cek Extensions → Installed → pilih "MCP Server" → tab Output
   Lihat apakah ada error message
2. Pastikan Java versi compatible (Java 11+)
3. Restart Burp Suite dan load ulang extension
4. Coba build ulang JAR dari source
```

### Problem: `health_check()` return False atau error

```
Solusi:
1. Verifikasi SSE endpoint langsung:
   curl -N http://127.0.0.1:9876/sse
   Harus dapat response (bukan connection refused)

2. Cek firewall/antivirus yang mungkin blokir port

3. Dari Docker, pastikan BURP_MCP_URL pakai host.docker.internal:
   BURP_MCP_URL=http://host.docker.internal:9876
   (Bukan localhost atau 127.0.0.1 dari dalam container)
```

### Problem: Proxy history kosong

```
Solusi:
1. Pastikan browser/target sudah dikonfigurasi pakai Burp proxy (127.0.0.1:8080)
2. Browse beberapa halaman target dulu sebelum fetch history
3. Cek filter di get_proxy_history() — mungkin filter regex terlalu ketat
```

### Problem: Collaborator tidak return payload (hanya di Burp Pro)

```
Solusi:
1. Pastikan menggunakan Burp Suite PROFESSIONAL (bukan Community)
2. Collaborator membutuhkan koneksi internet dari mesin Burp
3. Cek Burp → Project Options → Misc → Burp Collaborator Server
   Pastikan "Use the default Collaborator server" dipilih
4. Test manual: Burp → Collaborator client → Poll now
```

---

## Checklist Setup Burp Pro MCP

```
Setup
[ ] Burp Suite Pro terbuka dan berlisensi
[ ] Extension MCP Server ter-install (via BApp Store atau JAR manual)
[ ] Tab MCP muncul di header Burp
[ ] Checkbox Enabled dicentang di tab MCP
[ ] curl http://127.0.0.1:9876 return response (bukan connection refused)

Konfigurasi Pentra AI
[ ] BURP_MCP_URL=http://host.docker.internal:9876 di .env
[ ] BURP_MCP_ENABLED=true di .env
[ ] .env.example diupdate dengan instruksi Burp

Validasi
[ ] scripts/validate_burp_mcp.py: health_check ✅
[ ] scripts/validate_burp_mcp.py: proxy_history ✅
[ ] scripts/validate_burp_mcp.py: sitemap ✅
[ ] scripts/validate_burp_mcp.py: collaborator ✅
[ ] BURP_MCP_ENABLED=true pytest test_burp_mcp.py: 24 tests pass

Integrasi Agent
[ ] recon_node.py mengambil sitemap Burp jika BURP_MCP_ENABLED=true
[ ] recon_node.py mengambil proxy_history dan filter by scope
[ ] vuln_hunt_node.py trigger active scan pada target yang sudah disetujui HITL
[ ] _get_collaborator_payload() return payload string yang valid
[ ] Payload Collaborator di-inject ke dalfox untuk blind XSS testing
```

---

## Prompt untuk Copilot

Setelah setup Burp MCP selesai dan tervalidasi, gunakan prompt ini untuk update kode:

```
Burp Suite Pro sudah terhubung via MCP dan tervalidasi.
BURP_MCP_URL=http://host.docker.internal:9876, semua 24 Burp tests pass.

Sekarang update recon_node.py dan vuln_hunt_node.py di packages/pentra-agent/
untuk menggunakan BurpMCPClient secara aktif:

1. recon_node.py: tambahkan Burp sitemap fetch + proxy history analysis
   setelah nmap scan. Graceful fallback jika Burp tidak aktif.

2. vuln_hunt_node.py: tambahkan _run_burp_active_scan() dan
   _get_collaborator_payload() sesuai BURP-PRO-MCP-SETUP.md.

3. Pastikan scope.validate_or_raise() dipanggil sebelum setiap Burp call.

Ikuti semua konvensi di CLAUDE.md.
```

---

*BURP-PRO-MCP-SETUP.md — Pentra AI*  
*Panduan setup dan validasi Burp Suite Pro MCP integration*
