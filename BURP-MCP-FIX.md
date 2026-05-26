# BURP-MCP-FIX.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Problem:** Log menunjukkan `Burp MCP not configured — skipping proxy history`  
> **Root cause:** `BURP_MCP_URL` tidak ada di environment saat worker berjalan  
> **Tujuan:** Fix env var, perbaiki kode, dan pastikan Burp aktif di setiap engagement

---

## Log yang Ditemukan

```
2026-05-26 16:12:25 INFO  [vuln_hunt_node] Starting vuln hunt for localhost:8081
2026-05-26 16:12:25 DEBUG [vuln_hunt_node] open ports: [5432, 6379, 8080, 9000]
2026-05-26 16:14:10 INFO  [vuln_hunt_node] _nuclei_scan(None) → 30 findings
2026-05-26 16:16:36 INFO  [vuln_hunt_node] _nuclei_scan(['tcp','javascript']) → 29 findings
2026-05-26 16:16:36 INFO  [vuln_hunt_node] nuclei: http=30 net=29 total=59
2026-05-26 16:16:36 DEBUG [vuln_hunt_node] Burp MCP not configured — skipping proxy history
```

Nuclei berjalan bagus (59 findings). Tapi **Burp dilewati sepenuhnya** karena env var tidak di-set.

---

## Root Cause

Di `vuln_hunt_node.py` ada guard seperti ini:

```python
burp_url = os.getenv("BURP_MCP_URL")
if not burp_url:
    logger.debug("Burp MCP not configured — skipping proxy history")
    return []
```

Env var `BURP_MCP_URL` tidak ada atau kosong di process environment saat Celery worker berjalan. Akibatnya seluruh logika Burp — proxy history, active scan, Collaborator — diskip.

---

## Fix 1 — Environment Variable (WAJIB)

### Tambahkan ke `.env`

```bash
# Di root repo, buka .env dan tambahkan:

# Burp Suite Pro MCP Integration
# Burp Pro harus berjalan di host machine dengan MCP extension enabled
# Tab MCP di Burp → centang "Enabled" → default port 9876

# Jika worker berjalan langsung di host (bukan Docker):
BURP_MCP_URL=http://127.0.0.1:9876

# Jika worker berjalan di Docker container:
# BURP_MCP_URL=http://host.docker.internal:9876

BURP_MCP_ENABLED=true
```

### Verifikasi env var terbaca

```bash
# Jika worker berjalan langsung di terminal:
grep BURP .env
# Harus ada dua baris BURP_MCP_URL dan BURP_MCP_ENABLED

# Pastikan worker load .env — restart worker setelah edit:
# Ctrl+C → jalankan ulang

# Test env terbaca:
python -c "
import os
from dotenv import load_dotenv
load_dotenv()
print('BURP_MCP_URL:', os.getenv('BURP_MCP_URL'))
print('BURP_MCP_ENABLED:', os.getenv('BURP_MCP_ENABLED'))
"
# Output harus:
# BURP_MCP_URL: http://127.0.0.1:9876
# BURP_MCP_ENABLED: true
```

---

## Fix 2 — Perbaikan Kode di vuln_hunt_node.py

Problem kedua: log hanya `DEBUG` — tidak ada `INFO` sama sekali tentang status Burp. Pengguna tidak tahu apakah Burp sengaja dilewati atau ada error. Perbaiki logging dan tambahkan startup check.

**Update `packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py`:**

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py

import os
import logging

logger = logging.getLogger(__name__)

# ── Burp MCP helpers ──────────────────────────────────────────────────────

def _get_burp_config() -> tuple[str | None, bool]:
    """
    Baca konfigurasi Burp MCP dari environment.
    Return: (burp_url, is_enabled)
    """
    url = os.getenv("BURP_MCP_URL", "").strip()
    enabled = os.getenv("BURP_MCP_ENABLED", "false").lower() == "true"
    return (url if url else None, enabled)


async def _check_burp_connection(burp_url: str) -> bool:
    """
    Cek apakah Burp MCP server bisa diakses.
    Return True jika online, False jika tidak.
    Log dengan INFO agar terlihat di output.
    """
    try:
        from pentra_tools.burp.client import BurpMCPClient
        client = BurpMCPClient(base_url=burp_url)
        ok = await client.health_check()
        if ok:
            logger.info("[vuln_hunt_node] Burp MCP connected at %s", burp_url)
        else:
            logger.warning(
                "[vuln_hunt_node] Burp MCP health check FAILED at %s — "
                "skipping Burp integration", burp_url
            )
        return ok
    except Exception as e:
        logger.warning(
            "[vuln_hunt_node] Burp MCP unreachable at %s: %s — "
            "skipping Burp integration", burp_url, e
        )
        return False


async def _get_burp_proxy_history(
    burp_url: str,
    scope_enforcer,
    domain: str,
) -> list[dict]:
    """Ambil proxy history dari Burp, filter by scope."""
    try:
        from pentra_tools.burp.client import BurpMCPClient
        client = BurpMCPClient(base_url=burp_url)
        history = await client.get_proxy_history(
            filter_regex=domain,
            limit=100,
        )
        in_scope = [
            {
                "url": h.url,
                "method": h.method,
                "status": h.response_status,
                "source": "burp_proxy",
            }
            for h in history
            if scope_enforcer.is_allowed(h.url)
        ]
        logger.info(
            "[vuln_hunt_node] Burp proxy history: %d total, %d in-scope",
            len(history), len(in_scope)
        )
        return in_scope
    except Exception as e:
        logger.warning("[vuln_hunt_node] Burp proxy history error: %s", e)
        return []


async def _run_burp_active_scan(
    burp_url: str,
    target_url: str,
    scope_enforcer,
) -> list[dict]:
    """
    Trigger Burp active scan dan poll hasilnya.
    DESTRUCTIVE — hanya dipanggil setelah HITL approval.
    """
    import asyncio
    try:
        from pentra_tools.burp.client import BurpMCPClient
        client = BurpMCPClient(base_url=burp_url)

        scope_enforcer.validate_or_raise(target_url)

        scan_task = await client.trigger_active_scan(
            url=target_url,
            scope=scope_enforcer.in_scope,
        )
        logger.info(
            "[vuln_hunt_node] Burp active scan started: %s", scan_task.scan_id
        )

        # Poll max 5 menit
        for attempt in range(30):
            await asyncio.sleep(10)
            results = await client.get_scan_results(scan_task.scan_id)
            if results:
                logger.info(
                    "[vuln_hunt_node] Burp active scan: %d issues found", len(results)
                )
                break
        else:
            logger.warning("[vuln_hunt_node] Burp active scan timed out after 5 minutes")
            results = []

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
    except Exception as e:
        logger.warning("[vuln_hunt_node] Burp active scan error: %s", e)
        return []


async def _get_collaborator_payload(burp_url: str) -> str | None:
    """Generate Burp Collaborator payload untuk OOB testing."""
    try:
        from pentra_tools.burp.client import BurpMCPClient
        client = BurpMCPClient(base_url=burp_url)
        result = await client.generate_collaborator_payload()
        if result and result.payload:
            logger.info(
                "[vuln_hunt_node] Burp Collaborator payload: %s",
                result.payload[:30]
            )
            return result.payload
        return None
    except Exception as e:
        logger.debug("[vuln_hunt_node] Collaborator not available: %s", e)
        return None


# ── Main node function ────────────────────────────────────────────────────

async def vuln_hunt_node(state):
    """
    Vulnerability hunt: nuclei + GraphQL + Burp (jika tersedia).
    Burp diaktifkan hanya jika BURP_MCP_URL dan BURP_MCP_ENABLED di-set.
    """
    from pentra_scope import ScopeEnforcer
    from langchain_core.messages import AIMessage

    scope = ScopeEnforcer(
        in_scope=state["scope"]["in_scope"],
        out_of_scope=state["scope"]["out_of_scope"],
    )

    domain = state["target"]["domain"]
    all_findings = []
    burp_active = False
    collaborator_payload = None

    # ── Cek Burp MCP ──────────────────────────────────────────────────
    burp_url, burp_enabled = _get_burp_config()

    if not burp_url:
        logger.info(
            "[vuln_hunt_node] BURP_MCP_URL not set — Burp integration disabled. "
            "Set BURP_MCP_URL=http://127.0.0.1:9876 in .env to enable."
        )
    elif not burp_enabled:
        logger.info(
            "[vuln_hunt_node] BURP_MCP_ENABLED=false — Burp integration disabled."
        )
    else:
        burp_active = await _check_burp_connection(burp_url)

    # ── Burp proxy history (jika aktif) ───────────────────────────────
    if burp_active:
        burp_history = await _get_burp_proxy_history(burp_url, scope, domain)
        if burp_history:
            all_findings.extend(burp_history)

        # Collaborator untuk OOB testing
        collaborator_payload = await _get_collaborator_payload(burp_url)

    # ── Nuclei scan ──────────────────────────────────────────────────
    # ... (existing nuclei logic tetap sama) ...

    # ── GraphQL analysis ─────────────────────────────────────────────
    # ... (existing graphql logic tetap sama) ...

    # ── Summary ──────────────────────────────────────────────────────
    burp_status = (
        f"Burp: connected ({sum(1 for f in all_findings if 'burp' in f.get('source',''))} findings)"
        if burp_active
        else "Burp: not configured (set BURP_MCP_URL in .env)"
    )

    return {
        "findings": all_findings,
        "current_phase": "vuln_hunt",
        "messages": [
            AIMessage(content=(
                f"Vuln hunt complete.\n"
                f"- Total findings: {len(all_findings)}\n"
                f"- Nuclei: {sum(1 for f in all_findings if f.get('source') == 'nuclei')}\n"
                f"- {burp_status}\n"
                f"- Collaborator: {'available' if collaborator_payload else 'not available'}"
            ))
        ],
    }
```

---

## Fix 3 — Perbaikan di recon_node.py

Sama seperti vuln_hunt, recon_node juga skip Burp tanpa log yang jelas. Perbaiki dengan pattern yang sama:

```python
# packages/pentra-agent/pentra_agent/nodes/recon_node.py
# Cari bagian Burp dan ganti dengan:

# ── Burp sitemap + proxy history ─────────────────────────────────────────
burp_url, burp_enabled = _get_burp_config()
burp_active = False

if not burp_url:
    logger.info(
        "[recon_node] BURP_MCP_URL not set — Burp sitemap disabled. "
        "Set BURP_MCP_URL in .env to enable."
    )
elif not burp_enabled:
    logger.info("[recon_node] BURP_MCP_ENABLED=false — Burp disabled.")
else:
    try:
        from pentra_tools.burp.client import BurpMCPClient
        client = BurpMCPClient(base_url=burp_url)
        if await client.health_check():
            burp_active = True
            logger.info("[recon_node] Burp MCP connected at %s", burp_url)

            # Sitemap
            sitemap = await client.get_sitemap(url_prefix=f"https://{domain}")
            for entry in sitemap:
                if scope.is_allowed(entry.url):
                    all_endpoints.append({
                        "url": entry.url,
                        "method": entry.method,
                        "source": "burp_sitemap",
                    })
            logger.info(
                "[recon_node] Burp sitemap: %d entries in-scope", 
                len([e for e in all_endpoints if e.get("source") == "burp_sitemap"])
            )
        else:
            logger.warning(
                "[recon_node] Burp MCP health check failed at %s", burp_url
            )
    except Exception as e:
        logger.warning("[recon_node] Burp MCP error: %s", e)
```

---

## Fix 4 — Tambahkan Burp Status ke PentraState

Supaya UI bisa tampilkan status Burp, tambahkan field ke state:

```python
# packages/pentra-agent/pentra_agent/graph/state.py
# Tambahkan field:

class PentraState(TypedDict):
    # ... existing fields ...
    
    # Burp integration status
    burp_connected: bool          # True jika Burp MCP aktif di sesi ini
    burp_proxy_entries: int       # Jumlah proxy history yang diambil
    collaborator_payload: str | None  # OOB payload untuk blind testing
```

---

## Fix 5 — Tampilkan Burp Status di Live Feed

Tambahkan event ke WebSocket stream saat Burp connect atau gagal:

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Tambahkan setelah _check_burp_connection():

# Publish ke WebSocket via state message
if burp_active:
    burp_ws_message = "🔌 Burp Suite Pro connected — proxy history + active scan enabled"
else:
    burp_ws_message = (
        "⚠️ Burp Suite Pro not connected — "
        "set BURP_MCP_URL in .env and ensure Burp is running"
    )

# Message ini akan muncul di Live Feed frontend
return_messages.append(AIMessage(content=burp_ws_message))
```

---

## Fix 6 — .env.example Update

Update `.env.example` dengan instruksi yang lebih jelas:

```bash
# .env.example

# ──────────────────────────────────────────────────────────────
# BURP SUITE PRO MCP INTEGRATION
# ──────────────────────────────────────────────────────────────
# Burp Suite Pro harus berjalan di host machine.
# MCP extension harus terinstall dan enabled.
#
# Setup:
# 1. Buka Burp Suite Pro
# 2. Extensions → BApp Store → search "MCP Server" → Install
# 3. Tab MCP muncul → centang "Enabled"
# 4. Default port: 9876
#
# Test koneksi:
#   curl http://127.0.0.1:9876
#
# Jika worker berjalan di host langsung (development):
BURP_MCP_URL=http://127.0.0.1:9876
#
# Jika worker berjalan di Docker container:
# BURP_MCP_URL=http://host.docker.internal:9876
#
# Set false jika Burp tidak tersedia (agent tetap berjalan tanpa Burp):
BURP_MCP_ENABLED=true
```

---

## Fix 7 — CLAUDE.md Update

Tambahkan catatan di `CLAUDE.md` Section 12 (Environment Variables):

```markdown
# CLAUDE.md — tambahkan di Section 12

# ── Burp Suite Pro MCP ───────────────────────────────────────────────────
# BURP_MCP_URL wajib di-set agar Burp aktif di agent nodes.
# Tanpa ini, agent skip proxy history + active scan + Collaborator.
#
# Tanda Burp aktif di log:
#   INFO [vuln_hunt_node] Burp MCP connected at http://127.0.0.1:9876
#
# Tanda Burp tidak aktif (butuh fix):
#   INFO [vuln_hunt_node] BURP_MCP_URL not set — Burp integration disabled
#
# Development (worker di host):
BURP_MCP_URL=http://127.0.0.1:9876
BURP_MCP_ENABLED=true
#
# Docker (worker di container):
# BURP_MCP_URL=http://host.docker.internal:9876
# BURP_MCP_ENABLED=true
```

---

## Checklist Fix

```
Env Fix
[ ] BURP_MCP_URL ditambahkan ke .env
[ ] BURP_MCP_ENABLED=true ditambahkan ke .env
[ ] python -c "import os; from dotenv import load_dotenv; load_dotenv(); print(os.getenv('BURP_MCP_URL'))"
    → Output: http://127.0.0.1:9876 (bukan None)
[ ] Worker direstart setelah edit .env

Burp Pro
[ ] Burp Suite Pro terbuka dan berlisensi
[ ] Extension MCP Server terinstall (ada di tab Extensions → Installed)
[ ] Tab MCP muncul di header Burp
[ ] Checkbox Enabled dicentang di tab MCP
[ ] curl http://127.0.0.1:9876 → response (bukan connection refused)

Kode Fix
[ ] _get_burp_config() dibuat sebagai helper function
[ ] _check_burp_connection() dengan logging INFO/WARNING
[ ] Log "BURP_MCP_URL not set" pakai INFO bukan DEBUG
[ ] Log "Burp MCP connected" pakai INFO
[ ] recon_node.py diupdate dengan pattern yang sama
[ ] vuln_hunt_node.py summary message include burp status
[ ] .env.example diupdate dengan instruksi lengkap
[ ] CLAUDE.md Section 12 diupdate

Verifikasi Log Setelah Fix
[ ] Log TIDAK lagi menunjukkan "Burp MCP not configured — skipping"
[ ] Log menunjukkan salah satu dari:
    ✅ "Burp MCP connected at http://127.0.0.1:9876"
    atau
    ✅ "BURP_MCP_URL not set — Burp integration disabled. Set BURP_MCP_URL in .env"
    (bukan lagi hanya DEBUG yang bisa terlewat)
[ ] Jika Burp aktif: log menunjukkan jumlah proxy entries
[ ] Jika Burp tidak aktif: agent tetap berjalan dan nuclei findings tetap ada
```

---

## Prompt untuk Copilot

```
Baca CLAUDE.md, PROGRESS.md, dan BURP-MCP-FIX.md secara lengkap.

Ada bug: log menunjukkan "Burp MCP not configured — skipping proxy history"
karena BURP_MCP_URL tidak di-set di environment.

Lakukan perbaikan berikut secara berurutan:

1. Tambahkan BURP_MCP_URL=http://127.0.0.1:9876 dan BURP_MCP_ENABLED=true
   ke .env.example (dengan komentar lengkap sesuai BURP-MCP-FIX.md Fix 6)

2. Update packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py:
   - Buat helper _get_burp_config() yang baca env var
   - Buat helper _check_burp_connection() dengan logging INFO/WARNING
   - Ganti "Burp MCP not configured" DEBUG log dengan INFO yang lebih jelas
   - Sesuaikan dengan kode di BURP-MCP-FIX.md Fix 2

3. Update packages/pentra-agent/pentra_agent/nodes/recon_node.py:
   - Pattern yang sama dengan vuln_hunt_node
   - Sesuaikan dengan kode di BURP-MCP-FIX.md Fix 3

4. Update CLAUDE.md Section 12 dengan catatan Burp env var
   sesuai BURP-MCP-FIX.md Fix 7

Setelah selesai, jalankan:
  uv run pytest packages/pentra-agent/tests/ -v
untuk verifikasi tidak ada regresi.

Sertakan juga instruksi cara restart worker agar env var baru terbaca.
```

---

## Quick Fix Manual (Sekarang, Tanpa Copilot)

Jika ingin langsung test Burp sebelum code fix:

```bash
# 1. Pastikan Burp Pro terbuka dan MCP enabled
curl http://127.0.0.1:9876
# Harus ada response

# 2. Set env var dan restart worker langsung
export BURP_MCP_URL=http://127.0.0.1:9876
export BURP_MCP_ENABLED=true

# 3. Restart Celery worker
# Ctrl+C worker yang berjalan, lalu:
cd apps/worker
BURP_MCP_URL=http://127.0.0.1:9876 \
BURP_MCP_ENABLED=true \
uv run celery -A app.worker worker -l info -Q default

# 4. Jalankan ulang engagement
# Log harus berubah dari:
#   DEBUG: Burp MCP not configured — skipping proxy history
# Menjadi:
#   INFO: Burp MCP connected at http://127.0.0.1:9876
#   INFO: Burp proxy history: N total, M in-scope
```

---

*BURP-MCP-FIX.md — Pentra AI*  
*Fix untuk: "Burp MCP not configured — skipping proxy history"*  
*Root cause: BURP_MCP_URL tidak di-set di environment worker*
