# PHASE-2-EXECUTION.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `docs/PRD.md` → `PROGRESS.md` → file ini  
> **Status MVP saat ini:** Lihat `PROGRESS.md` — semua Phase 1–3 MVP sudah selesai  
> **Tujuan dokumen ini:** Eksekusi Sprint 1–3 post-MVP secara terstruktur dan terurut

---

## Konteks Penting Sebelum Mulai

MVP Pentra AI sudah berjalan dengan:
- Knowledge Engine (1.500 records di Qdrant — perlu diperbesar ke 50.000+)
- LangGraph agent dengan HITL semi-auto mode
- Tool wrappers: subfinder, nmap, nuclei, httpx, BurpMCPClient (kode ada, belum ditest real)
- React UI: workspaces, engagements, live feed, findings, KB browser
- Auth: JWT + bcrypt, admin + user roles
- Docker Compose: 7 services berjalan

**Jangan ubah** arsitektur yang sudah ada. Tambah di atas fondasi yang ada.  
**Selalu** jalankan `uv run pytest` setelah setiap task selesai.  
**Selalu** scope check di baris pertama setiap tool wrapper baru.

---

## Sprint 1 — Make it Real

> **Prioritas:** Validasi integrasi nyata + perkuat fondasi yang ada  
> **Estimasi:** 1–2 minggu  
> **Urutan eksekusi wajib diikuti — setiap task bergantung pada task sebelumnya**

---

### Task 1.1 — Burp Suite MCP End-to-End Integration

**Konteks:**  
`BurpMCPClient` sudah ada di `packages/pentra-tools/burp/client.py` tapi belum ditest dengan Burp Pro aktif. Burp MCP server dari PortSwigger berjalan di `http://host.docker.internal:9876` (dari dalam Docker) atau `http://127.0.0.1:9876` (dari host).

**Yang harus dikerjakan:**

```
packages/pentra-tools/burp/
├── client.py          ← Review dan fix existing code
├── models.py          ← Pydantic models untuk MCP responses
├── exceptions.py      ← BurpConnectionError, BurpScanError
└── tests/
    └── test_burp_mcp.py  ← Integration tests (skip jika Burp tidak aktif)
```

**Implementasi `client.py` — pastikan semua method ini ada dan benar:**

```python
class BurpMCPClient:
    """
    Client untuk PortSwigger official MCP Server extension.
    MCP server berjalan di dalam Burp Suite Pro.
    Default port: 9876
    
    Reference: https://portswigger.net/burp/documentation/desktop/tools/mcp-server
    """
    
    async def health_check(self) -> bool:
        """Cek apakah Burp MCP server aktif dan bisa diakses."""
        ...
    
    async def get_proxy_history(
        self,
        filter_regex: str | None = None,
        limit: int = 100
    ) -> list[ProxyEntry]:
        """
        Ambil proxy history untuk analisis LLM.
        Gunakan filter_regex untuk filter URL pattern tertentu.
        """
        ...
    
    async def get_sitemap(
        self, 
        url_prefix: str | None = None
    ) -> list[SitemapEntry]:
        """Ambil sitemap Burp untuk attack surface mapping."""
        ...
    
    async def send_to_repeater(
        self,
        request: HttpRequest,
        tab_name: str | None = None
    ) -> RepeaterTab:
        """Buat Repeater tab dengan request yang sudah dimodifikasi."""
        ...
    
    async def trigger_active_scan(
        self,
        url: str,
        scope: list[str]
    ) -> ScanTask:
        """
        Trigger active scan Burp pada URL tertentu.
        scope: list domain yang boleh di-scan (scope enforcement).
        """
        ...
    
    async def get_scan_results(
        self,
        scan_id: str
    ) -> list[ScanIssue]:
        """Poll hasil active scan berdasarkan scan_id."""
        ...
    
    async def generate_collaborator_payload(self) -> CollaboratorPayload:
        """Generate Burp Collaborator payload untuk OOB testing (Pro only)."""
        ...
    
    async def poll_collaborator(
        self,
        payload_id: str
    ) -> list[CollaboratorInteraction]:
        """Poll Collaborator interactions untuk SSRF/blind XSS detection."""
        ...
```

**Models yang harus ada di `models.py`:**

```python
class ProxyEntry(BaseModel):
    id: str
    url: str
    method: str
    request_headers: dict[str, str]
    request_body: str | None
    response_status: int | None
    response_headers: dict[str, str]
    response_body: str | None
    timestamp: datetime

class ScanIssue(BaseModel):
    issue_type: str
    severity: Literal["high", "medium", "low", "information"]
    confidence: Literal["certain", "firm", "tentative"]
    url: str
    detail: str
    remediation: str | None
    request: str | None
    response: str | None

class CollaboratorPayload(BaseModel):
    payload: str          # e.g., "xyz.oastify.com"
    payload_id: str

class CollaboratorInteraction(BaseModel):
    interaction_type: Literal["dns", "http", "smtp"]
    timestamp: datetime
    client_ip: str
    data: dict
```

**Test file `test_burp_mcp.py`:**

```python
import pytest
import os

# Skip semua test jika Burp tidak aktif
pytestmark = pytest.mark.skipif(
    os.getenv("BURP_MCP_ENABLED", "false").lower() != "true",
    reason="Burp Suite Pro not available in this environment"
)

@pytest.mark.asyncio
async def test_health_check_returns_true():
    client = BurpMCPClient(base_url="http://localhost:9876")
    assert await client.health_check() is True

@pytest.mark.asyncio
async def test_get_proxy_history_returns_list():
    client = BurpMCPClient(base_url="http://localhost:9876")
    history = await client.get_proxy_history(limit=10)
    assert isinstance(history, list)

@pytest.mark.asyncio  
async def test_generate_collaborator_payload():
    client = BurpMCPClient(base_url="http://localhost:9876")
    payload = await client.generate_collaborator_payload()
    assert payload.payload.endswith(".oastify.com")
```

**Integrasi ke `vuln_hunt_node` di `packages/pentra-agent/nodes/vuln_hunt.py`:**

Setelah BurpMCPClient berfungsi, tambahkan ke vuln_hunt_node:
1. Fetch proxy history → analisis LLM untuk temukan endpoint tidak terdokumentasi
2. Trigger active scan pada endpoint hasil recon
3. Poll hasil scan → convert `ScanIssue` ke `Finding`
4. Generate Collaborator payload untuk test SSRF pada endpoint yang dicurigai

---

### Task 1.2 — Agentic Mode (Full Auto tanpa HITL per step)

**Konteks:**  
Saat ini agent selalu pause di setiap HITL node. Perlu toggle mode: `semi_auto` (pause tiap step) vs `agentic` (hanya pause untuk destructive actions).

**Lokasi file:**
```
packages/pentra-agent/
├── graph/
│   ├── state.py      ← Sudah ada PentraState — tambah field mode
│   └── builder.py    ← Rebuild graph dengan conditional interrupt
└── nodes/
    └── hitl.py       ← Update logika interrupt berdasarkan mode
```

**Update `hitl.py`:**

```python
from langgraph.types import interrupt
from pentra_agent.graph.state import PentraState

async def hitl_plan_review(state: PentraState) -> dict:
    """
    Hanya interrupt jika mode semi_auto.
    Agentic mode: langsung lanjut tanpa pause.
    """
    if state["mode"] == "semi_auto":
        decision = interrupt({
            "type": "AWAITING_APPROVAL",
            "phase": "plan",
            "message": "Agent sudah membuat pentest plan. Review dan approve untuk lanjut.",
            "data": {
                "plan": state.get("pentest_plan"),
                "target": state["target"]["domain"],
                "scope": state["scope"]["in_scope"],
            }
        })
        return {"user_decision": decision}
    
    # Agentic mode: auto-approve, log saja
    await audit_log.write(
        engagement_id=state["engagement_id"],
        action="auto_approved_plan",
        detail={"mode": "agentic", "plan": state.get("pentest_plan")}
    )
    return {"user_decision": "approve"}


async def hitl_exploit_review(state: PentraState) -> dict:
    """
    SELALU interrupt — destructive action, tidak peduli mode.
    Ini adalah safety gate yang tidak boleh di-bypass.
    """
    decision = interrupt({
        "type": "AWAITING_APPROVAL",
        "phase": "exploit",
        "message": "⚠️ Agent akan melakukan exploit validation. Ini adalah destructive action — selalu butuh approval.",
        "data": {
            "finding": state.get("current_finding"),
            "proposed_payload": state.get("proposed_payload"),
            "risk_level": "HIGH"
        }
    })
    return {"user_decision": decision}
```

**Update API endpoint untuk support agentic mode:**

```python
# apps/api/app/api/v1/engagements.py

class EngagementCreate(BaseModel):
    name: str
    workspace_id: UUID
    mode: Literal["semi_auto", "agentic"] = "semi_auto"  # default semi_auto
    in_scope: list[str]
    out_of_scope: list[str] = []
    llm_model: str = "qwen2.5-coder:32b"
```

**Update UI toggle di frontend:**

```typescript
// apps/web/src/components/EngagementModeToggle.tsx
// Toggle switch: Semi-Auto ↔ Agentic
// Tampilkan warning saat pilih Agentic:
// "Mode Agentic akan menjalankan semua fase secara otomatis.
//  Hanya exploit validation yang akan meminta persetujuan manual."
```

---

### Task 1.3 — Screenshot & Evidence Capture

**Konteks:**  
MinIO sudah berjalan. Butuh headless browser untuk capture screenshot sebagai evidence setiap finding.

**Buat package baru: `packages/pentra-tools/screenshot/`**

```python
# packages/pentra-tools/screenshot/capture.py

import asyncio
from playwright.async_api import async_playwright
from pentra_scope import ScopeEnforcer

class ScreenshotCapture:
    """
    Headless Chromium via Playwright untuk capture evidence.
    Gunakan untuk: screenshot finding, capture request/response di browser.
    """
    
    def __init__(self, scope_enforcer: ScopeEnforcer, minio_client):
        self.scope = scope_enforcer
        self.minio = minio_client
    
    async def capture_finding_evidence(
        self,
        url: str,
        finding_id: str,
        cookies: list[dict] | None = None,
        headers: dict | None = None,
        wait_for: str | None = None,  # CSS selector to wait for
    ) -> EvidenceResult:
        """
        Capture screenshot URL sebagai evidence finding.
        Upload ke MinIO, return path.
        
        Returns:
            EvidenceResult dengan screenshot_path, full_page_path, har_path
        """
        # 1. Scope check
        self.scope.validate_or_raise(url)
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            context = await browser.new_context(
                extra_http_headers=headers or {},
                record_har_path=f"/tmp/{finding_id}.har"
            )
            
            if cookies:
                await context.add_cookies(cookies)
            
            page = await context.new_page()
            await page.goto(url, wait_until="networkidle", timeout=30000)
            
            if wait_for:
                await page.wait_for_selector(wait_for, timeout=5000)
            
            # Viewport screenshot
            screenshot_bytes = await page.screenshot(type="png")
            
            # Full page screenshot
            full_page_bytes = await page.screenshot(
                full_page=True, type="png"
            )
            
            await context.close()
            await browser.close()
        
        # Upload ke MinIO
        screenshot_path = await self.minio.upload(
            bucket="evidence",
            key=f"findings/{finding_id}/screenshot.png",
            data=screenshot_bytes,
            content_type="image/png"
        )
        
        full_page_path = await self.minio.upload(
            bucket="evidence", 
            key=f"findings/{finding_id}/screenshot_full.png",
            data=full_page_bytes,
            content_type="image/png"
        )
        
        return EvidenceResult(
            finding_id=finding_id,
            screenshot_path=screenshot_path,
            full_page_path=full_page_path,
        )
    
    async def capture_http_evidence(
        self,
        request_raw: str,
        response_raw: str,
        finding_id: str,
    ) -> str:
        """
        Simpan raw HTTP request/response sebagai file evidence di MinIO.
        Return path ke file.
        """
        evidence = f"=== REQUEST ===\n{request_raw}\n\n=== RESPONSE ===\n{response_raw}"
        path = await self.minio.upload(
            bucket="evidence",
            key=f"findings/{finding_id}/http_evidence.txt",
            data=evidence.encode(),
            content_type="text/plain"
        )
        return path
```

**Dependencies yang perlu ditambah:**

```toml
# packages/pentra-tools/pyproject.toml
[project.optional-dependencies]
screenshot = ["playwright>=1.44.0"]
```

**Docker — tambah Playwright ke worker:**

```dockerfile
# infra/docker/Dockerfile.worker — tambahkan:
RUN pip install playwright && playwright install chromium --with-deps
```

**Integrasi ke report generator:**

Setelah `ScreenshotCapture` selesai, update `pentra-report` agar include screenshot dalam PDF dan HTML report. Setiap finding section harus punya:
- Screenshot thumbnail (embedded base64 di HTML)
- Link ke full screenshot di MinIO
- Raw HTTP evidence

---

### Task 1.4 — Expand Knowledge Base ke 10.000+ Records

**Konteks:**  
Saat ini hanya 1.500 records. Perlu jalankan scraper secara agresif dan tambah sumber baru.

**Jalankan H1 GraphQL scraper yang sudah ada:**

```bash
# Jalankan worker task secara manual untuk test
cd apps/worker
uv run celery -A app.worker call knowledge_update \
  --args='{"source": "h1_graphql", "max_pages": 200}'

# Monitor progress
uv run celery -A app.worker inspect active
```

**Tambah sumber baru: PayloadsAllThings importer**

```python
# apps/worker/tasks/payloads_all_things.py

"""
Import teknik dari PayloadsAllThings GitHub repo.
Ini adalah curated technique library — sangat valuable untuk knowledge base.

Repo: https://github.com/swisskyrepo/PayloadsAllThings
"""

import httpx
from pentra_knowledge.ingestion.processor import KnowledgeProcessor

PAYLOADS_ALL_THINGS_API = "https://api.github.com/repos/swisskyrepo/PayloadsAllThings/contents"

# Mapping folder ke VulnClass
FOLDER_VULN_CLASS_MAP = {
    "IDOR": "IDOR",
    "SQL Injection": "SQL_INJECTION", 
    "XSS Injection": "XSS",
    "Server Side Request Forgery": "SSRF",
    "File Inclusion": "PATH_TRAVERSAL",
    "Command Injection": "COMMAND_INJECTION",
    "XML External Entity": "XXE",
    "Server Side Template Injection": "SSTI",
    "Mass Assignment": "MASS_ASSIGNMENT",
    "Race Condition": "RACE_CONDITION",
    "GraphQL Injection": "GRAPHQL",
    "JWT Null Signature": "JWT_ISSUES",
    "OAuth Misconfiguration": "OAUTH_MISCONFIG",
}

async def import_payloads_all_things():
    """
    Clone atau fetch PayloadsAllThings, parse setiap README.md,
    extract payloads dan teknik, simpan ke knowledge base.
    """
    ...
```

**Tambah sumber: writeup blogs via RSS**

```python
# apps/worker/tasks/rss_ingestion.py

RSS_FEEDS = [
    "https://portswigger.net/research/rss",
    "https://www.hackerone.com/blog.rss",
    "https://pentester.land/newsletter/rss.xml",
    "https://blog.assetnote.io/feed.xml",
    "https://www.tarlogic.com/blog/feed/",
    "https://labs.detectify.com/feed/",
]

async def ingest_rss_feeds():
    """
    Fetch RSS feeds, ambil artikel baru,
    extract vulnerability technique via LLM,
    simpan ke knowledge base.
    Jalankan: setiap hari via Celery Beat schedule.
    """
    ...
```

**Update Celery Beat schedule:**

```python
# apps/worker/app/celeryconfig.py

beat_schedule = {
    # Sudah ada
    "h1-scraper-daily": {
        "task": "tasks.knowledge_update",
        "schedule": crontab(hour=2, minute=0),  # 02:00 setiap hari
        "args": [{"source": "h1_graphql", "max_pages": 50}]
    },
    # Tambahkan
    "rss-ingestion-daily": {
        "task": "tasks.rss_ingestion",
        "schedule": crontab(hour=3, minute=0),  # 03:00 setiap hari
    },
    "payloads-sync-weekly": {
        "task": "tasks.payloads_all_things",
        "schedule": crontab(day_of_week=1, hour=4, minute=0),  # Senin 04:00
    },
}
```

---

## Sprint 2 — Complete the Arsenal

> **Prioritas:** Lengkapi tool coverage + self-learning + multi-user isolation  
> **Estimasi:** 1–2 minggu  
> **Mulai Sprint 2 hanya setelah Sprint 1 semua task selesai dan test pass**

---

### Task 2.1 — Tool Wrappers: ffuf, dalfox, sqlmap, katana, amass

**Semua wrapper mengikuti pattern yang sama dari `CLAUDE.md` Section 9.**  
**Buat satu per satu — test dulu sebelum lanjut ke berikutnya.**

```
packages/pentra-tools/
├── recon/
│   ├── subfinder.py    ← Sudah ada
│   ├── nmap.py         ← Sudah ada  
│   ├── httpx.py        ← Sudah ada
│   ├── amass.py        ← BUAT BARU
│   └── katana.py       ← BUAT BARU
└── vuln/
    ├── nuclei.py       ← Sudah ada
    ├── ffuf.py         ← BUAT BARU
    ├── dalfox.py       ← BUAT BARU
    └── sqlmap.py       ← BUAT BARU
```

#### Task 2.1.1 — `AmassWrapper`

```python
# packages/pentra-tools/recon/amass.py

class AmassWrapper(AsyncToolWrapper):
    """
    Deep OSINT subdomain enumeration via amass.
    Lebih dalam dari subfinder — pakai OSINT sources.
    Lebih lambat (timeout: 600s default).
    
    Output: list[Subdomain] dengan IP, ASN, source
    """
    name = "amass"
    rate_limiter = RateLimiter(max_calls=3, period=60)
    timeout = 600

    async def run(self, domain: str, mode: Literal["passive", "active"] = "passive") -> ToolResult:
        # scope check WAJIB di baris pertama
        self.scope.validate_or_raise(domain)
        
        cmd = ["amass", "enum", "-passive" if mode == "passive" else "-active",
               "-d", domain, "-json"]
        # parse output: {"name": "sub.target.com", "addresses": [{"ip": "1.2.3.4", "asn": 12345}]}
        ...
```

#### Task 2.1.2 — `KatanaWrapper`

```python
# packages/pentra-tools/recon/katana.py

class KatanaWrapper(AsyncToolWrapper):
    """
    Web crawling dan endpoint discovery via katana (ProjectDiscovery).
    Crawl target → temukan endpoint, parameter, form, JS files.
    
    Output: list[Endpoint] dengan url, method, params, source
    """
    name = "katana"
    rate_limiter = RateLimiter(max_calls=5, period=60)
    timeout = 300

    async def run(
        self,
        url: str,
        depth: int = 3,
        js_crawl: bool = True,
        headless: bool = False,
    ) -> ToolResult:
        self.scope.validate_or_raise(url)
        
        cmd = ["katana", "-u", url, "-d", str(depth), "-json"]
        if js_crawl:
            cmd.append("-jc")
        if headless:
            cmd.extend(["-headless", "-system-chrome"])
        # parse output JSON per line
        ...
```

#### Task 2.1.3 — `FfufWrapper`

```python
# packages/pentra-tools/vuln/ffuf.py

class FfufWrapper(AsyncToolWrapper):
    """
    Directory dan parameter fuzzing via ffuf.
    Gunakan wordlist yang sudah ada di sistem atau bundled.
    
    Output: list[FfufResult] dengan url, status, size, words, lines
    """
    name = "ffuf"
    rate_limiter = RateLimiter(max_calls=5, period=60)
    timeout = 300
    
    # Bundled wordlists — tambahkan ke Docker image worker
    WORDLISTS = {
        "dirs_small": "/usr/share/wordlists/dirb/common.txt",
        "dirs_medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "params": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "api": "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
    }

    async def run(
        self,
        url: str,                          # URL dengan FUZZ placeholder
        wordlist: str = "dirs_small",
        extensions: list[str] | None = None,
        filter_status: list[int] | None = None,  # filter response codes
        match_status: list[int] | None = None,
    ) -> ToolResult:
        self.scope.validate_or_raise(url)
        
        cmd = ["ffuf", "-u", url, "-w", self.WORDLISTS[wordlist], "-json", "-s"]
        if extensions:
            cmd.extend(["-e", ",".join(f".{e}" for e in extensions)])
        if filter_status:
            cmd.extend(["-fc", ",".join(str(s) for s in filter_status)])
        if match_status:
            cmd.extend(["-mc", ",".join(str(s) for s in match_status)])
        ...
```

#### Task 2.1.4 — `DalfoxWrapper`

```python
# packages/pentra-tools/vuln/dalfox.py

class DalfoxWrapper(AsyncToolWrapper):
    """
    XSS scanning via dalfox.
    Jalankan hanya pada parameter yang sudah diidentifikasi — bukan blind scan.
    
    Output: list[XSSFinding] dengan url, param, payload, poc
    """
    name = "dalfox"
    rate_limiter = RateLimiter(max_calls=3, period=60)
    timeout = 300

    async def run(
        self,
        url: str,
        params: list[str] | None = None,  # specific params to test
        blind_xss_endpoint: str | None = None,  # Collaborator endpoint untuk blind XSS
    ) -> ToolResult:
        self.scope.validate_or_raise(url)
        
        cmd = ["dalfox", "url", url, "--format", "json"]
        if params:
            cmd.extend(["--data", "&".join(f"{p}=test" for p in params)])
        if blind_xss_endpoint:
            cmd.extend(["--blind", blind_xss_endpoint])
        ...
```

#### Task 2.1.5 — `SqlmapWrapper`

```python
# packages/pentra-tools/vuln/sqlmap.py

class SqlmapWrapper(AsyncToolWrapper):
    """
    SQL injection testing via sqlmap.
    
    ⚠️  DESTRUCTIVE — selalu butuh user approval sebelum dijalankan.
        Wrapper ini TIDAK boleh dipanggil langsung dari agent node.
        Hanya boleh dipanggil SETELAH user approve via HITL.
    
    Output: list[SqliFinding] dengan url, param, type, dbms, data
    """
    name = "sqlmap"
    rate_limiter = RateLimiter(max_calls=2, period=60)
    timeout = 600
    IS_DESTRUCTIVE = True  # Flag untuk HITL enforcement

    async def run(
        self,
        url: str,
        data: str | None = None,       # POST data
        params: list[str] | None = None,
        level: int = 1,               # 1-5, default 1 (paling aman)
        risk: int = 1,                # 1-3, default 1 (paling aman)
        technique: str = "BEUST",    # SQL injection techniques
    ) -> ToolResult:
        self.scope.validate_or_raise(url)
        
        cmd = [
            "sqlmap", "-u", url,
            "--batch",              # Non-interactive
            "--output-dir", f"/tmp/sqlmap_{uuid4().hex[:8]}",
            "--format=json",
            f"--level={level}",
            f"--risk={risk}",
            f"--technique={technique}",
        ]
        if data:
            cmd.extend(["--data", data])
        if params:
            cmd.extend(["-p", ",".join(params)])
        ...
```

**Update `Dockerfile.worker` untuk install semua tools:**

```dockerfile
# infra/docker/Dockerfile.worker

RUN apt-get update && apt-get install -y \
    nmap curl wget git python3-pip \
    # Tools baru
    amass \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based tools
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/hahwul/dalfox/v2@latest

# Install sqlmap
RUN pip install sqlmap

# Playwright untuk screenshot
RUN pip install playwright && playwright install chromium --with-deps

# SecLists wordlists
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git \
    /usr/share/seclists
```

**Integrasi ke agent nodes setelah semua wrapper selesai:**

```python
# packages/pentra-agent/nodes/recon.py — tambahkan:
# amass untuk deep subdomain OSINT
# katana untuk web crawling dan endpoint discovery

# packages/pentra-agent/nodes/vuln_hunt.py — tambahkan:
# ffuf untuk directory fuzzing pada setiap subdomain
# dalfox untuk XSS testing pada parameter yang ditemukan katana
# sqlmap HANYA setelah HITL approval di hitl_exploit_review
```

---

### Task 2.2 — Knowledge Base Self-Learning dari Findings

**Konteks:**  
Setiap confirmed finding dari engagement seharusnya bisa masuk ke knowledge base setelah user approve. Ini membuat Pentra AI semakin pintar seiring pemakaian.

**Buat endpoint baru:**

```python
# apps/api/app/api/v1/findings.py — tambahkan endpoint:

@router.post("/{finding_id}/submit-to-knowledge")
async def submit_finding_to_knowledge(
    finding_id: UUID,
    annotation: FindingAnnotation,  # user bisa tambah notes sebelum submit
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Submit confirmed finding ke knowledge base.
    User harus review dan annotate sebelum submit.
    
    Flow:
    1. Fetch finding dari DB
    2. Convert Finding → KnowledgeRecord
    3. LLM extract key_insight dan attack_technique
    4. BGE-M3 embed
    5. Simpan ke Qdrant + PostgreSQL knowledge_records
    """
    ...

class FindingAnnotation(BaseModel):
    additional_notes: str = ""
    key_insight: str = ""           # User bisa isi manual atau biarkan kosong (LLM isi)
    attack_technique: str = ""      # User bisa isi manual atau biarkan kosong (LLM isi)
    make_public: bool = False       # Untuk future: share ke komunitas
```

**Buat converter `Finding → KnowledgeRecord`:**

```python
# packages/pentra-knowledge/ingestion/from_finding.py

async def convert_finding_to_knowledge(
    finding: Finding,
    annotation: FindingAnnotation,
    llm_client: LLMClient,
    embedding_client: EmbeddingClient,
) -> KnowledgeRecord:
    """
    Convert internal Finding ke KnowledgeRecord untuk disimpan di knowledge base.
    
    Jika user tidak isi key_insight/attack_technique,
    gunakan LLM untuk extract dari reproduction_steps dan description.
    """
    
    # Gunakan annotation jika ada, fallback ke LLM extraction
    key_insight = annotation.key_insight or await llm_client.extract_insight(finding)
    attack_technique = annotation.attack_technique or await llm_client.extract_technique(finding)
    
    record = KnowledgeRecord(
        source="pentra_finding",
        source_id=str(finding.id),
        title=finding.title,
        vuln_class=finding.vuln_class,
        vuln_subclass=finding.vuln_subclass or "",
        severity=finding.severity,
        program=finding.target_url,   # domain sebagai program
        tech_stack=finding.tech_stack or [],
        endpoint_pattern=extract_pattern(finding.target_url),
        attack_technique=attack_technique,
        key_insight=key_insight,
        indicators=[],
        attack_steps=finding.reproduction_steps,
        what_tools_missed="Found via Pentra AI agent",
        pentra_tags=["from_engagement", "user_confirmed"],
    )
    
    # Embed dan return
    record.embedding_dense = await embedding_client.embed(record.to_search_text())
    return record
```

**Update UI — tombol "Submit to Knowledge Base" di Finding detail:**

```typescript
// apps/web/src/pages/FindingDetail.tsx

// Tambahkan button dan modal:
// [Submit to Knowledge Base] → buka modal dengan form:
//   - Key Insight (textarea, optional — LLM akan isi jika kosong)
//   - Attack Technique (textarea, optional)
//   - Additional Notes (textarea)
//   - [Submit] → POST /api/v1/findings/{id}/submit-to-knowledge
```

---

### Task 2.3 — Multi-user Workspace Isolation (Row-Level Security)

**Konteks:**  
Saat ini semua authenticated user bisa lihat semua workspace. Perlu isolasi sehingga user hanya lihat workspace yang dia punya atau yang di-share ke dia.

**Update DB models:**

```python
# apps/api/app/models/workspace.py — tambahkan:

class WorkspaceMember(Base):
    """Junction table: user ↔ workspace dengan role."""
    __tablename__ = "workspace_members"
    
    workspace_id: Mapped[UUID] = mapped_column(ForeignKey("workspaces.id"), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(20), default="operator")  # admin/operator/viewer
    added_at: Mapped[datetime] = mapped_column(default=func.now())
    added_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
```

**Update semua query workspace — tambahkan filter user:**

```python
# apps/api/app/services/workspace.py

async def get_user_workspaces(
    db: AsyncSession,
    user: User
) -> list[Workspace]:
    """
    Admin: lihat semua workspace.
    User biasa: hanya workspace yang dia adalah member.
    """
    if user.is_admin:
        result = await db.execute(select(Workspace))
        return result.scalars().all()
    
    result = await db.execute(
        select(Workspace)
        .join(WorkspaceMember, WorkspaceMember.workspace_id == Workspace.id)
        .where(WorkspaceMember.user_id == user.id)
    )
    return result.scalars().all()
```

**Alembic migration:**

```bash
uv run alembic revision --autogenerate -m "add_workspace_members_table"
uv run alembic upgrade head
```

---

### Task 2.4 — KB Manual Inject via UI

**Konteks:**  
Saat ini user hanya bisa inject knowledge via API/script. Perlu UI yang memudahkan upload writeup langsung dari browser.

**Buat halaman baru: `/knowledge/inject`**

```typescript
// apps/web/src/pages/KnowledgeInject.tsx

// Form dengan 3 cara inject:
// Tab 1: "Paste URL" — masukkan URL writeup/blog post
//   → Backend fetch URL, extract content, LLM parse
// Tab 2: "Upload File" — upload PDF atau Markdown
//   → Backend parse file, LLM extract structured data
// Tab 3: "Manual Form" — isi form langsung
//   → Form dengan semua field KnowledgeRecord

// Setelah submit: tampilkan preview parsed record
// → User review → [Confirm & Index] atau [Edit & Re-submit]
```

**Backend endpoints:**

```python
# apps/api/app/api/v1/knowledge.py — tambahkan:

@router.post("/inject/url")
async def inject_from_url(
    payload: InjectFromUrl,  # {"url": "https://..."}
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
) -> InjectJob:
    """Fetch URL, parse content, extract knowledge, index ke Qdrant."""
    job = await knowledge_service.create_inject_job(source_url=payload.url)
    background_tasks.add_task(knowledge_service.process_url_inject, job.id)
    return job  # return job_id, polling via GET /inject/jobs/{job_id}

@router.post("/inject/file")
async def inject_from_file(
    file: UploadFile,
    current_user: User = Depends(get_current_user),
) -> InjectJob:
    """Upload PDF atau Markdown, parse, index ke Qdrant."""
    ...

@router.get("/inject/jobs/{job_id}")
async def get_inject_job_status(job_id: UUID) -> InjectJob:
    """Poll status inject job (pending/processing/done/failed)."""
    ...
```

---

## Sprint 3 — Polish & Automate

> **Prioritas:** Kualitas, keamanan, dan kenyamanan penggunaan jangka panjang  
> **Estimasi:** 1 minggu  
> **Mulai Sprint 3 hanya setelah Sprint 2 semua task selesai**

---

### Task 3.1 — Payload Generator (pentra-payload)

**Buat package baru: `packages/pentra-payload/`**

```python
# packages/pentra-payload/generator.py

class PayloadGenerator:
    """
    Context-aware payload generation via LLM.
    Bukan generator generic — payload disesuaikan dengan:
    - Tech stack target (Rails vs Django vs Laravel)
    - Vulnerability class yang sedang ditest
    - Evidence dari knowledge base (payload yang berhasil di H1 reports)
    - Parameter context (nama param, tipe data, posisi)
    """
    
    async def generate(
        self,
        context: PayloadContext,
        knowledge_records: list[KnowledgeRecord],  # dari RAG
        count: int = 10,
    ) -> list[Payload]:
        """
        Generate payloads berdasarkan context dan knowledge.
        
        Contoh:
        - context: {tech: "rails", vuln: "IDOR", param: "user_id", value: "123"}
        - knowledge: [records dengan IDOR Rails patterns]
        - output: ["124", "0", "-1", "abc", "1.0", ...]
        """
        ...

class PayloadContext(BaseModel):
    vuln_class: VulnClass
    tech_stack: list[str]
    target_url: str
    parameter_name: str
    parameter_value: str       # nilai asli
    parameter_position: Literal["path", "query", "body", "header", "cookie"]
    http_method: str
    additional_context: str = ""
```

**Integrasi ke UI:**  
Di Finding detail dan Knowledge Browser, tambahkan tombol **"Generate Payloads"** yang:
1. Ambil context dari finding/endpoint yang sedang dilihat
2. Query knowledge base untuk similar patterns
3. Tampilkan daftar payload yang di-generate LLM
4. User bisa copy-paste atau langsung send ke Burp Repeater via MCP

---

### Task 3.2 — Continuous Monitoring + Delta Detection

```python
# apps/worker/tasks/monitoring.py

class MonitoringTask:
    """
    Scheduled scan untuk track perubahan target dari waktu ke waktu.
    Jalankan setiap hari/minggu sesuai konfigurasi per engagement.
    """
    
    async def run_delta_scan(self, engagement_id: str):
        """
        1. Ambil engagement dan target dari DB
        2. Jalankan recon ringan (subfinder + httpx saja)
        3. Compare dengan hasil sebelumnya (stored di DB)
        4. Jika ada delta (new subdomain, new port, new endpoint):
           → Simpan ke DB sebagai MonitoringAlert
           → Kirim notifikasi ke user (Slack/Telegram/email)
           → Otomatis queue vuln scan pada target baru
        """
        ...
    
    async def detect_delta(
        self,
        previous: ReconSnapshot,
        current: ReconSnapshot,
    ) -> DeltaReport:
        """
        Compare dua snapshot recon.
        Return: new_subdomains, removed_subdomains, new_ports, new_endpoints
        """
        ...
```

**Simpan ReconSnapshot ke DB:**

```python
# apps/api/app/models/monitoring.py

class ReconSnapshot(Base):
    __tablename__ = "recon_snapshots"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    engagement_id: Mapped[UUID] = mapped_column(ForeignKey("engagements.id"))
    snapshot_at: Mapped[datetime] = mapped_column(default=func.now())
    subdomains: Mapped[list] = mapped_column(JSONB)
    open_ports: Mapped[list] = mapped_column(JSONB)
    tech_stack: Mapped[list] = mapped_column(JSONB)

class MonitoringAlert(Base):
    __tablename__ = "monitoring_alerts"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    engagement_id: Mapped[UUID] = mapped_column(ForeignKey("engagements.id"))
    alert_type: Mapped[str]   # "new_subdomain", "new_port", "new_endpoint"
    detail: Mapped[dict] = mapped_column(JSONB)
    is_read: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
```

---

### Task 3.3 — Notifications (Slack + Telegram)

```python
# apps/worker/tasks/notifications.py

class NotificationService:
    """
    Kirim notifikasi ke channel yang dikonfigurasi user.
    Trigger: new finding, monitoring alert, engagement selesai, HITL waiting.
    """
    
    async def send_slack(self, webhook_url: str, message: NotificationMessage):
        payload = {
            "text": f"*Pentra AI* — {message.title}",
            "attachments": [{
                "color": SEVERITY_COLOR[message.severity],
                "fields": [
                    {"title": "Engagement", "value": message.engagement_name, "short": True},
                    {"title": "Finding", "value": message.finding_title, "short": True},
                    {"title": "Severity", "value": message.severity.upper(), "short": True},
                    {"title": "URL", "value": message.target_url, "short": False},
                ]
            }]
        }
        async with httpx.AsyncClient() as client:
            await client.post(webhook_url, json=payload)
    
    async def send_telegram(self, bot_token: str, chat_id: str, message: NotificationMessage):
        text = (
            f"🔴 *Pentra AI Alert*\n\n"
            f"*{message.title}*\n"
            f"Severity: `{message.severity.upper()}`\n"
            f"Target: `{message.target_url}`\n"
            f"Engagement: {message.engagement_name}"
        )
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        async with httpx.AsyncClient() as client:
            await client.post(url, json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown"
            })
```

**Update Settings UI:**

```typescript
// apps/web/src/pages/Settings.tsx — tambahkan section Notifications:
// - Slack Webhook URL (input + test button)
// - Telegram Bot Token + Chat ID (input + test button)
// - Notification triggers checkboxes:
//   ☑ New finding (High/Critical only)
//   ☑ New finding (semua severity)
//   ☑ Monitoring alert (new subdomain/endpoint)
//   ☑ Engagement selesai
//   ☑ Agent menunggu approval (HITL)
```

---

### Task 3.4 — API Rate Limiting Middleware

```python
# apps/api/app/core/middleware/rate_limit.py

from fastapi import Request, HTTPException
import redis.asyncio as redis

class RateLimitMiddleware:
    """
    Sliding window rate limiter per user ID.
    Limit berbeda per endpoint category.
    """
    
    LIMITS = {
        "/api/v1/engagements": {"requests": 100, "window": 3600},  # 100/jam
        "/api/v1/knowledge/search": {"requests": 200, "window": 3600},  # 200/jam
        "/api/v1/auth": {"requests": 20, "window": 3600},  # 20/jam (brute force protection)
    }
    
    async def __call__(self, request: Request, call_next):
        # Extract user dari JWT (jika ada)
        # Check rate limit di Redis
        # Return 429 jika melebihi limit
        ...

# apps/api/app/main.py — tambahkan:
app.add_middleware(RateLimitMiddleware)
```

---

### Task 3.5 — Update Tests

Setelah semua Sprint 1–3 selesai, tambahkan tests:

```
packages/pentra-tools/tests/
├── test_scope_enforcer.py     ← Sudah ada (22 tests)
├── test_wrappers.py           ← Sudah ada (10 tests)
├── test_amass_wrapper.py      ← BARU
├── test_katana_wrapper.py     ← BARU
├── test_ffuf_wrapper.py       ← BARU
├── test_dalfox_wrapper.py     ← BARU
└── test_sqlmap_wrapper.py     ← BARU

packages/pentra-knowledge/tests/
├── test_search.py             ← Sudah ada (jika ada)
└── test_from_finding.py       ← BARU (test convert finding → knowledge)

apps/api/tests/
├── test_auth.py               ← Sudah ada (jika ada)
├── test_workspace_isolation.py ← BARU
└── test_rate_limit.py         ← BARU
```

**Target setelah Phase 2 selesai:** minimum 50 tests, semua pass.

---

## Checklist Akhir Phase 2

Sebelum declare Phase 2 complete, pastikan semua ini terpenuhi:

```
Sprint 1
[ ] Burp MCP health_check() return True dengan Burp Pro aktif
[ ] get_proxy_history() return list ProxyEntry yang valid
[ ] trigger_active_scan() mengembalikan scan_id yang bisa di-poll
[ ] generate_collaborator_payload() return payload dengan domain oastify.com
[ ] Agentic mode berjalan tanpa pause kecuali di hitl_exploit_review
[ ] Screenshot capture menyimpan file PNG ke MinIO
[ ] Evidence path tersimpan di Finding.screenshot_path
[ ] Qdrant indexing mencapai minimal 10.000 records
[ ] Celery Beat schedule berjalan (h1-scraper + rss-ingestion)

Sprint 2
[ ] AmassWrapper — scope check, parse output, test pass
[ ] KatanaWrapper — scope check, JS crawl, test pass
[ ] FfufWrapper — scope check, wordlist, filter status, test pass
[ ] DalfoxWrapper — scope check, blind XSS support, test pass
[ ] SqlmapWrapper — scope check, IS_DESTRUCTIVE=True, test pass
[ ] Submit Finding ke Knowledge Base — finding terindex di Qdrant
[ ] Workspace isolation — user B tidak bisa lihat workspace user A
[ ] KB inject via URL — fetch, parse, index berhasil
[ ] KB inject via file upload — PDF dan Markdown berhasil diparse

Sprint 3
[ ] PayloadGenerator menghasilkan 10 payload kontekstual per request
[ ] MonitoringTask menyimpan ReconSnapshot ke DB
[ ] Delta detection identify new_subdomain dengan benar
[ ] Slack notification terkirim saat new finding
[ ] Telegram notification terkirim saat new finding
[ ] Rate limiter return 429 setelah limit tercapai
[ ] Total tests: minimal 50, semua pass

Security Compliance (re-check setelah semua selesai)
[ ] Semua wrapper baru punya scope.validate_or_raise() di baris pertama
[ ] SqlmapWrapper tidak bisa dipanggil tanpa HITL approval (IS_DESTRUCTIVE=True)
[ ] Tidak ada hardcoded credentials atau secrets
[ ] Semua API endpoints baru require JWT authentication
[ ] Audit log mencatat semua agent actions baru
```

---

## Cara Memulai

Buka Copilot Chat di VS Code dan mulai dengan prompt ini:

```
Baca CLAUDE.md, docs/PRD.md, dan PROGRESS.md secara lengkap.
Kemudian baca PHASE-2-EXECUTION.md.

Kita akan mulai Sprint 1, Task 1.1 — Burp Suite MCP End-to-End Integration.

Review kode yang sudah ada di packages/pentra-tools/burp/client.py,
identifikasi apa yang perlu diperbaiki atau ditambahkan,
lalu implementasikan semua method yang dijelaskan di Task 1.1.
Mulai dari health_check() dan get_proxy_history() dulu.
```

---

*Phase 2 Execution Plan — Pentra AI*  
*Dibuat berdasarkan gap analysis dari PROGRESS.md vs PRD v0.2*
