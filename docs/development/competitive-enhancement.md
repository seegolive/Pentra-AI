# COMPETITIVE-ENHANCEMENT.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `PROGRESS.md` → file ini  
> **Tujuan:** Adopsi keunggulan dari PentAGI, HexStrike AI, dan ekosistem OSS  
> **Tanggal riset:** 3 Juni 2026

---

## Posisi Pentra AI dalam Ekosistem 2026

```
                  LOCAL LLM + PRIVACY-FIRST
                           ↑
                   Pentra AI ●  ← UNIK
                    Burp Pro MCP + H1 RAG + HITL
                        /        \
           HexStrike AI            PentAGI
           (MCP-only,              (Cloud-first,
            no local LLM)          13 agents,
                                   Go backend)
                        \        /
                    CLOUD LLM DEPENDENT
```

**Keunggulan defensible Pentra AI yang tidak dimiliki tools lain:**
1. Local LLM inference — data tidak keluar mesin
2. Burp Suite Pro MCP terintegrasi sebagai first-class citizen
3. Knowledge base dari H1 real disclosures (RAG-powered)
4. Human-in-the-loop yang stateful dan resumable (LangGraph)
5. Self-learning dari confirmed findings

**Gap yang perlu ditutup (dari analisis PentAGI + HexStrike):**

---

## Analisis per Tools

---

### PentAGI — Keunggulan yang Harus Diadopsi

#### 1. Knowledge Graph (Graphiti-style) — P1

PentAGI menyimpan **relasi** antar entitas: tool ↔ target ↔ vulnerability ↔ technique.  
Pentra AI hanya punya flat vector similarity search — tidak bisa jawab pertanyaan seperti:
- "Tool apa yang berhasil di target dengan ASP.NET stack sebelumnya?"
- "Technique mana yang paling sering menghasilkan HIGH finding?"
- "Parameter apa yang pernah injectable di endpoint pattern /products?id=?"

**Implementasi yang disarankan:**

```python
# packages/pentra-knowledge/pentra_knowledge/graph/
# Tidak perlu Graphiti penuh — PostgreSQL dengan relasi sudah cukup untuk tahap awal

class EngagementLearning(Base):
    """
    Learning record dari setiap engagement — disimpan setelah selesai.
    Diquery oleh agent sebelum mulai engagement baru di target serupa.
    """
    __tablename__ = "engagement_learnings"

    id: Mapped[UUID]
    engagement_id: Mapped[UUID]

    # Target context
    tech_stack: Mapped[list] = mapped_column(JSONB)
    target_pattern: Mapped[str]  # e.g., "ASP.NET + IIS + MSSQL"

    # What worked
    effective_tools: Mapped[list] = mapped_column(JSONB)
    # e.g., [{"tool": "nuclei", "tags": ["sqli"], "findings": 3}]

    effective_techniques: Mapped[list] = mapped_column(JSONB)
    # e.g., [{"technique": "HTTPS→HTTP fallback", "impact": "unblocked 30 findings"}]

    # What didn't work
    failed_tools: Mapped[list] = mapped_column(JSONB)
    failed_techniques: Mapped[list] = mapped_column(JSONB)

    # Interesting endpoints
    high_value_endpoints: Mapped[list] = mapped_column(JSONB)
    # e.g., [{"pattern": "/products?cat=", "vuln": "SQLi", "confirmed": true}]

    # Timing
    created_at: Mapped[datetime]
    engagement_duration_minutes: Mapped[int | None]
    findings_count: Mapped[int]
    high_critical_count: Mapped[int]
```

**Query di agent:**

```python
# packages/pentra-agent/pentra_agent/nodes/plan_node.py
# Sebelum generate plan, query learnings dari engagement serupa:

async def query_similar_learnings(tech_stack: list[str], db) -> list[EngagementLearning]:
    """
    Cari engagement sebelumnya dengan tech stack serupa.
    Return: effective tools + techniques + high-value endpoints.
    """
    # Simple overlap scoring — tidak perlu vector
    result = await db.execute(
        select(EngagementLearning)
        .where(
            # PostgreSQL JSON overlap
            EngagementLearning.tech_stack.op("&&")(
                cast(tech_stack, JSONB)
            )
        )
        .order_by(EngagementLearning.high_critical_count.desc())
        .limit(5)
    )
    return result.scalars().all()

# Gunakan di plan_node untuk enrich LLM context:
# "Dari 3 engagement sebelumnya dengan ASP.NET + MSSQL:
#  - nuclei sqli templates menghasilkan 8 findings
#  - /products?cat= adalah parameter SQLi yang paling produktif
#  - HTTPS→HTTP fallback wajib di target ini"
```

#### 2. Isolated Execution (Container per Engagement) — P2

PentAGI menjalankan setiap tool eksekusi di container Docker terisolasi.  
Manfaat: tidak ada kontaminasi antar engagement, OPSEC yang lebih baik, clean environment.

**Implementasi minimal (tanpa full container orchestration):**

```python
# packages/pentra-tools/pentra_tools/base.py
# Tambahkan environment isolation via process namespace:

class AsyncToolWrapper:
    async def _exec_isolated(
        self,
        cmd: list[str],
        timeout: int = 300,
        env_override: dict | None = None,
    ) -> tuple[str, str, int]:
        """
        Jalankan tool dalam environment yang terisolasi.
        - Clean environment (hanya PATH yang diperlukan)
        - Timeout enforcement
        - Resource limit via ulimit
        """
        # Clean environment — tidak inherit semua env var dari parent
        clean_env = {
            "PATH": "/home/mdilab/go/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin",
            "HOME": "/tmp",
        }
        if env_override:
            clean_env.update(env_override)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=clean_env,
            cwd="/tmp",  # Isolated working dir
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
            return stdout.decode(), stderr.decode(), process.returncode
        except asyncio.TimeoutError:
            process.kill()
            raise ToolTimeoutError(f"{cmd[0]} timed out after {timeout}s")
```

#### 3. Chain Summarization — P2

PentAGI auto-summarize conversation chains saat context panjang.  
Problem Pentra AI saat ini: engagement panjang (50+ HITL cycles) bisa menyebabkan LLM context overflow.

```python
# packages/pentra-agent/pentra_agent/llm/summarizer.py

class ChainSummarizer:
    """
    Compress message history saat mendekati context limit.
    Pertahankan: key findings, scope, current hypothesis.
    Compress: tool outputs yang verbose.
    """
    SUMMARIZE_THRESHOLD = 50  # messages

    async def maybe_summarize(
        self,
        messages: list[AnyMessage],
        llm: LLMClient,
    ) -> list[AnyMessage]:
        if len(messages) < self.SUMMARIZE_THRESHOLD:
            return messages

        # Ambil 10 pesan terakhir (tetap verbatim)
        recent = messages[-10:]
        older = messages[:-10]

        # Summarize yang lama
        summary_text = await llm.complete(
            system=(
                "You are summarizing a penetration testing session. "
                "Preserve ALL findings, confirmed vulnerabilities, and key decisions. "
                "Compress tool output details. Be concise but complete."
            ),
            user="\n".join(m.content for m in older if hasattr(m, "content")),
        )

        # Ganti dengan summary
        summary_msg = SystemMessage(
            content=f"[COMPRESSED SESSION HISTORY]\n{summary_text}"
        )
        return [summary_msg] + recent
```

#### 4. Searcher Agent (OSINT) — P1

PentAGI punya dedicated **Searcher agent** yang melakukan OSINT dan threat intelligence sebelum engagement dimulai.  
Pentra AI tidak punya layer OSINT yang terstruktur.

```python
# packages/pentra-agent/pentra_agent/nodes/osint_node.py

async def osint_node(state: PentraState) -> dict:
    """
    OSINT phase sebelum recon teknis.
    Cari: teknologi yang digunakan, CVE terkait, breach data, pasive recon.
    """
    domain = state["target"]["domain"]

    results = {}

    # 1. Technology fingerprint via passive sources
    # Shodan, Censys, SecurityTrails (jika ada API key)

    # 2. CVE lookup untuk tech stack yang sudah diketahui
    # dari knowledge base kita sendiri

    # 3. H1 program lookup
    # Apakah domain ini punya bug bounty program?
    # Scope apa saja yang diizinkan?

    # 4. Breach data check (HaveIBeenPwned API)
    # Apakah ada email/credential yang sudah bocor?

    # 5. Certificate transparency (crt.sh)
    # Subdomain discovery via cert logs

    return {
        "osint_results": results,
        "messages": [AIMessage(content=f"OSINT complete for {domain}")]
    }
```

---

### HexStrike AI — Keunggulan yang Harus Diadopsi

#### 5. TechnologyDetector + Tech-Aware Parameter Candidates — P1 (SUDAH SEBAGIAN ADA)

Progress report menunjukkan ini sudah diimplementasikan sebagian di `_get_tech_default_candidates()`.  
Perlu **diperluas** dengan lebih banyak tech stack:

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Perluas _get_tech_default_candidates():

TECH_PARAM_CANDIDATES = {
    # Web Frameworks
    "asp.net":      ["id", "cat", "search", "page", "sort", "order", "filter",
                     "__VIEWSTATE", "__EVENTVALIDATION", "username", "password",
                     "ReturnUrl", "returnUrl", "redirect", "url", "next"],
    "rails":        ["id", "user_id", "account_id", "token", "utf8", "_method",
                     "authenticity_token", "q", "search", "page", "per_page",
                     "scope", "format", "callback"],
    "django":       ["id", "pk", "csrfmiddlewaretoken", "q", "search", "page",
                     "next", "redirect_to", "format", "username", "password",
                     "email", "token", "key"],
    "laravel":      ["id", "_token", "page", "search", "q", "sort", "order",
                     "direction", "filter", "username", "password", "email",
                     "redirect", "intended", "token"],
    "spring":       ["id", "userId", "accountId", "token", "page", "size",
                     "sort", "direction", "q", "search", "filter", "format"],
    "express":      ["id", "_id", "userId", "token", "q", "search", "page",
                     "limit", "offset", "sort", "order", "filter", "callback"],

    # Databases (hint dari port scan)
    "mysql":        ["id", "user_id", "order_id", "product_id", "cat"],
    "mssql":        ["id", "cat", "productid", "categoryid", "articleid"],
    "postgresql":   ["id", "user_id", "account_id", "record_id"],

    # CMS
    "wordpress":    ["p", "page_id", "cat", "tag", "author", "s", "attachment_id",
                     "wpnonce", "_wpnonce", "action", "post", "name"],
    "drupal":       ["nid", "uid", "tid", "fid", "vid", "q", "destination"],
    "joomla":       ["id", "catid", "option", "view", "layout", "task", "token"],

    # API Patterns
    "graphql":      ["query", "variables", "operationName"],
    "rest-api":     ["id", "userId", "accountId", "limit", "offset", "page",
                     "sort", "filter", "fields", "include", "expand"],

    # Cloud
    "aws":          ["bucket", "key", "prefix", "region", "token"],
}

def _get_tech_default_candidates(tech_stack: list[str]) -> list[str]:
    """Return parameter candidates berdasarkan detected tech stack."""
    candidates = set()
    candidates.update(["id", "q", "search", "page", "token"])  # universal baseline

    for tech in tech_stack:
        tech_lower = tech.lower()
        for key, params in TECH_PARAM_CANDIDATES.items():
            if key in tech_lower:
                candidates.update(params)

    return list(candidates)
```

#### 6. RateLimitDetector — P2

HexStrike punya dedicated agent untuk deteksi rate limiting.  
Pentra AI saat ini tidak deteksi rate limit sebelum fuzzing — bisa trigger block atau inaccurate results.

```python
# packages/pentra-tools/pentra_tools/recon/rate_limit_detector.py

class RateLimitDetector:
    """
    Deteksi rate limiting sebelum mulai fuzzing/scanning intensif.
    Cek: response time variance, 429 response, X-RateLimit headers.
    """

    async def probe(self, url: str) -> RateLimitResult:
        """
        Kirim 5 request cepat, analisis response patterns.
        Return: is_rate_limited, requests_per_minute_safe, retry_after
        """
        import time
        responses = []

        async with httpx.AsyncClient(timeout=10) as client:
            for i in range(5):
                start = time.monotonic()
                try:
                    r = await client.get(url)
                    elapsed = time.monotonic() - start
                    responses.append({
                        "status": r.status_code,
                        "elapsed": elapsed,
                        "retry_after": r.headers.get("Retry-After"),
                        "x_rate_limit": r.headers.get("X-RateLimit-Remaining"),
                        "ratelimit_remaining": r.headers.get("RateLimit-Remaining"),
                    })
                except Exception:
                    responses.append({"status": 0, "elapsed": 0})
                await asyncio.sleep(0.2)  # 200ms antara probe

        # Analisis
        statuses = [r["status"] for r in responses]
        has_429 = 429 in statuses
        has_ratelimit_headers = any(
            r.get("x_rate_limit") or r.get("ratelimit_remaining")
            for r in responses
        )

        # Timing variance (server-side throttling)
        elapsed_times = [r["elapsed"] for r in responses if r.get("elapsed", 0) > 0]
        time_variance = max(elapsed_times) / min(elapsed_times) if min(elapsed_times) > 0 else 1

        return RateLimitResult(
            is_rate_limited=has_429,
            has_ratelimit_headers=has_ratelimit_headers,
            timing_variance=time_variance,
            recommended_delay_ms=500 if has_429 else (200 if has_ratelimit_headers else 0),
            safe_rps=2 if has_429 else (5 if has_ratelimit_headers else 20),
        )
```

**Integrasi ke recon_node sebelum ffuf/subfinder:**

```python
# packages/pentra-agent/pentra_agent/nodes/recon_node.py
# Tambahkan setelah httpx probe, sebelum ffuf:

rate_limit = await RateLimitDetector().probe(f"http://{domain}/")
if rate_limit.is_rate_limited:
    logger.warning("[recon] Rate limiting detected — reducing tool speed")
    ffuf_rate = 10    # sangat lambat
    nuclei_rate = 5
else:
    ffuf_rate = 100   # default
    nuclei_rate = 50
```

#### 7. VulnerabilityCorrelator — P2

HexStrike punya agent yang menghubungkan findings satu sama lain untuk suggest attack chains.  
Pentra AI menyimpan findings secara isolated — tidak ada correlation logic.

```python
# packages/pentra-agent/pentra_agent/nodes/report_node.py
# Tambahkan setelah collect findings, sebelum persist:

async def correlate_findings(
    findings: list[dict],
    llm: LLMClient,
    knowledge_context: list[dict],
) -> list[dict]:
    """
    Analisis findings untuk identifikasi potential attack chains.
    Contoh: SSRF + Internal service discovery = RCE potential
            XSS + CSRF token exposure = Account takeover
            IDOR + PII exposure = Critical data breach
    """
    if len(findings) < 2:
        return findings  # Tidak ada yang bisa dikorelasikan

    correlation_prompt = f"""
Analyze these security findings and identify potential attack chains.
For each chain: describe the combined impact, which findings to chain, and severity upgrade.

Findings:
{json.dumps([{"title": f["title"], "vuln_class": f.get("vuln_class"), "url": f.get("target_url")} for f in findings], indent=2)}

Known patterns from similar engagements:
{json.dumps([k.get("chained_with", []) for k in knowledge_context[:5]], indent=2)}

Return JSON: list of {{ "chain": [finding_titles], "combined_impact": str, "upgraded_severity": str }}
"""

    chains = await llm.complete_json(
        system="You are a senior penetration tester identifying attack chains.",
        user=correlation_prompt,
    )

    # Attach chain info ke findings yang relevan
    for chain in (chains if isinstance(chains, list) else []):
        for finding in findings:
            if finding.get("title") in chain.get("chain", []):
                finding["chain_info"] = chain

    return findings
```

---

### awesome-ai-security Ecosystem — Teknik Terbaik

#### 8. ReAct Reasoning yang Eksplisit — P1

Dari riset ekosistem, tools terbaik seperti PentAGI dan Pentest Swarm AI menggunakan **ReAct (Reason-Act) loop yang eksplisit** — LLM harus verbalize reasoning sebelum mengambil action.

Pentra AI saat ini: LLM langsung suggest action tanpa intermediate reasoning step yang tertulis.

```python
# packages/pentra-agent/pentra_agent/llm/client.py
# Tambahkan method react_step():

async def react_step(
    self,
    observation: str,
    available_actions: list[str],
    history: list[dict],
) -> ReActOutput:
    """
    Implementasi ReAct: Thought → Action → Observation loop.
    LLM harus tulis thought sebelum action — meningkatkan accuracy.
    """
    system = """You are a penetration tester using ReAct (Reason+Act) framework.

For each step, you MUST output in this exact format:
Thought: [Your analysis of the current situation]
Action: [ONE action from the available list]
Action Input: [Parameters for the action as JSON]

Available actions: {actions}

Never skip the Thought step. Base every Action on explicit reasoning.""".format(
        actions=", ".join(available_actions)
    )

    user = f"""Current observation:
{observation}

History (last 5 steps):
{json.dumps(history[-5:], indent=2)}

What is your next step?"""

    raw = await self.complete(system, user)

    # Parse Thought/Action/Action Input
    return parse_react_output(raw)


def parse_react_output(raw: str) -> ReActOutput:
    """Parse ReAct format output dari LLM."""
    thought = ""
    action = ""
    action_input = {}

    for line in raw.splitlines():
        if line.startswith("Thought:"):
            thought = line.replace("Thought:", "").strip()
        elif line.startswith("Action:"):
            action = line.replace("Action:", "").strip()
        elif line.startswith("Action Input:"):
            try:
                action_input = json.loads(line.replace("Action Input:", "").strip())
            except json.JSONDecodeError:
                action_input = {"raw": line.replace("Action Input:", "").strip()}

    return ReActOutput(thought=thought, action=action, action_input=action_input)
```

#### 9. Attack Playbooks — P2

Dari riset ekosistem: PentestAgent punya **prebuilt attack playbooks** — urutan langkah yang sudah terbukti untuk skenario tertentu.

```python
# packages/pentra-agent/pentra_agent/playbooks/

# Contoh playbook: SQL Injection Discovery
SQLI_PLAYBOOK = {
    "name": "SQL Injection Discovery",
    "trigger": "Parameter dengan nilai numerik atau string di URL/body",
    "steps": [
        {"action": "baseline_request", "description": "Ambil response normal"},
        {"action": "error_based_probe", "payload": "'", "detect": "syntax error"},
        {"action": "boolean_probe", "payload": "' OR '1'='1", "detect": "response change"},
        {"action": "time_based_probe", "payload": "'; WAITFOR DELAY '0:0:5'--", "detect": "delay"},
        {"action": "confirm_with_burp", "description": "Send to Burp Repeater untuk manual verification"},
    ],
    "tech_stack_hints": ["mssql", "mysql", "postgresql", "asp.net"],
}

# XSS Playbook
XSS_PLAYBOOK = {
    "name": "XSS Discovery",
    "trigger": "Input yang direfleksikan di response",
    "steps": [
        {"action": "reflection_probe", "payload": "PENTRA_MARKER_12345"},
        {"action": "html_injection", "payload": "<b>PENTRA</b>"},
        {"action": "script_injection", "payload": "<script>alert(1)</script>"},
        {"action": "csp_check", "description": "Cek Content-Security-Policy header"},
        {"action": "dom_xss_check", "description": "Analisis JavaScript untuk DOM sources/sinks"},
    ],
    "tech_stack_hints": ["react", "angular", "vue", "jquery"],
}

# Playbook registry
PLAYBOOKS = {
    "sqli": SQLI_PLAYBOOK,
    "xss": XSS_PLAYBOOK,
    # ... tambah lebih banyak
}
```

#### 10. CVSS v3.1 Auto-scoring — P1

Dari riset: Pentest Swarm AI punya CVSS v3.1 scoring otomatis.  
Pentra AI punya `cvss_score` field tapi diisi LLM tanpa vector string yang valid.

```python
# packages/pentra-shared/pentra_shared/utils/cvss.py

"""
CVSS v3.1 auto-calculator berdasarkan vuln_class dan context.
Menghasilkan score DAN vector string yang valid untuk report.
"""

CVSS_BASE_SCORES = {
    # (vuln_class, auth_required, network_accessible) → (score, vector)
    ("SQL_INJECTION", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("SQL_INJECTION", True, True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    ("XSS", False, True): (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("IDOR", True, True): (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    ("SSRF", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("PATH_TRAVERSAL", False, True): (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("COMMAND_INJECTION", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("SSTI", False, True): (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("OPEN_REDIRECT", False, True): (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
}

def calculate_cvss(
    vuln_class: str,
    auth_required: bool = True,
    network_accessible: bool = True,
) -> tuple[float, str]:
    """
    Return (score, vector_string) berdasarkan vuln class dan context.
    """
    key = (vuln_class.upper(), auth_required, network_accessible)
    return CVSS_BASE_SCORES.get(key, (5.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"))
```

---

## Apa yang Pentra AI Sudah Unggul

Berdasarkan analisis ekosistem, Pentra AI **sudah lebih baik** dari semua referensi dalam hal:

| Aspek | Pentra AI | PentAGI | HexStrike |
|-------|-----------|---------|-----------|
| Local LLM privacy | ✅ First-class | ❌ Cloud-first | ❌ External AI |
| Burp Pro integration | ✅ MCP + 27 tools | ❌ Tidak ada | Partial |
| H1 Knowledge RAG | ✅ BGE-M3 + Qdrant | ❌ Tidak ada | ❌ Tidak ada |
| HITL stateful/resumable | ✅ LangGraph checkpoint | Partial | ❌ Tidak ada |
| Self-learning dari findings | ✅ KB pipeline | ❌ Tidak ada | ❌ Tidak ada |
| Bug bounty H1 format | ✅ Auto-format | ❌ | ❌ |
| HTTPS→HTTP fallback | ✅ Fix sudah ada | ❓ | ❓ |
| OPSEC mode + jitter | ✅ Ada | ❌ | ❌ |
| Web UI | ✅ React full UI | ✅ React | ❌ CLI only |

---

## Roadmap Implementasi

### Sprint 14 — Intelligence Upgrade (P1 items)

**Task 14.1 — EngagementLearning table + query di plan_node**
- Buat model `EngagementLearnings`
- Setelah engagement selesai, auto-save learning ke DB
- Query di `plan_node` untuk contextualize plan dengan history

**Task 14.2 — ReAct reasoning loop yang eksplisit**
- Tambah `LLMClient.react_step()` method
- Update `vuln_hunt_node` untuk pakai ReAct sebelum setiap injection test
- Log Thought setiap step untuk audit trail dan debugging

**Task 14.3 — CVSS v3.1 auto-calculator**
- Buat `pentra_shared/utils/cvss.py`
- Integrasi ke `report_node.py` — setiap finding dapat valid CVSS vector
- Update `FindingsTable.tsx` untuk tampilkan CVSS vector string

**Task 14.4 — Tech-aware parameter candidates (expanded)**
- Perluas `TECH_PARAM_CANDIDATES` dict dengan semua tech stack
- Test dengan target ASP.NET, Rails, Django, Laravel, Spring, Express, WordPress
- Validate improvement di hit rate

### Sprint 15 — Architecture Upgrade (P2 items)

**Task 15.1 — RateLimitDetector**
- Buat wrapper di `pentra-tools`
- Integrasi ke recon_node sebelum ffuf/katana
- Adjust tool speed otomatis berdasarkan rate limit detection

**Task 15.2 — VulnerabilityCorrelator**
- Buat `correlate_findings()` di report_node
- LLM identify attack chains dari combined findings
- Tampilkan di FindingsTable sebagai "Chain" badge

**Task 15.3 — Attack Playbooks**
- Buat `packages/pentra-agent/pentra_agent/playbooks/`
- Start dengan: SQLi, XSS, IDOR, SSRF, Path Traversal
- Integrasi ke vuln_hunt_node sebagai structured test sequence

**Task 15.4 — Chain Summarization**
- Buat `ChainSummarizer` class
- Trigger otomatis saat messages > 50
- Preserve findings dan decisions, compress tool outputs

**Task 15.5 — OSINT Node**
- Buat `osint_node.py` sebelum `recon_node` dalam graph
- crt.sh untuk subdomain via certificate transparency
- H1 program lookup (apakah target punya bug bounty?)
- Passive tech fingerprint

---

## Prioritas Saat Ini

Berdasarkan progress report (E2E-v11 sedang berjalan dengan nuclei aktif), fokus sekarang:

```
IMMEDIATE (setelah E2E-v11 konfirmasi findings):
  1. EngagementLearning table — supaya v12 lebih pintar dari v11
  2. CVSS auto-calculator — findings perlu valid CVSS sebelum H1 submission
  3. ReAct loop di vuln_hunt — meningkatkan precision confirmed findings

SHORT-TERM (sprint 14-15):
  4. Tech-aware params expansion — lebih banyak hits di SQLi/XSS testing
  5. RateLimitDetector — prevent blocking saat engagement di real targets
  6. VulnerabilityCorrelator — nilai findings lebih tinggi via chaining

MEDIUM-TERM:
  7. OSINT node — context lebih kaya sebelum recon teknis
  8. Attack Playbooks — structured testing untuk common vuln classes
  9. Chain Summarizer — engagement panjang tanpa context overflow
```

---

## Prompt untuk Copilot

**Mulai Task 14.1 — EngagementLearning:**
```
Baca CLAUDE.md, PROGRESS.md, dan COMPETITIVE-ENHANCEMENT.md.

Kita mulai Task 14.1 — EngagementLearning table.

1. Buat SQLAlchemy model EngagementLearning di apps/api/app/db/models.py
   sesuai schema di Task 14.1 COMPETITIVE-ENHANCEMENT.md

2. Buat Alembic migration: uv run alembic revision --autogenerate -m "add_engagement_learnings"

3. Buat fungsi save_engagement_learning() di apps/api/app/services/
   — dipanggil di report_node setelah engagement selesai
   — record: effective_tools, effective_techniques, high_value_endpoints

4. Buat fungsi query_similar_learnings() di pentra-knowledge
   — dipanggil di plan_node sebelum generate plan
   — return: top 3 learnings dengan tech stack overlap

5. Update plan_node.py untuk include learnings di LLM context

Ikuti konvensi CLAUDE.md.
```

**Mulai Task 14.2 — ReAct loop:**
```
EngagementLearning selesai.
Sekarang Task 14.2 — tambahkan ReAct reasoning loop.

Buat LLMClient.react_step() sesuai COMPETITIVE-ENHANCEMENT.md Task 14.2.
Update _run_llm_burp_active_testing() di vuln_hunt_node.py untuk
gunakan react_step() sebelum setiap injection test.
Log "Thought:" ke audit_logs untuk observability.
```

**Mulai Task 14.3 — CVSS auto-calculator:**
```
Buat packages/pentra-shared/pentra_shared/utils/cvss.py
sesuai COMPETITIVE-ENHANCEMENT.md Task 14.3.
Integrasi ke report_node — setiap finding dapat valid CVSS score + vector.
Update FindingsTable.tsx untuk tampilkan CVSS vector string di expanded row.
```

---

*COMPETITIVE-ENHANCEMENT.md — Pentra AI*  
*Analisis: PentAGI (14.6K stars) + HexStrike AI (9K stars) + awesome-ai-security*  
*10 improvements dengan prioritas, siap dieksekusi*
