# CLAUDE-BUGHUNTER-ENHANCEMENT.md — Pentra AI
> **Referensi:** https://github.com/elementalsouls/Claude-BugHunter  
> **Status Pentra AI:** Sprint 1–15 ✅, 159 tests, 30/35 smoke test  
> **Tujuan:** Adopsi keunggulan Claude-BugHunter ke arsitektur Pentra AI

---

## Apa itu Claude-BugHunter?

**Claude-BugHunter** adalah skill bundle untuk Claude Code — 51 skills + 15 slash commands + **574+ disclosed report patterns** dari 24 vulnerability class. Bukan platform, tapi **knowledge + methodology layer** yang di-inject ke Claude Code sebagai context.

Pendekatan berbeda dari Pentra AI:
```
Claude-BugHunter:   Claude Code + skills → manual hunt, AI-assisted
Pentra AI:          Platform otomatis + LLM + tools + Burp + KB → full pipeline
```

Keduanya komplementer, bukan kompetitif. Yang terbaik dari BugHunter bisa diadopsi.

---

## Gap Analysis: BugHunter vs Pentra AI

### Yang BugHunter Punya, Pentra AI Belum

| # | BugHunter Feature | Detail | Priority |
|---|-------------------|--------|----------|
| **A** | **7-Question Triage Gate** | Validation framework sebelum filing — mencegah false positive | P1 |
| **B** | **574+ disclosed report patterns** | Per-class detection dari H1 reports yang dikurasi manual | P1 |
| **C** | **Developer Psychology Heuristics** | Bagaimana developer berpikir → di mana mereka biasa salah | P2 |
| **D** | **"DO NOT STOP" operator discipline** | Ketika agent menemukan 1 vuln, jangan stop — lanjut chain | P1 |
| **E** | **VRT mapping (Bugcrowd taxonomy)** | Auto-kategorisasi ke Bugcrowd VRT hierarchy | P3 |
| **F** | **Enterprise attack matrix** | M365/Entra, Okta, VMware vCenter, SSL VPN chains (2024-2026 CVE) | P2 |
| **G** | **mid-engagement-ir-detection** | Deteksi SOC/EDR response saat engagement berlangsung | P3 |
| **H** | **Anomaly detection patterns** | Identifikasi respons server yang "berbeda dari normal" | P2 |
| **I** | **Token scan + web3 audit** | Secret detection + Web3/blockchain vuln | P3 |
| **J** | **OOS rebuttals** | Template untuk argue scope ketika tim keamanan bilang "OOS" | P2 |

### Yang Pentra AI Punya, BugHunter Tidak

| Aspek | Pentra AI |
|-------|-----------|
| Full automation pipeline | Recon → Vuln Hunt → Report otomatis |
| Local LLM (privacy) | Data tidak keluar mesin |
| Burp Pro MCP integration | 27 tools, proxy history, Collaborator |
| Self-learning dari findings | EngagementLearning, KB update |
| Stateful HITL sessions | LangGraph checkpoint, resume |
| CVSS v3.1 auto-scoring | Valid vector string setiap finding |
| Attack chain correlation | VulnerabilityCorrelator |
| Structured playbooks | 5 playbooks dengan step sequences |

---

## Prioritas Adopsi

---

### Enhancement A — 7-Question Triage Gate (P1)

**Dari BugHunter `triage-validation` skill.**

BugHunter punya framework yang ketat sebelum submit bug:
1. *Can I reproduce it?*
2. *Is it in scope?*
3. *Is the impact real or theoretical?*
4. *Is this a known/informational issue?*
5. *Can I chain it to increase severity?*
6. *Do I have clean evidence?*
7. *Am I duplicating an existing report?*

Output dari gate: **PASS** / **DOWNGRADE** / **KILL** / **CHAIN REQUIRED**

**Pentra AI saat ini:** findings dari nuclei langsung masuk DB tanpa validation gate. Banyak findings adalah informational atau theoretical impact.

**Implementasi:**

```python
# packages/pentra-agent/pentra_agent/nodes/triage_node.py
"""
Triage Gate — LLM validate setiap finding sebelum persist ke DB.
Filter: false positive, informational, theoretical-only, duplicate.
Output per finding: PASS / DOWNGRADE / KILL / CHAIN_REQUIRED
"""

import logging
from pentra_agent.llm.client import LLMClient
from pentra_agent.graph.state import PentraState

logger = logging.getLogger(__name__)

TRIAGE_PROMPT = """You are a senior bug bounty validator applying strict triage criteria.

Evaluate this security finding using the 7-Question Gate:

1. REPRODUCIBLE: Can this be reproduced with the provided steps?
2. IN_SCOPE: Is the vulnerable URL/parameter within the engagement scope?
3. REAL_IMPACT: Is the impact real (not theoretical)? Can it affect real users/data?
4. NOVEL: Is this genuinely new? Not just a version disclosure or best-practice recommendation?
5. CHAINABLE: If low severity, can it chain with other findings to increase impact?
6. EVIDENCED: Is there request/response evidence that proves the finding?
7. NOT_DUPLICATE: Is this different from other findings in this engagement?

Finding to evaluate:
Title: {title}
Vuln Class: {vuln_class}
Severity: {severity}
URL: {target_url}
Description: {description}
Request evidence: {request_evidence}
Response evidence: {response_evidence}

Other findings in this engagement: {other_titles}

Return JSON:
{{
  "verdict": "PASS" | "DOWNGRADE" | "KILL" | "CHAIN_REQUIRED",
  "final_severity": "critical|high|medium|low|info",
  "reason": "one sentence explanation",
  "chain_suggestion": "if CHAIN_REQUIRED: what to chain with",
  "downgrade_reason": "if DOWNGRADE: why severity is lower"
}}"""


async def triage_node(state: PentraState) -> dict:
    """
    Triage gate — validate setiap finding sebelum persist.
    Berjalan setelah vuln_hunt_node, sebelum report_node.
    """
    findings = state.get("findings", [])
    if not findings:
        return {"findings": [], "messages": []}

    llm = LLMClient(
        base_url=_get_ollama_url(),
        model=state["llm_model"]
    )

    other_titles = [f.get("title", "") for f in findings]
    triaged = []
    killed = 0
    downgraded = 0

    for finding in findings:
        try:
            result = await llm.complete_json(
                system="You are a strict bug bounty validator. Return only valid JSON.",
                user=TRIAGE_PROMPT.format(
                    title=finding.get("title", ""),
                    vuln_class=finding.get("vuln_class", ""),
                    severity=finding.get("severity", ""),
                    target_url=finding.get("target_url", ""),
                    description=finding.get("description", "")[:500],
                    request_evidence=finding.get("request_raw", "")[:300],
                    response_evidence=finding.get("response_raw", "")[:300],
                    other_titles=str(other_titles[:10]),
                )
            )

            verdict = result.get("verdict", "PASS")
            finding["triage_verdict"] = verdict
            finding["triage_reason"] = result.get("reason", "")

            if verdict == "KILL":
                killed += 1
                logger.info(
                    "[triage] KILL: %s — %s",
                    finding.get("title"), result.get("reason")
                )
                continue  # Skip — tidak masuk DB

            if verdict == "DOWNGRADE":
                downgraded += 1
                old_sev = finding.get("severity")
                finding["severity"] = result.get("final_severity", old_sev)
                logger.info(
                    "[triage] DOWNGRADE: %s → %s — %s",
                    finding.get("title"), finding["severity"], result.get("reason")
                )

            if verdict == "CHAIN_REQUIRED":
                finding["chain_suggestion"] = result.get("chain_suggestion", "")
                logger.info(
                    "[triage] CHAIN_REQUIRED: %s — %s",
                    finding.get("title"), result.get("chain_suggestion")
                )

            triaged.append(finding)

        except Exception as e:
            logger.warning("[triage] LLM triage failed for %s: %s", finding.get("title"), e)
            triaged.append(finding)  # Fallback: keep finding

    from langchain_core.messages import AIMessage
    summary = (
        f"Triage complete: {len(triaged)} passed, "
        f"{killed} killed, {downgraded} downgraded."
    )
    logger.info("[triage] %s", summary)

    return {
        "findings": triaged,
        "messages": [AIMessage(content=summary)],
    }


def _get_ollama_url() -> str:
    import os
    return os.getenv("OLLAMA_URL", "http://localhost:11434") + "/v1"
```

**Update `builder.py` — tambahkan triage_node setelah vuln_hunt:**

```python
# packages/pentra-agent/pentra_agent/graph/builder.py

from pentra_agent.nodes.triage_node import triage_node

# Graph setelah update:
# osint → plan → hitl_plan → recon → hitl_recon
# → vuln_hunt → triage → hitl_exploit → report

graph.add_node("triage", triage_node)
graph.add_edge("vuln_hunt", "triage")
# Ubah conditional_edges dari vuln_hunt → triage
# Dan triage → hitl_exploit atau report
```

---

### Enhancement B — 574+ Disclosed Patterns ke KB Pipeline (P1)

**Dari BugHunter `hunt-*` skills — 24 vuln class patterns.**

BugHunter punya detection patterns yang dikurasi manual dari 574+ H1 reports, diorganisasi per vuln class:
- Exact payloads yang terbukti work
- Bypass tables (WAF bypass, encoding bypass)
- Chain templates (vuln A + vuln B → critical)

**Pentra AI sudah punya KB dari H1 reports, tapi perlu enrichment:**

```python
# scripts/import_bughunter_patterns.py
"""
Import detection patterns dari Claude-BugHunter skill files
ke Pentra AI knowledge base sebagai high-quality records.

Source: https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills
Skills yang relevan: hunt-sqli, hunt-xss, hunt-ssrf, hunt-idor, hunt-xxe,
hunt-csrf, hunt-jwt, hunt-oauth, hunt-graphql, hunt-rce, hunt-ssti, dll.
"""

BUGHUNTER_SKILL_URLS = [
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-sqli",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-xss",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-ssrf",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-idor",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-xxe",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-jwt",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-oauth",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-graphql",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-business-logic",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-race-conditions",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-ssti",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-http-smuggling",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-cache-poison",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-api-misconfig",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-file-upload",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-auth-bypass",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-pii-leak",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-llm-ai",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-ato",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-mfa-bypass",
    "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-saml",
]

async def import_skill_to_kb(skill_url: str):
    """
    Fetch skill content dari GitHub, parse detection patterns,
    inject ke Pentra AI KB sebagai high-quality curated records.
    """
    ...
```

---

### Enhancement C — "DO NOT STOP" Operator Discipline (P1)

**Dari BugHunter `redteam-mindset` skill.**

BugHunter punya "DO NOT STOP" directive: ketika menemukan 1 vulnerability, **jangan stop dan report** — lanjut hunt untuk chain yang lebih valuable.

**Pentra AI saat ini:** setelah `vuln_hunt_node` menemukan findings, agent langsung ke report_node. Tidak ada logika untuk "temukan lebih banyak" atau "chain findings".

**Implementasi — tambahkan continue-hunt logic:**

```python
# packages/pentra-agent/pentra_agent/graph/builder.py
# Tambahkan conditional routing setelah triage:

def route_after_triage(state: PentraState) -> str:
    """
    'DO NOT STOP' logic:
    - Jika ada CHAIN_REQUIRED findings → lanjut hunting dengan chain context
    - Jika semua findings sudah PASS/DOWNGRADE → ke hitl_exploit atau report
    - Jika terlalu banyak rounds sudah → force ke report
    """
    findings = state.get("findings", [])
    hunt_rounds = state.get("hunt_rounds", 0)

    # Prevent infinite loop
    if hunt_rounds >= 3:
        logger.info("[router] Max hunt rounds reached — forcing report")
        return "report"

    # Ada chain yang perlu di-explore
    chain_required = [f for f in findings if f.get("triage_verdict") == "CHAIN_REQUIRED"]
    if chain_required:
        logger.info(
            "[router] %d findings need chaining — continue hunt round %d",
            len(chain_required), hunt_rounds + 1
        )
        return "vuln_hunt"  # Loop kembali ke vuln_hunt dengan chain context

    # Normal flow
    high_value = [f for f in findings if f.get("severity") in ("critical", "high")]
    if high_value:
        return "hitl_exploit"
    return "report"
```

**Tambahkan `hunt_rounds` ke PentraState:**

```python
# packages/pentra-agent/pentra_agent/graph/state.py
hunt_rounds: int  # Counter untuk prevent infinite loop
```

---

### Enhancement D — Developer Psychology Heuristics (P2)

**Dari BugHunter `bug-bounty` skill — bagaimana developer berpikir.**

BugHunter punya heuristics tentang di mana developer biasa salah:
- "Developer trust input dari frontend lebih dari backend"
- "Authorization check di controller sering di-skip untuk API endpoints baru"
- "Copy-paste code sering membawa auth bypass dari versi lama"
- "v2 API endpoint sering dibuat terburu-buru, kurang tested"

**Implementasi — enrich LLM prompt di vuln_hunt:**

```python
# packages/pentra-agent/pentra_agent/llm/prompts/vuln_hunt_prompt.py

DEVELOPER_PSYCHOLOGY_HEURISTICS = """
## Developer Psychology — Where to Focus

Common developer mistakes that create vulnerabilities:

1. **API versioning mistakes**: v1 endpoints often have auth checks, v2 endpoints
   added quickly may skip authorization. Always test /api/v1/ vs /api/v2/ side by side.

2. **Frontend trust**: Developers trust frontend validation. Look for parameters
   that should be validated server-side but only have client-side checks.

3. **Copy-paste auth bypass**: New features copy old code. Check if deprecated/old
   auth patterns exist alongside new ones.

4. **Admin endpoints leaked**: Admin functionality at /admin/, /api/admin/, /internal/
   often has weaker auth checks because "it's internal".

5. **Debug/test endpoints**: /debug/, /test/, /health/ endpoints often expose more
   than intended.

6. **Integer ID assumption**: Numeric IDs in URLs are often IDOR candidates because
   developers assume users won't guess other IDs.

7. **Missing function-level auth**: Object-level auth present, but function-level
   (e.g., can view vs can edit) often missed.

8. **Error message verbosity**: Developers leave verbose errors in staging that
   somehow end up in production.
"""

# Inject ke system prompt di analyze_recon_results() dan vuln_hunt planning
```

---

### Enhancement E — Anomaly Detection Patterns (P2)

**Dari BugHunter — identifikasi respons yang "berbeda dari normal".**

BugHunter mengajarkan bahwa finding terbaik berasal dari memperhatikan hal-hal yang "aneh":
- Response lebih lambat dari biasanya → potential time-based injection
- Response lebih panjang dari biasanya → potential data disclosure
- Response code berbeda → potential auth bypass
- Response berisi data yang tidak seharusnya ada

**Implementasi — tambahkan anomaly detection ke baseline comparison:**

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Di _run_llm_burp_active_testing(), setelah baseline request:

def detect_anomalies(
    baseline_response: dict,
    injected_response: dict,
) -> list[str]:
    """
    Detect anomalies antara baseline dan injected response.
    Return list of anomaly descriptions.
    """
    anomalies = []

    # 1. Response time anomaly (potential time-based injection)
    time_ratio = injected_response.get("elapsed", 0) / max(baseline_response.get("elapsed", 1), 0.001)
    if time_ratio >= 3.0:  # 3x lebih lambat
        anomalies.append(
            f"TIME_ANOMALY: Response {time_ratio:.1f}x slower than baseline "
            f"({injected_response.get('elapsed', 0):.1f}s vs "
            f"{baseline_response.get('elapsed', 0):.1f}s) — potential time-based injection"
        )

    # 2. Response size anomaly (potential data disclosure or error)
    baseline_size = len(baseline_response.get("body", ""))
    injected_size = len(injected_response.get("body", ""))
    size_diff = abs(injected_size - baseline_size)
    if size_diff > 500 and size_diff / max(baseline_size, 1) > 0.3:
        direction = "larger" if injected_size > baseline_size else "smaller"
        anomalies.append(
            f"SIZE_ANOMALY: Response is {size_diff} bytes {direction} than baseline — "
            f"potential data disclosure or error message"
        )

    # 3. Status code change
    if baseline_response.get("status") != injected_response.get("status"):
        anomalies.append(
            f"STATUS_CHANGE: {baseline_response.get('status')} → "
            f"{injected_response.get('status')} — potential auth bypass or error"
        )

    # 4. Error keywords in response
    error_keywords = [
        "sql syntax", "mysql error", "ora-", "pg::", "sqlite",
        "traceback", "exception", "stack trace", "undefined",
        "null pointer", "cannot read property",
    ]
    injected_body_lower = injected_response.get("body", "").lower()
    found_errors = [kw for kw in error_keywords if kw in injected_body_lower]
    if found_errors:
        anomalies.append(
            f"ERROR_DISCLOSURE: Found '{found_errors[0]}' in response — "
            f"potential injection or debug info disclosure"
        )

    # 5. Reflection detected
    if "PENTRA_MARKER" in injected_response.get("body", ""):
        anomalies.append("REFLECTION: Input reflected in response — XSS candidate")

    return anomalies
```

---

### Enhancement F — Enterprise Attack Matrix (P2)

**Dari BugHunter: m365-entra-attack, okta-attack, enterprise-vpn-attack.**

BugHunter punya attack chains yang sangat specific untuk enterprise targets:
- M365/Entra ID: password spray patterns, AADSTS error codes, OAuth consent phishing
- Okta: SSO bypass, token pivoting, app-level auth bypass
- SSL VPN: Cisco ASA, Fortinet, Citinet, Palo Alto — specific CVE chains 2024-2026

**Pentra AI saat ini:** hanya cover web app vulnerabilities. Tidak ada enterprise attack surface.

**Implementasi — tambahkan enterprise attack node:**

```python
# packages/pentra-agent/pentra_agent/nodes/enterprise_recon_node.py
"""
Enterprise attack surface enumeration — opsional, aktif jika target terdeteksi
sebagai enterprise (M365, Okta, VPN, SharePoint).

Tech stack indicators:
- "Microsoft" → M365/SharePoint/Teams surface
- "Okta" → SSO/IAM surface  
- "Cisco ASA" / "Fortinet" / "Palo Alto" → VPN surface
- "VMware" → vCenter/Workspace ONE surface
"""

ENTERPRISE_INDICATORS = {
    "m365": ["Microsoft", "Azure", "O365", "Teams", "SharePoint", "Outlook Web"],
    "okta": ["Okta", "okta.com"],
    "cisco_vpn": ["Cisco ASA", "AnyConnect", "Cisco SSL"],
    "fortinet": ["Fortinet", "FortiGate", "FortiClient"],
    "palo_alto": ["Palo Alto", "GlobalProtect", "PAN-OS"],
    "vmware": ["VMware", "vCenter", "Workspace ONE", "vSphere"],
    "sharepoint": ["SharePoint", "/_layouts/", "/_vti_bin/"],
}

async def detect_enterprise_surface(tech_stack: list[str], endpoints: list[dict]) -> dict:
    """
    Deteksi enterprise attack surface dari tech stack dan endpoints.
    Return: dict of detected surfaces dan recommended attack vectors.
    """
    surfaces = {}

    tech_lower = " ".join(t.lower() for t in tech_stack)
    endpoint_urls = " ".join(e.get("url", "") for e in endpoints)

    for surface_name, indicators in ENTERPRISE_INDICATORS.items():
        if any(ind.lower() in tech_lower or ind.lower() in endpoint_urls.lower()
               for ind in indicators):
            surfaces[surface_name] = True

    return surfaces
```

---

### Enhancement G — Frontend Smoke Test Automation (dari BLOK 6)

Smoke test menunjukkan BLOK 6 (Frontend UI) belum ditest — `0/5`.
Ini adalah satu-satunya blok yang tersisa. Buat Playwright tests untuk cover manual tests yang tertunda:

```typescript
// apps/web/e2e/smoke-complete.spec.ts
// Cover ST-6.1 s/d ST-6.5 yang manual

import { test, expect } from "@playwright/test";

test.describe("ST-6.1 — Login Flow", () => {
  test("login valid redirect ke dashboard", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("Pentra@2026!");
    await page.getByRole("button", { name: "Sign In" }).click();
    await expect(page).toHaveURL("/");
    await expect(page.getByText("Dashboard")).toBeVisible();
  });

  test("login invalid tampilkan error", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("wrong");
    await page.getByRole("button", { name: "Sign In" }).click();
    await expect(page.getByText(/invalid/i)).toBeVisible();
  });
});

test.describe("ST-6.3 — FindingsTable", () => {
  test.beforeEach(async ({ page }) => {
    // Login
    await page.goto("/login");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("Pentra@2026!");
    await page.getByRole("button", { name: "Sign In" }).click();
    await page.waitForURL("/");
  });

  test("findings table renders dengan severity pills", async ({ page }) => {
    // Navigate ke engagement yang sudah punya findings
    await page.goto(`/engagements/${process.env.TEST_ENG_ID}`);
    await page.getByRole("tab", { name: "Findings" }).click();
    // Severity pills harus ada
    await expect(page.getByText(/critical|high|medium|low/i).first()).toBeVisible({
      timeout: 10_000,
    });
  });
});

test.describe("ST-6.5 — KB Browser", () => {
  test("KB search returns results", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("Pentra@2026!");
    await page.getByRole("button", { name: "Sign In" }).click();

    await page.goto("/knowledge");
    await page.getByPlaceholder(/search/i).fill("SQL injection");
    await page.getByRole("button", { name: /search/i }).click();

    await expect(
      page.locator("[data-testid='knowledge-result']").first()
    ).toBeVisible({ timeout: 10_000 });
  });
});
```

---

### Enhancement H — FindingsTable Attack Chains UI (Sprint 15.2 remaining)

Progress menunjukkan chains field sudah ada di DB tapi UI belum tampilkan.

```typescript
// apps/web/src/components/findings/FindingsTable.tsx
// Tambahkan di ExpandedDetail section:

{finding.chains && finding.chains.length > 0 && (
  <div>
    <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-2">
      ⛓️ Attack Chains
    </p>
    <div className="space-y-2">
      {finding.chains.map((chain: ChainInfo, i: number) => (
        <div
          key={i}
          className="bg-red-950/20 border border-red-900/30 rounded p-3 space-y-1"
        >
          <div className="flex items-center gap-2">
            <Badge
              variant="outline"
              className="text-xs border-red-800 text-red-400"
            >
              {chain.upgraded_severity?.toUpperCase()}
            </Badge>
            <span className="text-sm font-medium text-red-300">
              {chain.name}
            </span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            {chain.scenario}
          </p>
          {chain.business_impact && (
            <p className="text-xs text-red-400 mt-1">
              💥 {chain.business_impact}
            </p>
          )}
        </div>
      ))}
    </div>
  </div>
)}
```

---

## Roadmap Sprint 16

Berdasarkan analisis Claude-BugHunter, Sprint 16 fokus pada **quality over quantity**:

### Sprint 16 — Triage + Discipline + Quality

| Task | Enhancement | Estimasi | Impact |
|------|-------------|----------|--------|
| **16.1** | Triage Gate node (7-Question) | 3 jam | Eliminasi false positive sebelum persist |
| **16.2** | DO NOT STOP routing (chain loop) | 2 jam | Temukan chain sebelum report |
| **16.3** | FindingsTable Attack Chains UI | 1 jam | Tutup Sprint 15.2 yang tertunda |
| **16.4** | Anomaly Detection di baseline comparison | 2 jam | Better detection dari respons "aneh" |
| **16.5** | Developer Psychology dalam LLM prompt | 1 jam | Context lebih kaya untuk injection decisions |
| **16.6** | Frontend E2E tests (BLOK 6 smoke) | 2 jam | Tutup 5/35 smoke test yang tertunda |
| **16.7** | Import BugHunter patterns ke KB | 3 jam | 24 vuln class patterns dikurasi manual |
| **16.8** | E2E-v12 dengan stack baru | ongoing | Validasi semua Sprint 15-16 bekerja bersama |

---

## Checklist Sprint 16

```
Task 16.1 — Triage Gate Node
[ ] triage_node.py dibuat dengan 7-Question Gate prompt
[ ] builder.py: vuln_hunt → triage → hitl_exploit/report
[ ] KILL verdict → finding tidak masuk DB
[ ] DOWNGRADE verdict → severity di-update
[ ] CHAIN_REQUIRED verdict → chain_suggestion field terisi
[ ] 3 tests: PASS verdict, KILL verdict, DOWNGRADE verdict

Task 16.2 — DO NOT STOP Routing
[ ] hunt_rounds field di PentraState
[ ] route_after_triage() dengan DO NOT STOP logic
[ ] Max 3 rounds untuk prevent infinite loop
[ ] Log informative saat chain loop aktif

Task 16.3 — FindingsTable Attack Chains UI
[ ] ChainInfo interface di types.ts
[ ] Attack Chains section di ExpandedDetail
[ ] Hanya tampil jika chains.length > 0
[ ] Upgraded severity badge merah

Task 16.4 — Anomaly Detection
[ ] detect_anomalies() function di vuln_hunt_node.py
[ ] TIME_ANOMALY: 3x slower → time-based injection flag
[ ] SIZE_ANOMALY: 30%+ size diff → potential disclosure
[ ] STATUS_CHANGE: → potential auth bypass
[ ] ERROR_DISCLOSURE: SQL/traceback keywords → injection evidence
[ ] REFLECTION: marker found → XSS candidate
[ ] Anomalies di-inject ke LLM context untuk better verdict

Task 16.5 — Developer Psychology Prompt
[ ] DEVELOPER_PSYCHOLOGY_HEURISTICS constant di prompts
[ ] Inject ke system prompt di analyze_traffic_for_injections()
[ ] Inject ke plan_engagement() untuk better test prioritization

Task 16.6 — Frontend E2E Tests
[ ] apps/web/e2e/smoke-complete.spec.ts dibuat
[ ] ST-6.1 Login flow test pass
[ ] ST-6.3 FindingsTable renders test pass
[ ] ST-6.5 KB Search test pass
[ ] Smoke test total: 35/35

Task 16.7 — BugHunter Patterns KB Import
[ ] Script import_bughunter_patterns.py
[ ] 20+ hunt-* skill files di-fetch dan di-parse
[ ] Records masuk ke KB dengan source="bughunter"
[ ] quality_score tinggi (manually curated)

Task 16.8 — E2E-v12
[ ] Jalankan engagement baru dengan OSINT node aktif
[ ] Verify triage_node KILL setidaknya 1 informational finding
[ ] Verify chain loop aktif minimal 1 round
[ ] Verify anomaly detection muncul di log
[ ] Smoke test BLOK 6 manual di browser
[ ] Update PROGRESS.md

Total tests target: 159 + 6 baru = 165+
Smoke test target: 35/35
```

---

## Prompt untuk Copilot

**Mulai Task 16.1:**
```
Baca CLAUDE.md, PROGRESS.md, dan CLAUDE-BUGHUNTER-ENHANCEMENT.md secara lengkap.

Kita mulai Sprint 16, Task 16.1 — Triage Gate Node.

1. Buat packages/pentra-agent/pentra_agent/nodes/triage_node.py
   sesuai kode di Enhancement A CLAUDE-BUGHUNTER-ENHANCEMENT.md

2. Update packages/pentra-agent/pentra_agent/graph/builder.py:
   - Tambahkan triage node
   - Update edges: vuln_hunt → triage → hitl_exploit/report

3. Buat packages/pentra-agent/tests/test_triage_node.py dengan 3 tests:
   - PASS verdict: finding dengan evidence kuat
   - KILL verdict: theoretical-only finding
   - DOWNGRADE verdict: severity terlalu tinggi

4. Jalankan: uv run pytest packages/pentra-agent/tests/ -q
   Pastikan 3 tests baru pass, 0 regresi.

Ikuti konvensi CLAUDE.md.
```

**Lanjut Task 16.3 (cepat — 1 jam):**
```
Task 16.1 selesai. Lanjut Task 16.3 — FindingsTable Attack Chains UI.

Update apps/web/src/components/findings/FindingsTable.tsx:
Tambahkan ChainInfo interface dan Attack Chains section di ExpandedDetail
sesuai kode di Enhancement H CLAUDE-BUGHUNTER-ENHANCEMENT.md.
Section hanya tampil jika finding.chains?.length > 0.
```

**Lanjut Task 16.4 + 16.5:**
```
Task 16.3 selesai. Kerjakan Task 16.4 (Anomaly Detection) dan
Task 16.5 (Developer Psychology) sesuai Enhancement E dan D
di CLAUDE-BUGHUNTER-ENHANCEMENT.md.
```

---

*CLAUDE-BUGHUNTER-ENHANCEMENT.md — Pentra AI*  
*Analisis: Claude-BugHunter (794 stars, 574+ patterns, 24 vuln classes)*  
*Sprint 16: Triage Gate + DO NOT STOP + Anomaly Detection + Developer Psychology*
