# SPRINT-15.md — Pentra AI
> **Untuk:** GitHub Copilot dengan Claude Sonnet 4.6  
> **Baca terlebih dahulu:** `CLAUDE.md` → `PROGRESS.md` → `COMPETITIVE-ENHANCEMENT.md` → file ini  
> **Status:** Sprint 1–14.3 selesai, 143 tests passing, 12 migrations  
> **Tujuan:** Architecture Upgrade — 5 tasks dari backlog Sprint 15

---

## Konteks

Sprint 14 selesai dengan sempurna:
- **14.1** EngagementLearning — agent belajar dari engagement sebelumnya
- **14.2** ReAct loop — reasoning eksplisit sebelum setiap injection test
- **14.3** CVSS v3.1 auto-scoring — setiap finding punya valid vector string

Sprint 15 fokus pada **intelligence dan robustness**:
- Tools menjadi lebih cerdas (rate limit aware, tech-aware)
- Findings menjadi lebih valuable (correlation, chaining)
- Engagement panjang tidak overflow (summarizer)
- Coverage lebih dalam (OSINT + playbooks)

**Urutan eksekusi: 15.1 → 15.2 → 15.3 → 15.4 → 15.5**  
Setiap task bergantung pada task sebelumnya.

---

## Task 15.1 — RateLimitDetector

> **Estimasi:** 2–3 jam  
> **Impact:** Mencegah blocking saat engagement di real production targets  
> **Priority:** HIGH — tanpa ini ffuf/katana bisa trigger WAF ban

### Buat file: `packages/pentra-tools/pentra_tools/recon/rate_limit_detector.py`

```python
# packages/pentra-tools/pentra_tools/recon/rate_limit_detector.py

"""
RateLimitDetector — probe target sebelum fuzzing intensif.
Deteksi: HTTP 429, X-RateLimit-* headers, timing variance.
Output: safe_rps untuk di-pass ke ffuf, katana, nuclei.
"""

import asyncio
import logging
import statistics
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


@dataclass
class RateLimitResult:
    url: str
    is_rate_limited: bool           # 429 ditemukan
    has_ratelimit_headers: bool     # X-RateLimit-* atau RateLimit-* header
    has_retry_after: bool           # Retry-After header
    timing_variance: float          # max/min response time ratio
    recommended_delay_ms: int       # delay antar request (ms)
    safe_rps: int                   # safe requests per second untuk tools
    notes: list[str]                # human-readable observations


async def probe_rate_limit(
    url: str,
    probe_count: int = 6,
    probe_interval: float = 0.15,
    timeout: float = 10.0,
) -> RateLimitResult:
    """
    Probe URL dengan N requests cepat dan analisis response patterns.

    Args:
        url: Target URL untuk diprobe
        probe_count: Jumlah request probe (default 6)
        probe_interval: Interval antar probe dalam detik (default 150ms)
        timeout: HTTP timeout per request

    Returns:
        RateLimitResult dengan rekomendasi safe_rps
    """
    responses = []
    notes = []

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        for i in range(probe_count):
            start = time.monotonic()
            try:
                r = await client.get(url)
                elapsed = time.monotonic() - start
                responses.append({
                    "status": r.status_code,
                    "elapsed": elapsed,
                    "retry_after": r.headers.get("Retry-After"),
                    "x_ratelimit_remaining": r.headers.get("X-RateLimit-Remaining"),
                    "x_ratelimit_limit": r.headers.get("X-RateLimit-Limit"),
                    "ratelimit_remaining": r.headers.get("RateLimit-Remaining"),
                    "ratelimit_policy": r.headers.get("RateLimit-Policy"),
                })
            except httpx.TimeoutException:
                responses.append({"status": 0, "elapsed": timeout})
            except Exception as e:
                responses.append({"status": 0, "elapsed": 0, "error": str(e)})

            if i < probe_count - 1:
                await asyncio.sleep(probe_interval)

    # ── Analysis ──────────────────────────────────────────────────────

    statuses = [r["status"] for r in responses]
    elapsed_times = [r["elapsed"] for r in responses if r.get("elapsed", 0) > 0]

    # 1. Hard rate limiting (HTTP 429)
    is_rate_limited = 429 in statuses
    if is_rate_limited:
        notes.append(f"HTTP 429 detected after {statuses.index(429)+1} requests")

    # 2. Rate limit headers
    has_ratelimit_headers = any(
        r.get("x_ratelimit_remaining") is not None or
        r.get("ratelimit_remaining") is not None
        for r in responses
    )
    if has_ratelimit_headers:
        # Try to extract limit value
        for r in responses:
            limit = r.get("x_ratelimit_limit") or r.get("ratelimit_policy")
            if limit:
                notes.append(f"Rate limit header detected: limit={limit}")
                break
        else:
            notes.append("Rate limit headers detected (X-RateLimit-* or RateLimit-*)")

    # 3. Retry-After header
    has_retry_after = any(r.get("retry_after") for r in responses)
    if has_retry_after:
        retry_val = next(r["retry_after"] for r in responses if r.get("retry_after"))
        notes.append(f"Retry-After: {retry_val}")

    # 4. Timing variance — high variance = potential throttling
    timing_variance = 1.0
    if len(elapsed_times) >= 3:
        timing_variance = max(elapsed_times) / max(min(elapsed_times), 0.001)
        if timing_variance > 5.0:
            notes.append(
                f"High timing variance ({timing_variance:.1f}x) — "
                "possible server-side throttling"
            )

    # ── Recommendations ───────────────────────────────────────────────

    if is_rate_limited:
        recommended_delay_ms = 2000
        safe_rps = 1
        notes.append("Aggressive rate limiting — use very slow scan mode")
    elif has_ratelimit_headers:
        recommended_delay_ms = 500
        safe_rps = 3
        notes.append("Rate limit headers present — using conservative speed")
    elif timing_variance > 3.0:
        recommended_delay_ms = 300
        safe_rps = 5
        notes.append("Timing variance suggests throttling — using moderate speed")
    elif has_retry_after:
        recommended_delay_ms = 1000
        safe_rps = 2
    else:
        recommended_delay_ms = 0
        safe_rps = 20
        notes.append("No rate limiting detected — normal speed")

    result = RateLimitResult(
        url=url,
        is_rate_limited=is_rate_limited,
        has_ratelimit_headers=has_ratelimit_headers,
        has_retry_after=has_retry_after,
        timing_variance=timing_variance,
        recommended_delay_ms=recommended_delay_ms,
        safe_rps=safe_rps,
        notes=notes,
    )

    logger.info(
        "[rate_limit_detector] %s → rate_limited=%s headers=%s safe_rps=%d notes=%s",
        url, is_rate_limited, has_ratelimit_headers, safe_rps, notes
    )

    return result
```

### Integrasi ke `recon_node.py`

```python
# packages/pentra-agent/pentra_agent/nodes/recon_node.py
# Tambahkan setelah httpx probe, sebelum ffuf/katana:

from pentra_tools.recon.rate_limit_detector import probe_rate_limit, RateLimitResult

# ── Rate limit detection ──────────────────────────────────────
rate_limit: RateLimitResult | None = None
primary_url = f"http://{domain}/"

try:
    rate_limit = await probe_rate_limit(primary_url)
    logger.info(
        "[recon_node] Rate limit probe: safe_rps=%d delay=%dms",
        rate_limit.safe_rps,
        rate_limit.recommended_delay_ms,
    )
except Exception as e:
    logger.warning("[recon_node] Rate limit probe failed: %s", e)

# Pass safe_rps ke tool wrappers
ffuf_rate = rate_limit.safe_rps * 10 if rate_limit else 100   # ffuf pakai req/min
katana_rate = rate_limit.safe_rps if rate_limit else 10
nuclei_concurrency = min(rate_limit.safe_rps, 25) if rate_limit else 25

# Simpan di state untuk vuln_hunt_node
rate_limit_info = {
    "safe_rps": rate_limit.safe_rps if rate_limit else 20,
    "delay_ms": rate_limit.recommended_delay_ms if rate_limit else 0,
    "is_limited": rate_limit.is_rate_limited if rate_limit else False,
    "notes": rate_limit.notes if rate_limit else [],
}
```

### Update `PentraState` untuk simpan rate limit info

```python
# packages/pentra-agent/pentra_agent/graph/state.py
# Tambahkan field:

class PentraState(TypedDict):
    # ... existing fields ...
    rate_limit_info: dict  # {safe_rps, delay_ms, is_limited, notes}
```

### Tests

```python
# packages/pentra-tools/tests/test_rate_limit_detector.py

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

@pytest.mark.asyncio
async def test_detects_429_response():
    """HTTP 429 → is_rate_limited=True, safe_rps=1."""
    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_response.headers = {}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        from pentra_tools.recon.rate_limit_detector import probe_rate_limit
        result = await probe_rate_limit("http://target.com/", probe_count=2)

    assert result.is_rate_limited is True
    assert result.safe_rps == 1
    assert result.recommended_delay_ms == 2000


@pytest.mark.asyncio
async def test_detects_ratelimit_headers():
    """X-RateLimit-Remaining header → has_ratelimit_headers=True."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"X-RateLimit-Remaining": "10", "X-RateLimit-Limit": "100"}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        from pentra_tools.recon.rate_limit_detector import probe_rate_limit
        result = await probe_rate_limit("http://target.com/", probe_count=2)

    assert result.has_ratelimit_headers is True
    assert result.safe_rps <= 5


def test_no_rate_limit_returns_high_rps():
    """Normal responses → safe_rps=20, no delay."""
    import asyncio
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {}

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        from pentra_tools.recon.rate_limit_detector import probe_rate_limit
        result = asyncio.run(probe_rate_limit("http://target.com/", probe_count=2))

    assert result.safe_rps == 20
    assert result.recommended_delay_ms == 0
    assert result.is_rate_limited is False
```

---

## Task 15.2 — VulnerabilityCorrelator

> **Estimasi:** 2–3 jam  
> **Impact:** Findings individual menjadi attack chains — nilai bounty lebih tinggi  
> **Priority:** HIGH — directly impacts bounty value

### Tambahkan ke `report_node.py`

```python
# packages/pentra-agent/pentra_agent/nodes/report_node.py
# Tambahkan fungsi correlate_findings() dan panggil sebelum persist:

async def correlate_findings(
    findings: list[dict],
    llm: "LLMClient",
    knowledge_context: list[dict],
) -> list[dict]:
    """
    Analisis findings untuk identifikasi potential attack chains.

    Contoh chains yang sering terjadi:
    - SSRF + exposed internal service → potential RCE
    - Reflected XSS + CSRF → account takeover
    - IDOR + PII disclosure → critical data breach
    - Open redirect + OAuth → token theft
    - SQLi read + file write → RCE

    Returns: findings yang sudah di-enrich dengan chain_info
    """
    if len(findings) < 2:
        return findings  # tidak ada yang bisa dikorelasikan

    # Siapkan summary findings untuk LLM
    findings_summary = [
        {
            "idx": i,
            "title": f.get("title", "Finding"),
            "vuln_class": f.get("vuln_class", "UNKNOWN"),
            "url": f.get("target_url", ""),
            "severity": f.get("severity", "medium"),
        }
        for i, f in enumerate(findings)
    ]

    # Ambil pola chaining dari knowledge base
    chain_patterns = [
        k.get("chained_with", [])
        for k in knowledge_context
        if k.get("chained_with")
    ][:5]

    chain_prompt = f"""You are analyzing penetration testing findings to identify attack chains.

Findings discovered:
{json.dumps(findings_summary, indent=2)}

Known chain patterns from similar engagements:
{json.dumps(chain_patterns, indent=2)}

Identify all possible attack chains. For each chain:
- List the finding indexes that form the chain
- Describe the combined attack scenario
- State the upgraded severity
- Explain the business impact

Return JSON array:
[
  {{
    "chain_indexes": [0, 2],
    "chain_name": "SSRF to Internal RCE",
    "scenario": "SSRF allows access to internal service, combined with exposed Redis...",
    "upgraded_severity": "critical",
    "business_impact": "Full server compromise possible"
  }}
]

Return empty array [] if no meaningful chains exist.
Only include chains where the combination creates significantly higher impact."""

    try:
        chains = await llm.complete_json(
            system="You are a senior penetration tester specializing in vulnerability chaining.",
            user=chain_prompt,
        )
    except Exception as e:
        logger.warning("[report_node] correlate_findings failed: %s", e)
        return findings

    if not isinstance(chains, list) or not chains:
        return findings

    # Attach chain info ke setiap finding yang terlibat
    for chain in chains:
        chain_indexes = chain.get("chain_indexes", [])
        for idx in chain_indexes:
            if 0 <= idx < len(findings):
                if "chains" not in findings[idx]:
                    findings[idx]["chains"] = []
                findings[idx]["chains"].append({
                    "name": chain.get("chain_name", "Attack Chain"),
                    "scenario": chain.get("scenario", ""),
                    "upgraded_severity": chain.get("upgraded_severity"),
                    "business_impact": chain.get("business_impact", ""),
                    "chain_size": len(chain_indexes),
                })

    # Log chains yang ditemukan
    if chains:
        logger.info(
            "[report_node] Found %d attack chains: %s",
            len(chains),
            [c.get("chain_name") for c in chains]
        )

    return findings


# Di report_node() — tambahkan setelah LLM classify, sebelum persist:
# findings = await correlate_findings(findings, llm, state.get("knowledge_context", []))
```

### Update `FindingORM` dan schema

```python
# apps/api/app/db/models.py — tambahkan field:
chains: Mapped[list | None] = mapped_column(JSONB, nullable=True)
```

```bash
# Buat migration:
uv run alembic revision --autogenerate -m "add_chains_to_findings"
uv run alembic upgrade head
```

### Update `FindingsTable.tsx` — tampilkan chain badges

```typescript
// apps/web/src/components/findings/FindingsTable.tsx
// Di expanded row, tambahkan section "Attack Chains":

{finding.chains && finding.chains.length > 0 && (
  <div>
    <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-2">
      ⛓️ Attack Chains
    </p>
    <div className="space-y-2">
      {finding.chains.map((chain: any, i: number) => (
        <div
          key={i}
          className="bg-red-950/30 border border-red-900/40 rounded p-3"
        >
          <div className="flex items-center gap-2 mb-1">
            <Badge
              variant="outline"
              className="text-xs text-red-400 border-red-800"
            >
              {chain.upgraded_severity?.toUpperCase() ?? "CHAIN"}
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

## Task 15.3 — Attack Playbooks

> **Estimasi:** 3–4 jam  
> **Impact:** Structured testing — tidak ada manual vuln class yang terlewat  
> **Priority:** MEDIUM

### Buat `packages/pentra-agent/pentra_agent/playbooks/__init__.py`

```python
# packages/pentra-agent/pentra_agent/playbooks/__init__.py

from .base import Playbook, PlaybookStep, PlaybookResult
from .registry import PLAYBOOKS, get_playbook_for_context

__all__ = ["Playbook", "PlaybookStep", "PlaybookResult", "PLAYBOOKS", "get_playbook_for_context"]
```

### Buat `base.py`

```python
# packages/pentra-agent/pentra_agent/playbooks/base.py

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class PlaybookStep:
    name: str
    action: Literal[
        "probe_reflection",     # Cek apakah input direfleksikan
        "error_based_probe",    # Cek syntax error response
        "boolean_probe",        # Boolean-based test
        "time_based_probe",     # Time-delay based test
        "oob_probe",            # Out-of-band via Collaborator
        "boundary_probe",       # Boundary/overflow test
        "traverse_probe",       # Path traversal test
        "idor_probe",           # Object reference manipulation
        "confirm_with_burp",    # Send to Burp Repeater
        "manual_review",        # Flag untuk manual review
    ]
    payload_template: str       # Template payload, {MARKER} = injection point
    detect_pattern: str         # Regex atau string untuk deteksi success
    description: str
    is_destructive: bool = False
    requires_burp: bool = False


@dataclass
class Playbook:
    name: str
    vuln_class: str
    description: str
    steps: list[PlaybookStep]
    tech_stack_hints: list[str]     # Tech stack yang relevan
    url_patterns: list[str]         # URL pattern hints (e.g., "?id=", "?cat=")
    priority: int = 5               # 1=highest, 10=lowest


@dataclass
class PlaybookResult:
    playbook_name: str
    steps_executed: int
    steps_confirmed: int
    confirmed_findings: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
```

### Buat `registry.py`

```python
# packages/pentra-agent/pentra_agent/playbooks/registry.py

from .base import Playbook, PlaybookStep

PLAYBOOKS: dict[str, Playbook] = {

    "sqli_error": Playbook(
        name="SQL Injection — Error Based",
        vuln_class="SQL_INJECTION",
        description="Test parameter untuk SQL injection via error messages",
        priority=1,
        tech_stack_hints=["mssql", "mysql", "postgresql", "asp.net", "php", "rails"],
        url_patterns=["?id=", "?cat=", "?pid=", "?article=", "?user=", "?product="],
        steps=[
            PlaybookStep(
                name="Single Quote Probe",
                action="error_based_probe",
                payload_template="'",
                detect_pattern=r"sql|syntax|mysql|mssql|ora-|unterminated|quoted",
                description="Single quote biasanya memicu SQL error jika tidak di-sanitize",
            ),
            PlaybookStep(
                name="Double Quote Probe",
                action="error_based_probe",
                payload_template='"',
                detect_pattern=r"sql|syntax|mysql|mssql|error",
                description="Double quote untuk string-delimited queries",
            ),
            PlaybookStep(
                name="Boolean True Probe",
                action="boolean_probe",
                payload_template="' OR '1'='1",
                detect_pattern="response_change",  # handled by caller
                description="Boolean injection — response harus berbeda dari baseline",
            ),
            PlaybookStep(
                name="Time-Based Probe (MSSQL)",
                action="time_based_probe",
                payload_template="'; WAITFOR DELAY '0:0:5'--",
                detect_pattern="delay_5s",
                description="Time delay probe untuk MSSQL — 5 detik delay = vulnerable",
            ),
            PlaybookStep(
                name="Time-Based Probe (MySQL)",
                action="time_based_probe",
                payload_template="' AND SLEEP(5)--",
                detect_pattern="delay_5s",
                description="Time delay probe untuk MySQL",
            ),
            PlaybookStep(
                name="Confirm with Burp",
                action="confirm_with_burp",
                payload_template="",
                detect_pattern="",
                description="Send ke Burp Repeater untuk manual verification + Intruder",
                requires_burp=True,
            ),
        ],
    ),

    "xss_reflected": Playbook(
        name="XSS — Reflected",
        vuln_class="XSS",
        description="Test parameter untuk reflected XSS",
        priority=2,
        tech_stack_hints=["php", "asp.net", "java", "rails", "django"],
        url_patterns=["?search=", "?q=", "?query=", "?name=", "?message=", "?input="],
        steps=[
            PlaybookStep(
                name="Marker Reflection Test",
                action="probe_reflection",
                payload_template="PENTRA_XSS_12345",
                detect_pattern="PENTRA_XSS_12345",
                description="Cek apakah input direfleksikan ke response",
            ),
            PlaybookStep(
                name="HTML Tag Injection",
                action="probe_reflection",
                payload_template="<b>PENTRA</b>",
                detect_pattern=r"<b>PENTRA</b>",
                description="Cek apakah HTML tag tidak di-escape",
            ),
            PlaybookStep(
                name="Script Tag Test",
                action="probe_reflection",
                payload_template="<script>alert('XSS')</script>",
                detect_pattern=r"<script>alert\('XSS'\)</script>",
                description="Basic XSS payload tanpa encoding",
            ),
            PlaybookStep(
                name="Event Handler Test",
                action="probe_reflection",
                payload_template='"><img src=x onerror=alert(1)>',
                detect_pattern=r"onerror=alert",
                description="Event handler injection untuk bypass quote filtering",
            ),
            PlaybookStep(
                name="CSP Check",
                action="manual_review",
                payload_template="",
                detect_pattern="content-security-policy",
                description="Cek Content-Security-Policy header — jika ada, perlu bypass",
            ),
        ],
    ),

    "idor": Playbook(
        name="IDOR — Insecure Direct Object Reference",
        vuln_class="IDOR",
        description="Test parameter ID untuk unauthorized object access",
        priority=1,
        tech_stack_hints=["rails", "django", "laravel", "spring", "express", "rest-api"],
        url_patterns=["?id=", "?user_id=", "?account_id=", "/users/", "/accounts/", "/orders/"],
        steps=[
            PlaybookStep(
                name="ID Increment Test",
                action="idor_probe",
                payload_template="{ID+1}",
                detect_pattern="response_change",
                description="Increment ID — response berbeda = IDOR potential",
            ),
            PlaybookStep(
                name="ID Decrement Test",
                action="idor_probe",
                payload_template="{ID-1}",
                detect_pattern="response_change",
                description="Decrement ID",
            ),
            PlaybookStep(
                name="Zero ID Test",
                action="idor_probe",
                payload_template="0",
                detect_pattern="response_change",
                description="ID=0 kadang mengembalikan semua records",
            ),
            PlaybookStep(
                name="Negative ID Test",
                action="idor_probe",
                payload_template="-1",
                detect_pattern="error_or_change",
                description="Negative ID untuk test boundary",
            ),
            PlaybookStep(
                name="UUID Manipulation",
                action="idor_probe",
                payload_template="00000000-0000-0000-0000-000000000001",
                detect_pattern="response_change",
                description="Untuk endpoint dengan UUID — test dengan known other user UUID",
            ),
        ],
    ),

    "ssrf": Playbook(
        name="SSRF — Server-Side Request Forgery",
        vuln_class="SSRF",
        description="Test URL/destination parameters untuk SSRF",
        priority=1,
        tech_stack_hints=["python", "ruby", "java", "php", "node"],
        url_patterns=["?url=", "?dest=", "?redirect=", "?uri=", "?path=", "?target=", "?src="],
        steps=[
            PlaybookStep(
                name="Internal IP Probe",
                action="probe_reflection",
                payload_template="http://127.0.0.1/",
                detect_pattern=r"localhost|127\.0\.0\.1|connection refused|refused",
                description="Test SSRF ke localhost",
            ),
            PlaybookStep(
                name="Cloud Metadata Probe",
                action="probe_reflection",
                payload_template="http://169.254.169.254/latest/meta-data/",
                detect_pattern=r"ami-id|instance-id|meta-data",
                description="AWS metadata endpoint — high impact jika berhasil",
            ),
            PlaybookStep(
                name="OOB Collaborator Probe",
                action="oob_probe",
                payload_template="http://{COLLABORATOR_PAYLOAD}/ssrf-test",
                detect_pattern="collaborator_dns",
                description="Out-of-band test via Burp Collaborator",
                requires_burp=True,
            ),
            PlaybookStep(
                name="Internal Port Scan",
                action="probe_reflection",
                payload_template="http://127.0.0.1:{PORT}/",
                detect_pattern="response_change",
                description="Scan internal ports via SSRF (6379=Redis, 5432=PostgreSQL)",
            ),
        ],
    ),

    "path_traversal": Playbook(
        name="Path Traversal / LFI",
        vuln_class="PATH_TRAVERSAL",
        description="Test file path parameters untuk directory traversal",
        priority=2,
        tech_stack_hints=["php", "python", "ruby", "java", "node"],
        url_patterns=["?file=", "?path=", "?page=", "?template=", "?include=", "?doc="],
        steps=[
            PlaybookStep(
                name="Basic Traversal (Linux)",
                action="probe_reflection",
                payload_template="../../../etc/passwd",
                detect_pattern=r"root:.*:/bin/",
                description="Linux /etc/passwd — definitive proof of LFI",
            ),
            PlaybookStep(
                name="Basic Traversal (Windows)",
                action="probe_reflection",
                payload_template="..\\..\\..\\windows\\win.ini",
                detect_pattern=r"\[fonts\]|\[extensions\]",
                description="Windows win.ini — definitive proof of LFI",
            ),
            PlaybookStep(
                name="URL Encoded Traversal",
                action="probe_reflection",
                payload_template="%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                detect_pattern=r"root:.*:/bin/",
                description="URL encoded untuk bypass simple filters",
            ),
            PlaybookStep(
                name="Double Encoded Traversal",
                action="probe_reflection",
                payload_template="..%252f..%252f..%252fetc%252fpasswd",
                detect_pattern=r"root:.*:/bin/",
                description="Double encoding bypass",
            ),
        ],
    ),
}


def get_playbook_for_context(
    tech_stack: list[str],
    url: str,
    param: str,
) -> list[Playbook]:
    """
    Return playbooks yang relevan berdasarkan context.
    Sorted by priority (1=highest).
    """
    relevant = []
    url_lower = (url + "?" + param).lower()

    for playbook in PLAYBOOKS.values():
        score = 0

        # Tech stack match
        for hint in playbook.tech_stack_hints:
            if any(hint in t.lower() for t in tech_stack):
                score += 2

        # URL pattern match
        for pattern in playbook.url_patterns:
            if pattern.lower() in url_lower:
                score += 3

        if score > 0:
            relevant.append((score, playbook))

    # Sort: score desc, priority asc
    relevant.sort(key=lambda x: (-x[0], x[1].priority))
    return [p for _, p in relevant]
```

### Integrasi ke `vuln_hunt_node.py`

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# Di _run_llm_burp_active_testing(), setelah extract candidates:

from pentra_agent.playbooks import get_playbook_for_context

# Per kandidat parameter:
for url, param in param_candidates:
    # Get relevant playbooks
    playbooks = get_playbook_for_context(
        tech_stack=state.get("tech_stack", []),
        url=url,
        param=param,
    )

    if playbooks:
        logger.info(
            "[vuln_hunt] Running %d playbooks for %s?%s: %s",
            len(playbooks), url, param,
            [p.name for p in playbooks[:3]]
        )
        # Jalankan playbook terpilih
        for playbook in playbooks[:2]:  # max 2 playbooks per param
            result = await run_playbook(playbook, url, param, state, llm)
            if result.confirmed_findings:
                all_findings.extend(result.confirmed_findings)
```

---

## Task 15.4 — Chain Summarizer

> **Estimasi:** 2 jam  
> **Impact:** Engagement panjang (50+ HITL cycles) tidak overflow context  
> **Priority:** MEDIUM

### Buat `packages/pentra-agent/pentra_agent/llm/summarizer.py`

```python
# packages/pentra-agent/pentra_agent/llm/summarizer.py

"""
ChainSummarizer — compress message history saat mendekati context limit.
Dipanggil otomatis oleh agent nodes jika len(messages) > SUMMARIZE_THRESHOLD.

Strategy:
- Pertahankan 10 pesan terakhir verbatim (context terkini)
- Compress semua pesan sebelumnya menjadi 1 summary pesan
- Summary wajib preserve: semua findings, confirmed vulns, scope, decisions
- Compress: verbose tool outputs, repetitive recon data
"""

import logging
from langchain_core.messages import AnyMessage, SystemMessage, AIMessage

logger = logging.getLogger(__name__)

SUMMARIZE_THRESHOLD = 40    # Trigger compression setelah N messages
KEEP_RECENT = 10            # Jumlah pesan terbaru yang tetap verbatim
MAX_SUMMARY_TOKENS = 2000   # Max length summary dalam karakter


async def maybe_summarize(
    messages: list[AnyMessage],
    llm: "LLMClient",
) -> list[AnyMessage]:
    """
    Compress messages jika melebihi threshold.
    Return messages yang sudah dikompresi (atau original jika belum perlu).
    """
    if len(messages) <= SUMMARIZE_THRESHOLD:
        return messages

    recent = messages[-KEEP_RECENT:]
    older = messages[:-KEEP_RECENT]

    logger.info(
        "[summarizer] Compressing %d messages (keeping %d recent)",
        len(older), len(recent)
    )

    # Extract text content dari older messages
    older_text = "\n\n".join(
        f"[{type(m).__name__}]: {getattr(m, 'content', str(m))[:500]}"
        for m in older
        if hasattr(m, "content")
    )

    try:
        summary = await llm.complete(
            system="""You are summarizing a penetration testing session history.

CRITICAL RULES:
1. PRESERVE ALL: confirmed vulnerabilities, CVE IDs, CVSS scores, URLs, parameters
2. PRESERVE ALL: scope decisions, HITL approvals, rejected techniques
3. PRESERVE ALL: key findings with severity levels
4. COMPRESS: verbose tool outputs, raw HTTP responses, repeated status messages
5. FORMAT: Use bullet points, be concise but complete

Output format:
## Confirmed Findings
- [list all confirmed vulns with URL and severity]

## Key Decisions
- [list HITL approvals, skipped tests, scope clarifications]

## Recon Summary
- [brief summary of discovered assets]

## Current State
- [what phase, what's been tested, what's pending]""",
            user=f"Summarize this penetration testing session:\n\n{older_text[:6000]}",
        )
    except Exception as e:
        logger.warning("[summarizer] Summarization failed: %s — keeping original", e)
        return messages

    # Trim summary jika terlalu panjang
    if len(summary) > MAX_SUMMARY_TOKENS:
        summary = summary[:MAX_SUMMARY_TOKENS] + "\n... [truncated]"

    summary_msg = SystemMessage(
        content=f"[COMPRESSED SESSION HISTORY — {len(older)} messages summarized]\n\n{summary}"
    )

    compressed = [summary_msg] + list(recent)
    logger.info(
        "[summarizer] Compressed %d → %d messages",
        len(messages), len(compressed)
    )

    return compressed
```

### Integrasi ke semua nodes yang pakai messages

```python
# packages/pentra-agent/pentra_agent/nodes/vuln_hunt_node.py
# packages/pentra-agent/pentra_agent/nodes/recon_node.py
# Tambahkan di awal setiap node:

from pentra_agent.llm.summarizer import maybe_summarize

async def vuln_hunt_node(state: PentraState) -> dict:
    # Compress messages jika terlalu panjang
    messages = await maybe_summarize(
        state.get("messages", []),
        llm=LLMClient(base_url=_get_ollama_url(), model=state["llm_model"])
    )
    # Lanjut dengan messages yang sudah dikompresi
    ...
```

---

## Task 15.5 — OSINT Node

> **Estimasi:** 3–4 jam  
> **Impact:** Context lebih kaya sebelum recon teknis — better planning  
> **Priority:** MEDIUM

### Buat `packages/pentra-agent/pentra_agent/nodes/osint_node.py`

```python
# packages/pentra-agent/pentra_agent/nodes/osint_node.py

"""
OSINT Node — passive information gathering sebelum recon teknis.
Posisi di graph: START → osint → plan → recon → ...

Sources:
1. crt.sh — subdomain via certificate transparency (gratis, no API key)
2. H1 program lookup — apakah target punya bug bounty program?
3. Shodan summary — port/service summary (requires SHODAN_API_KEY, optional)
"""

import asyncio
import json
import logging
import os
from datetime import datetime

import httpx
from langchain_core.messages import AIMessage

from pentra_agent.graph.state import PentraState
from pentra_scope import ScopeEnforcer

logger = logging.getLogger(__name__)


async def osint_node(state: PentraState) -> dict:
    """
    Passive OSINT sebelum recon aktif.
    Tidak ada traffic ke target — semua passive sources.
    """
    domain = state["target"]["domain"]
    results = {}
    messages = []

    logger.info("[osint_node] Starting passive OSINT for %s", domain)

    # ── 1. Certificate Transparency (crt.sh) ────────────────────────
    ct_subdomains = await _query_crt_sh(domain)
    if ct_subdomains:
        results["ct_subdomains"] = ct_subdomains
        logger.info(
            "[osint_node] crt.sh: %d subdomains via certificate transparency",
            len(ct_subdomains)
        )

    # ── 2. H1 Bug Bounty Program Lookup ─────────────────────────────
    h1_program = await _lookup_h1_program(domain)
    if h1_program:
        results["h1_program"] = h1_program
        logger.info(
            "[osint_node] H1 program found: %s (scope: %d items)",
            h1_program.get("name", "unknown"),
            len(h1_program.get("in_scope", []))
        )

    # ── 3. Shodan Summary (optional) ────────────────────────────────
    shodan_key = os.getenv("SHODAN_API_KEY")
    if shodan_key:
        shodan_data = await _query_shodan(domain, shodan_key)
        if shodan_data:
            results["shodan"] = shodan_data
            logger.info(
                "[osint_node] Shodan: %d ports, org=%s",
                len(shodan_data.get("ports", [])),
                shodan_data.get("org", "unknown")
            )
    else:
        logger.debug("[osint_node] SHODAN_API_KEY not set — skipping Shodan")

    # ── Summary message ─────────────────────────────────────────────
    summary_parts = [f"OSINT complete for {domain}:"]

    if ct_subdomains:
        summary_parts.append(
            f"- {len(ct_subdomains)} subdomains via certificate transparency"
        )
        # Top 5 yang paling menarik
        interesting = [s for s in ct_subdomains if any(
            kw in s.lower() for kw in ["admin", "api", "dev", "staging", "test", "internal"]
        )]
        if interesting:
            summary_parts.append(f"  Interesting: {', '.join(interesting[:5])}")

    if h1_program:
        summary_parts.append(
            f"- Bug bounty program: {h1_program.get('name')} "
            f"({'active' if h1_program.get('active') else 'inactive'})"
        )
        if h1_program.get("bounty_range"):
            summary_parts.append(f"  Bounty: {h1_program['bounty_range']}")

    if not results:
        summary_parts.append("- No significant OSINT data found (passive only)")

    messages.append(AIMessage(content="\n".join(summary_parts)))

    return {
        "osint_results": results,
        "messages": messages,
        # Enrich subdomains dengan CT data sebelum active recon
        "subdomains": [
            {"host": s, "source": "crt.sh", "is_alive": False}
            for s in ct_subdomains
        ] if ct_subdomains else [],
    }


async def _query_crt_sh(domain: str) -> list[str]:
    """
    Query crt.sh untuk subdomain via certificate transparency.
    Free, no API key, passive only.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json"},
            )
            if r.status_code != 200:
                return []

            data = r.json()

            # Extract unique subdomains
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                # Handle wildcards dan multiple names
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n and domain in n and n != domain:
                        subdomains.add(n)

            return sorted(subdomains)[:100]  # Max 100

    except Exception as e:
        logger.warning("[osint_node] crt.sh query failed: %s", e)
        return []


async def _lookup_h1_program(domain: str) -> dict | None:
    """
    Cek apakah domain punya active bug bounty program di HackerOne.
    Menggunakan H1 public GraphQL (no auth required untuk basic info).
    """
    # Extract root domain
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Try H1 program search via public API
            r = await client.get(
                f"https://hackerone.com/programs/search",
                params={"q": root, "sort": "relevance", "limit": 5},
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0",
                },
            )

            if r.status_code != 200:
                return None

            data = r.json()
            programs = data.get("results", [])

            for prog in programs:
                # Check if domain matches
                prog_domain = prog.get("handle", "").lower()
                if root.replace(".", "") in prog_domain or prog_domain in root:
                    return {
                        "name": prog.get("name"),
                        "handle": prog.get("handle"),
                        "active": True,
                        "url": f"https://hackerone.com/{prog.get('handle')}",
                        "bounty_range": prog.get("meta", {}).get("reward_range"),
                    }

    except Exception as e:
        logger.debug("[osint_node] H1 lookup failed: %s", e)

    return None


async def _query_shodan(domain: str, api_key: str) -> dict | None:
    """Query Shodan DNS resolve + host info (requires API key)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Resolve domain ke IP dulu
            dns_r = await client.get(
                f"https://api.shodan.io/dns/resolve",
                params={"hostnames": domain, "key": api_key},
            )
            if dns_r.status_code != 200:
                return None

            ips = dns_r.json()
            ip = ips.get(domain)
            if not ip:
                return None

            # Get host info
            host_r = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key},
            )
            if host_r.status_code != 200:
                return None

            data = host_r.json()
            return {
                "ip": ip,
                "org": data.get("org"),
                "isp": data.get("isp"),
                "country": data.get("country_name"),
                "ports": data.get("ports", []),
                "tags": data.get("tags", []),
                "vulns": list(data.get("vulns", {}).keys())[:10],
                "last_update": data.get("last_update"),
            }

    except Exception as e:
        logger.debug("[osint_node] Shodan query failed: %s", e)
        return None
```

### Update `PentraState` untuk osint_results

```python
# packages/pentra-agent/pentra_agent/graph/state.py
# Tambahkan:
osint_results: dict   # {ct_subdomains, h1_program, shodan}
```

### Update `builder.py` — tambahkan osint node di graph

```python
# packages/pentra-agent/pentra_agent/graph/builder.py

from pentra_agent.nodes.osint_node import osint_node

def build_pentra_graph(checkpointer):
    graph = StateGraph(PentraState)

    # Tambahkan osint node
    graph.add_node("osint", osint_node)
    graph.add_node("plan", plan_node)
    # ... rest of nodes ...

    # Update edges
    graph.add_edge(START, "osint")      # osint dulu sebelum plan
    graph.add_edge("osint", "plan")     # lalu plan
    graph.add_edge("plan", "hitl_plan")
    # ... rest unchanged ...
```

---

## Tests Sprint 15

```python
# packages/pentra-tools/tests/test_rate_limit_detector.py   — 3 tests
# packages/pentra-agent/tests/test_playbooks.py             — 4 tests
# packages/pentra-agent/tests/test_osint_node.py            — 3 tests
# packages/pentra-agent/tests/test_summarizer.py            — 2 tests

# test_playbooks.py:
def test_get_playbook_for_context_sqli():
    """ASP.NET + ?cat= param → SQLi playbook returned."""
    from pentra_agent.playbooks import get_playbook_for_context
    result = get_playbook_for_context(
        tech_stack=["ASP.NET", "MSSQL"],
        url="http://target.com/products.aspx",
        param="cat",
    )
    names = [p.name for p in result]
    assert any("SQL" in n for n in names)


def test_get_playbook_for_context_xss():
    """?search= param → XSS playbook returned."""
    from pentra_agent.playbooks import get_playbook_for_context
    result = get_playbook_for_context(
        tech_stack=["PHP"],
        url="http://target.com/search",
        param="q",
    )
    names = [p.name for p in result]
    assert any("XSS" in n for n in names)


def test_playbook_steps_have_required_fields():
    """Semua steps di semua playbooks harus punya field yang diperlukan."""
    from pentra_agent.playbooks import PLAYBOOKS
    for name, playbook in PLAYBOOKS.items():
        assert playbook.name
        assert playbook.vuln_class
        assert len(playbook.steps) > 0
        for step in playbook.steps:
            assert step.name
            assert step.action
            assert step.description


def test_ssrf_playbook_has_oob_step():
    """SSRF playbook harus punya OOB step untuk Collaborator."""
    from pentra_agent.playbooks import PLAYBOOKS
    ssrf = PLAYBOOKS["ssrf"]
    oob_steps = [s for s in ssrf.steps if s.action == "oob_probe"]
    assert len(oob_steps) > 0


# test_osint_node.py:
@pytest.mark.asyncio
async def test_crt_sh_returns_subdomains():
    """_query_crt_sh harus return list of strings."""
    with patch("httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "api.target.com"},
            {"name_value": "admin.target.com"},
        ]
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_cls.return_value = mock_client

        from pentra_agent.nodes.osint_node import _query_crt_sh
        result = await _query_crt_sh("target.com")

    assert "api.target.com" in result
    assert "admin.target.com" in result


# test_summarizer.py:
@pytest.mark.asyncio
async def test_summarizer_not_triggered_below_threshold():
    """Jika messages < 40, return original tanpa perubahan."""
    from langchain_core.messages import AIMessage
    from pentra_agent.llm.summarizer import maybe_summarize, SUMMARIZE_THRESHOLD

    messages = [AIMessage(content=f"msg {i}") for i in range(SUMMARIZE_THRESHOLD - 5)]
    mock_llm = MagicMock()

    result = await maybe_summarize(messages, mock_llm)
    assert result == messages
    mock_llm.complete.assert_not_called()
```

---

## Checklist Sprint 15

```
Task 15.1 — RateLimitDetector
[x] File rate_limit_detector.py dibuat
[x] probe_rate_limit() deteksi 429 dengan benar
[x] probe_rate_limit() deteksi X-RateLimit-* headers
[x] Integrasi ke recon_node — safe_rps di-pass ke ffuf/katana
[x] PentraState punya field rate_limit_info
[x] 3 tests pass

Task 15.2 — VulnerabilityCorrelator
[x] correlate_findings() function di report_node.py
[x] Migration add_chains_to_findings berhasil di-apply
[ ] FindingsTable.tsx tampilkan "Attack Chains" section   (frontend task)
[x] Chains section hanya muncul jika chains ada (tidak kosong)
[x] LLM tidak crash jika correlate gagal (graceful fallback)

Task 15.3 — Attack Playbooks
[x] playbooks/__init__.py, base.py, registry.py dibuat
[x] 5 playbooks: sqli_error, xss_reflected, idor, ssrf, path_traversal
[x] get_playbook_for_context() return SQLi untuk ASP.NET + ?cat=
[x] get_playbook_for_context() return XSS untuk ?search=
[x] Integrasi ke vuln_hunt_node — playbooks dijalankan per param
[x] 4 tests pass

Task 15.4 — Chain Summarizer
[x] summarizer.py dibuat dengan SUMMARIZE_THRESHOLD=40
[x] maybe_summarize() tidak trigger jika < threshold
[x] maybe_summarize() compress pesan lama ke 1 summary SystemMessage
[x] Summary wajib preserve findings dan decisions
[x] Integrasi ke vuln_hunt_node dan recon_node
[x] 2 tests pass

Task 15.5 — OSINT Node
[x] osint_node.py dibuat
[x] _query_crt_sh() return list subdomains dari crt.sh API
[x] _lookup_h1_program() cek H1 bug bounty program (graceful jika 404)
[x] osint_node() graceful jika semua sources gagal
[x] PentraState punya field osint_results
[x] builder.py updated: START → osint → plan → recon
[x] 3 tests pass

Final
[x] Total tests: pentra-tools 84+3skip, pentra-agent 24, apps/api 51 — 0 failed
[x] uv run pytest -q → 0 failed
[ ] E2E-v12 dijalankan dengan OSINT node aktif
[x] Rate limit probe di log sebelum ffuf
[x] Playbook steps di log per parameter
```

---

## Prompt untuk Copilot

**Mulai Task 15.1:**
```
Baca CLAUDE.md, PROGRESS.md, dan SPRINT-15.md secara lengkap.

Kita mulai Task 15.1 — RateLimitDetector.

1. Buat packages/pentra-tools/pentra_tools/recon/rate_limit_detector.py
   sesuai kode di Task 15.1 SPRINT-15.md

2. Buat packages/pentra-tools/tests/test_rate_limit_detector.py
   dengan 3 tests sesuai Task 15.1

3. Update packages/pentra-agent/pentra_agent/graph/state.py
   tambahkan field rate_limit_info: dict

4. Integrasi ke packages/pentra-agent/pentra_agent/nodes/recon_node.py
   — panggil probe_rate_limit() setelah httpx probe
   — pass safe_rps ke ffuf dan katana

5. Jalankan: uv run pytest packages/pentra-tools/tests/ -q
   Pastikan 3 tests baru pass, tidak ada regresi.

Ikuti konvensi CLAUDE.md.
```

**Lanjut Task 15.2:**
```
Task 15.1 selesai. Lanjut Task 15.2 — VulnerabilityCorrelator.

1. Tambahkan correlate_findings() ke report_node.py sesuai Task 15.2 SPRINT-15.md
2. Tambahkan field chains ke FindingORM dan buat migration
3. Update FindingsTable.tsx untuk tampilkan Attack Chains section
```

**Lanjut Task 15.3:**
```
Task 15.2 selesai. Lanjut Task 15.3 — Attack Playbooks.

Buat packages/pentra-agent/pentra_agent/playbooks/ dengan
__init__.py, base.py, registry.py sesuai Task 15.3 SPRINT-15.md.
5 playbooks: sqli_error, xss_reflected, idor, ssrf, path_traversal.
Integrasi ke vuln_hunt_node.
4 tests.
```

**Lanjut Task 15.4 + 15.5:**
```
Task 15.3 selesai. Kerjakan Task 15.4 (Chain Summarizer) dan
Task 15.5 (OSINT Node) secara berurutan sesuai SPRINT-15.md.
```

---

*SPRINT-15.md — Pentra AI*  
*Architecture Upgrade: RateLimitDetector + VulnerabilityCorrelator + Playbooks + Summarizer + OSINT*  
*Target setelah selesai: 155+ tests, engagement lebih cerdas dan lebih dalam*
