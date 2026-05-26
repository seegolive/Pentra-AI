"""Tests for tool wrappers — scope enforcement and output parsing.

All tests mock subprocess execution so no real tools need to be installed.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from pentra_scope import ScopeEnforcer, ScopeViolationError
from pentra_tools.base import AsyncToolWrapper, ToolResult
from pentra_tools.wrappers.subfinder import SubfinderWrapper, Subdomain
from pentra_tools.wrappers.nmap import NmapWrapper
from pentra_tools.wrappers.nuclei import NucleiWrapper
from pentra_tools.wrappers.amass import AmassWrapper
from pentra_tools.wrappers.katana import KatanaWrapper
from pentra_tools.wrappers.ffuf import FfufWrapper
from pentra_tools.wrappers.dalfox import DalfoxWrapper
from pentra_tools.wrappers.sqlmap import SqlmapWrapper


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def scope() -> ScopeEnforcer:
    return ScopeEnforcer(
        in_scope=["target.com", "*.target.com"],
        out_of_scope=["admin.target.com"],
    )


@pytest.fixture
def subfinder(scope: ScopeEnforcer) -> SubfinderWrapper:
    return SubfinderWrapper(scope)


@pytest.fixture
def nmap(scope: ScopeEnforcer) -> NmapWrapper:
    return NmapWrapper(scope)


@pytest.fixture
def nuclei(scope: ScopeEnforcer) -> NucleiWrapper:
    return NucleiWrapper(scope)


# ── SubfinderWrapper ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_subfinder_scope_check_blocks_oos(subfinder: SubfinderWrapper) -> None:
    """SubfinderWrapper must raise ScopeViolationError for out-of-scope targets."""
    with pytest.raises(ScopeViolationError):
        await subfinder.run("evil.com")


@pytest.mark.asyncio
async def test_subfinder_scope_check_blocks_excluded(subfinder: SubfinderWrapper) -> None:
    with pytest.raises(ScopeViolationError):
        await subfinder.run("admin.target.com")


@pytest.mark.asyncio
async def test_subfinder_parses_json_output(subfinder: SubfinderWrapper) -> None:
    """SubfinderWrapper correctly parses JSON-per-line subfinder output."""
    mock_stdout = "\n".join([
        json.dumps({"host": "api.target.com", "source": "dnsx", "ip": "1.2.3.4"}),
        json.dumps({"host": "mail.target.com", "source": "crtsh"}),
    ])

    with patch.object(subfinder, "_exec", new=AsyncMock(return_value=(mock_stdout, "", 0))):
        result: ToolResult = await subfinder.run("target.com")

    assert result.success is True
    assert result.tool == "subfinder"
    assert len(result.data) == 2
    hosts = [s.host for s in result.data]
    assert "api.target.com" in hosts
    assert "mail.target.com" in hosts
    assert result.data[0].ip == "1.2.3.4"


@pytest.mark.asyncio
async def test_subfinder_parses_plaintext_fallback(subfinder: SubfinderWrapper) -> None:
    """SubfinderWrapper handles plain-text host-per-line output (older subfinder)."""
    mock_stdout = "api.target.com\nmail.target.com\n"

    with patch.object(subfinder, "_exec", new=AsyncMock(return_value=(mock_stdout, "", 0))):
        result: ToolResult = await subfinder.run("target.com")

    assert len(result.data) == 2
    assert all(isinstance(s, Subdomain) for s in result.data)


@pytest.mark.asyncio
async def test_subfinder_empty_output_succeeds(subfinder: SubfinderWrapper) -> None:
    """Empty output is a valid (no subdomains found) result, not an error."""
    with patch.object(subfinder, "_exec", new=AsyncMock(return_value=("", "", 0))):
        result = await subfinder.run("target.com")

    assert result.success is True
    assert result.data == []


# ── NmapWrapper ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_nmap_scope_check_blocks_oos(nmap: NmapWrapper) -> None:
    with pytest.raises(ScopeViolationError):
        await nmap.run("evil.com")


@pytest.mark.asyncio
async def test_nmap_returns_tool_result(nmap: NmapWrapper) -> None:
    """NmapWrapper returns a ToolResult with success flag."""
    mock_nmap_output = (
        "PORT   STATE SERVICE VERSION\n"
        "80/tcp open  http    nginx 1.24\n"
        "443/tcp open https   nginx 1.24\n"
    )

    with patch.object(nmap, "_exec", new=AsyncMock(return_value=(mock_nmap_output, "", 0))):
        result = await nmap.run("target.com")

    assert isinstance(result, ToolResult)
    assert result.tool == "nmap"
    assert result.success is True


# ── NucleiWrapper ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_nuclei_scope_check_blocks_oos(nuclei: NucleiWrapper) -> None:
    with pytest.raises(ScopeViolationError):
        await nuclei.run("evil.com")


@pytest.mark.asyncio
async def test_nuclei_empty_output(nuclei: NucleiWrapper) -> None:
    """Nuclei returning no findings is valid (clean target)."""
    with patch.object(nuclei, "_exec", new=AsyncMock(return_value=("", "", 0))):
        result = await nuclei.run("target.com")

    assert result.success is True
    assert result.data == []


@pytest.mark.asyncio
async def test_nuclei_parses_json_finding(nuclei: NucleiWrapper) -> None:
    """NucleiWrapper parses JSONL nuclei output into structured findings."""
    finding = {
        "template-id": "exposed-git",
        "info": {"name": "Exposed Git Directory", "severity": "medium"},
        "matched-at": "https://target.com/.git",
        "host": "target.com",
    }
    mock_stdout = json.dumps(finding)

    with patch.object(nuclei, "_exec", new=AsyncMock(return_value=(mock_stdout, "", 0))):
        result = await nuclei.run("target.com")

    assert result.success is True
    assert len(result.data) >= 1


# ── AmassWrapper ──────────────────────────────────────────────────────────────

@pytest.fixture
def amass(scope: ScopeEnforcer) -> AmassWrapper:
    return AmassWrapper(scope)


@pytest.mark.asyncio
async def test_amass_scope_check_blocks_oos(amass: AmassWrapper) -> None:
    with pytest.raises(ScopeViolationError):
        await amass.run("evil.com")


@pytest.mark.asyncio
async def test_amass_parses_json_output(amass: AmassWrapper) -> None:
    entry = {
        "name": "api.target.com",
        "addresses": [{"ip": "1.2.3.4", "asn": 12345, "cidr": "1.2.3.0/24"}],
        "tag": "cert",
    }
    with patch.object(amass, "_exec", new=AsyncMock(return_value=(json.dumps(entry), "", 0))):
        result = await amass.run("target.com")

    assert result.success is True
    assert len(result.data) == 1
    assert result.data[0].host == "api.target.com"
    assert result.data[0].ip == "1.2.3.4"
    assert result.data[0].asn == 12345


@pytest.mark.asyncio
async def test_amass_plaintext_fallback(amass: AmassWrapper) -> None:
    """AmassWrapper falls back to plain-hostname parsing when JSON is absent."""
    plain = "sub1.target.com\nsub2.target.com\n"
    with patch.object(amass, "_exec", new=AsyncMock(return_value=(plain, "", 0))):
        result = await amass.run("target.com")

    hosts = [s.host for s in result.data]
    assert "sub1.target.com" in hosts
    assert "sub2.target.com" in hosts


# ── KatanaWrapper ─────────────────────────────────────────────────────────────

@pytest.fixture
def katana(scope: ScopeEnforcer) -> KatanaWrapper:
    return KatanaWrapper(scope)


@pytest.mark.asyncio
async def test_katana_scope_check_blocks_oos(katana: KatanaWrapper) -> None:
    with pytest.raises(ScopeViolationError):
        await katana.run("https://evil.com")


@pytest.mark.asyncio
async def test_katana_parses_json_endpoints(katana: KatanaWrapper) -> None:
    entry = {
        "timestamp": "2026-05-22T00:00:00Z",
        "request": {"method": "GET", "endpoint": "https://target.com/api/v1/users"},
        "tag": "js",
    }
    with patch.object(katana, "_exec", new=AsyncMock(return_value=(json.dumps(entry), "", 0))):
        result = await katana.run("https://target.com")

    assert result.success is True
    assert len(result.data) == 1
    assert result.data[0].url == "https://target.com/api/v1/users"
    assert result.data[0].method == "GET"


@pytest.mark.asyncio
async def test_katana_filters_oos_endpoints(katana: KatanaWrapper) -> None:
    """KatanaWrapper silently drops out-of-scope URLs from results."""
    entries = "\n".join([
        json.dumps({"request": {"method": "GET", "endpoint": "https://target.com/in"}}),
        json.dumps({"request": {"method": "GET", "endpoint": "https://evil.com/out"}}),
    ])
    with patch.object(katana, "_exec", new=AsyncMock(return_value=(entries, "", 0))):
        result = await katana.run("https://target.com")

    assert all("evil.com" not in ep.url for ep in result.data)


# ── FfufWrapper ───────────────────────────────────────────────────────────────

@pytest.fixture
def ffuf(scope: ScopeEnforcer) -> FfufWrapper:
    return FfufWrapper(scope)


@pytest.mark.asyncio
async def test_ffuf_scope_check_blocks_oos(ffuf: FfufWrapper) -> None:
    with pytest.raises(ScopeViolationError):
        await ffuf.run("https://evil.com/FUZZ")


@pytest.mark.asyncio
async def test_ffuf_parses_wrapped_json(ffuf: FfufWrapper) -> None:
    payload = {
        "results": [
            {"url": "https://target.com/admin", "input": {"FUZZ": "admin"},
             "status": 200, "length": 1234, "words": 50, "lines": 20},
        ]
    }
    with patch.object(ffuf, "_exec", new=AsyncMock(return_value=(json.dumps(payload), "", 0))):
        result = await ffuf.run("https://target.com/FUZZ")

    assert result.success is True
    assert len(result.data) == 1
    assert result.data[0].status == 200
    assert result.data[0].url == "https://target.com/admin"


@pytest.mark.asyncio
async def test_ffuf_empty_results(ffuf: FfufWrapper) -> None:
    with patch.object(ffuf, "_exec", new=AsyncMock(return_value=(json.dumps({"results": []}), "", 0))):
        result = await ffuf.run("https://target.com/FUZZ")

    assert result.data == []


# ── DalfoxWrapper ─────────────────────────────────────────────────────────────

@pytest.fixture
def dalfox(scope: ScopeEnforcer) -> DalfoxWrapper:
    return DalfoxWrapper(scope)


@pytest.mark.asyncio
async def test_dalfox_scope_check_blocks_oos(dalfox: DalfoxWrapper) -> None:
    with pytest.raises(ScopeViolationError):
        await dalfox.run("https://evil.com/search?q=test")


@pytest.mark.asyncio
async def test_dalfox_parses_xss_finding(dalfox: DalfoxWrapper) -> None:
    finding = {
        "type": "G",
        "inject_type": "inHTML-none",
        "poc": "https://target.com/search?q=<script>alert(1)</script>",
        "param": "q",
        "payload": "<script>alert(1)</script>",
    }
    with patch.object(dalfox, "_exec", new=AsyncMock(return_value=(json.dumps(finding), "", 0))):
        result = await dalfox.run("https://target.com/search?q=test")

    assert result.success is True
    assert len(result.data) == 1
    assert result.data[0].param == "q"
    assert result.data[0].cwe == "CWE-79"


# ── SqlmapWrapper ─────────────────────────────────────────────────────────────

@pytest.fixture
def sqlmap(scope: ScopeEnforcer) -> SqlmapWrapper:
    return SqlmapWrapper(scope)


@pytest.mark.asyncio
async def test_sqlmap_scope_check_blocks_oos(sqlmap: SqlmapWrapper) -> None:
    with pytest.raises(ScopeViolationError):
        await sqlmap.run("https://evil.com/item?id=1")


def test_sqlmap_is_destructive_flag(sqlmap: SqlmapWrapper) -> None:
    assert sqlmap.IS_DESTRUCTIVE is True


@pytest.mark.asyncio
async def test_sqlmap_parses_text_output(sqlmap: SqlmapWrapper) -> None:
    """SqlmapWrapper extracts findings from classic sqlmap text output."""
    text_output = (
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
        "    DBMS: MySQL\n"
    )
    with patch.object(sqlmap, "_exec", new=AsyncMock(return_value=(text_output, "", 0))):
        result = await sqlmap.run("https://target.com/item?id=1")

    assert result.success is True
    assert len(result.data) >= 1
    assert result.data[0].param == "id"
    assert "boolean" in result.data[0].injection_type.lower()


@pytest.mark.asyncio
async def test_sqlmap_empty_output(sqlmap: SqlmapWrapper) -> None:
    with patch.object(sqlmap, "_exec", new=AsyncMock(return_value=("", "", 0))):
        result = await sqlmap.run("https://target.com/item?id=1")

    assert result.data == []


# ── OPSEC mode / jitter (AsyncToolWrapper base) ───────────────────────────────

class _OpsecWrapper(AsyncToolWrapper):
    """Minimal concrete wrapper for testing OPSEC base behaviour."""

    name = "opsec_test"

    async def run(self, target: str, **kwargs) -> ToolResult:  # type: ignore[override]
        self.scope.validate_or_raise(target)
        return ToolResult(
            tool=self.name, success=True, data={}, raw="", target=target,
            command=[], duration_seconds=0.0,
        )


@pytest.mark.asyncio
async def test_opsec_jitter_not_triggered_when_disabled() -> None:
    """_maybe_jitter must NOT sleep when opsec_mode=False."""
    wrapper = _OpsecWrapper(
        ScopeEnforcer(in_scope=["target.com"], out_of_scope=[]),
        opsec_mode=False,
        request_jitter_ms=5000,
    )
    with patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
        await wrapper._maybe_jitter()
    mock_sleep.assert_not_called()


@pytest.mark.asyncio
async def test_opsec_jitter_not_triggered_when_jitter_zero() -> None:
    """_maybe_jitter must NOT sleep when request_jitter_ms=0 even if opsec_mode=True."""
    wrapper = _OpsecWrapper(
        ScopeEnforcer(in_scope=["target.com"], out_of_scope=[]),
        opsec_mode=True,
        request_jitter_ms=0,
    )
    with patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
        await wrapper._maybe_jitter()
    mock_sleep.assert_not_called()


@pytest.mark.asyncio
async def test_opsec_jitter_sleeps_when_enabled() -> None:
    """_maybe_jitter must call asyncio.sleep when opsec_mode=True and jitter > 0."""
    wrapper = _OpsecWrapper(
        ScopeEnforcer(in_scope=["target.com"], out_of_scope=[]),
        opsec_mode=True,
        request_jitter_ms=2000,
    )
    sleep_calls: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    with patch("asyncio.sleep", new=_fake_sleep):
        await wrapper._maybe_jitter()

    assert len(sleep_calls) == 1
    assert 0.0 <= sleep_calls[0] <= 2.0  # within [0, jitter_ms/1000]


@pytest.mark.asyncio
async def test_opsec_constructor_stores_params() -> None:
    """AsyncToolWrapper stores opsec_mode and request_jitter_ms from __init__."""
    scope = ScopeEnforcer(in_scope=["target.com"], out_of_scope=[])
    wrapper = _OpsecWrapper(scope, opsec_mode=True, request_jitter_ms=3000)
    assert wrapper.opsec_mode is True
    assert wrapper.request_jitter_ms == 3000


@pytest.mark.asyncio
async def test_exec_calls_maybe_jitter_before_process() -> None:
    """_exec must call _maybe_jitter before spawning the subprocess."""
    wrapper = _OpsecWrapper(
        ScopeEnforcer(in_scope=["target.com"], out_of_scope=[]),
        opsec_mode=True,
        request_jitter_ms=100,
    )

    jitter_called_before_proc: list[bool] = []
    proc_called = [False]

    async def _fake_jitter() -> None:
        # Record that jitter was called before subprocess
        jitter_called_before_proc.append(not proc_called[0])

    async def _fake_create_subprocess(*args, **kwargs):
        proc_called[0] = True
        mock = AsyncMock()
        mock.stdout.__aiter__ = AsyncMock(return_value=iter([]))
        mock.stderr.read = AsyncMock(return_value=b"")
        mock.wait = AsyncMock(return_value=0)
        mock.returncode = 0
        return mock

    with patch.object(wrapper, "_maybe_jitter", new=_fake_jitter):
        with patch("asyncio.create_subprocess_exec", new=_fake_create_subprocess):
            try:
                await wrapper._exec(["echo", "test"])
            except Exception:
                pass  # subprocess mock may not be perfect; jitter timing is what matters

    assert jitter_called_before_proc == [True]

