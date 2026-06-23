from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from pentra_tools.scanners.crlfuzz_scanner import CRLFFinding, CRLFuzzScanner


@pytest.mark.asyncio
async def test_scan_skips_when_binary_missing():
    with patch("shutil.which", return_value=None):
        assert await CRLFuzzScanner().scan("https://example.com") == []


@pytest.mark.asyncio
async def test_scan_parses_output_file():
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(b"", b""))
    with (
        patch("shutil.which", return_value="/usr/bin/crlfuzz"),
        patch("tempfile.NamedTemporaryFile") as tmp,
        patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
        patch("os.path.exists", return_value=True),
        patch("builtins.open", mock_open(read_data="https://example.com/%0d%0aX: y\nnoise\n")),
        patch("os.unlink"),
    ):
        tmp.return_value.__enter__.return_value.name = "/tmp/out.txt"
        findings = await CRLFuzzScanner().scan("https://example.com")

    assert findings == [
        CRLFFinding(
            url="https://example.com",
            payload="https://example.com/%0d%0aX: y",
            evidence="CRLF injection found: https://example.com/%0d%0aX: y",
        )
    ]


@pytest.mark.asyncio
async def test_scan_timeout_returns_empty():
    proc = MagicMock()
    proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
    proc.kill = MagicMock()
    with (
        patch("shutil.which", return_value="/usr/bin/crlfuzz"),
        patch("tempfile.NamedTemporaryFile") as tmp,
        patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
        patch("os.path.exists", return_value=False),
    ):
        tmp.return_value.__enter__.return_value.name = "/tmp/out.txt"
        findings = await CRLFuzzScanner().scan("https://example.com", timeout=1)

    assert findings == []
    proc.kill.assert_called_once()


@pytest.mark.asyncio
async def test_scan_handles_subprocess_error():
    with (
        patch("shutil.which", return_value="/usr/bin/crlfuzz"),
        patch("tempfile.NamedTemporaryFile") as tmp,
        patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=RuntimeError("boom"))),
        patch("os.path.exists", return_value=False),
    ):
        tmp.return_value.__enter__.return_value.name = "/tmp/out.txt"
        assert await CRLFuzzScanner().scan("https://example.com") == []


@pytest.mark.asyncio
async def test_scan_batch_flattens_results():
    scanner = CRLFuzzScanner()
    scanner.scan = AsyncMock(  # type: ignore[method-assign]
        side_effect=[
            [CRLFFinding(url="https://a.test", payload="a")],
            [CRLFFinding(url="https://b.test", payload="b")],
        ]
    )

    findings = await scanner.scan_batch(["https://a.test", "https://b.test"])

    assert [finding.payload for finding in findings] == ["a", "b"]


@pytest.mark.asyncio
async def test_scan_batch_empty_input():
    assert await CRLFuzzScanner().scan_batch([]) == []
