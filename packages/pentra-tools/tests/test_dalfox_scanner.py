from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from pentra_tools.scanners.dalfox_scanner import DalfoxScanner, XSSFinding


@pytest.mark.asyncio
async def test_scan_skips_when_binary_missing():
    with patch("shutil.which", return_value=None):
        assert await DalfoxScanner().scan("https://example.com/?q=x") == []


def test_parse_output_file_list():
    data = '[{"url":"https://example.com/?q=x","param":"q","payload":"<x>","type":"reflected","evidence":"poc"}]'
    with patch("os.path.exists", return_value=True), patch("builtins.open", mock_open(read_data=data)):
        findings = DalfoxScanner()._parse_output_file("/tmp/out.json", "https://fallback")

    assert findings == [
        XSSFinding(
            url="https://example.com/?q=x",
            param="q",
            payload="<x>",
            xss_type="reflected",
            evidence="poc",
        )
    ]


def test_parse_output_file_single_object_defaults():
    data = '{"payload":"<svg/onload=1>"}'
    with patch("os.path.exists", return_value=True), patch("builtins.open", mock_open(read_data=data)):
        findings = DalfoxScanner()._parse_output_file("/tmp/out.json", "https://fallback")

    assert findings[0].url == "https://fallback"
    assert findings[0].param == "unknown"
    assert findings[0].payload == "<svg/onload=1>"


def test_parse_output_file_invalid_json():
    with patch("os.path.exists", return_value=True), patch("builtins.open", mock_open(read_data="not json")):
        assert DalfoxScanner()._parse_output_file("/tmp/out.json", "https://fallback") == []


@pytest.mark.asyncio
async def test_scan_success_reads_output():
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(b"", b""))
    data = '[{"url":"https://example.com/?q=x","param":"q","payload":"<x>"}]'
    with (
        patch("shutil.which", return_value="/usr/bin/dalfox"),
        patch("tempfile.NamedTemporaryFile") as tmp,
        patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
        patch("os.path.exists", return_value=True),
        patch("builtins.open", mock_open(read_data=data)),
        patch("os.unlink"),
    ):
        tmp.return_value.__enter__.return_value.name = "/tmp/out.json"
        findings = await DalfoxScanner().scan("https://example.com/?q=x")

    assert len(findings) == 1
    assert findings[0].param == "q"


@pytest.mark.asyncio
async def test_scan_timeout_returns_empty():
    proc = MagicMock()
    proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
    proc.kill = MagicMock()
    with (
        patch("shutil.which", return_value="/usr/bin/dalfox"),
        patch("tempfile.NamedTemporaryFile") as tmp,
        patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
        patch("os.path.exists", return_value=False),
    ):
        tmp.return_value.__enter__.return_value.name = "/tmp/out.json"
        findings = await DalfoxScanner().scan("https://example.com/?q=x", timeout=1)

    assert findings == []
    proc.kill.assert_called_once()


@pytest.mark.asyncio
async def test_scan_batch_flattens_results():
    scanner = DalfoxScanner()
    scanner.scan = AsyncMock(  # type: ignore[method-assign]
        side_effect=[
            [XSSFinding(url="https://a.test", param="q", payload="a")],
            [XSSFinding(url="https://b.test", param="q", payload="b")],
        ]
    )

    findings = await scanner.scan_batch(["https://a.test", "https://b.test"])

    assert [finding.payload for finding in findings] == ["a", "b"]
