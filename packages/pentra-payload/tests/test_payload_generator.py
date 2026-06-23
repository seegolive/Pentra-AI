"""Tests for PayloadGenerator — context-aware LLM payload generation.

LLM calls are mocked via httpx. Pure-Python helpers tested without mocks.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentra_payload.generator import PayloadGenerator
from pentra_payload.models import Payload, PayloadContext, PayloadGenerateResponse
from pentra_shared.types.vuln_class import VulnClass


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _ctx(**kwargs) -> PayloadContext:
    defaults = dict(
        vuln_class=VulnClass.SQLI,
        target_url="https://target.com/login",
        parameter_name="username",
        parameter_value="alice",
        tech_stack=["django", "postgresql"],
    )
    return PayloadContext(**{**defaults, **kwargs})


def _gen() -> PayloadGenerator:
    return PayloadGenerator(ollama_url="http://localhost:11434", model="qwen2.5-coder:7b")


def _llm_response(payloads: list[dict]) -> dict:
    """Build a minimal Ollama chat response dict."""
    return {"message": {"content": json.dumps(payloads)}}


# ── Model validation ──────────────────────────────────────────────────────────

def test_payload_context_defaults():
    ctx = PayloadContext(
        vuln_class=VulnClass.XSS_REFLECTED,
        target_url="https://t.com/search",
        parameter_name="q",
        parameter_value="hello",
    )
    assert ctx.parameter_position == "query"
    assert ctx.http_method == "GET"
    assert ctx.tech_stack == []
    assert ctx.additional_context == ""


def test_payload_defaults():
    p = Payload(value="'--", rationale="Classic SQLi comment terminator")
    assert p.severity_hint == "medium"
    assert p.requires_encoding is False


def test_payload_all_fields():
    p = Payload(
        value="<script>alert(1)</script>",
        rationale="Stored XSS",
        severity_hint="high",
        requires_encoding=True,
    )
    assert p.value == "<script>alert(1)</script>"
    assert p.requires_encoding is True


def test_payload_context_position_choices():
    for pos in ("path", "query", "body", "header", "cookie"):
        ctx = _ctx(parameter_position=pos)
        assert ctx.parameter_position == pos


# ── PayloadGenerator._format_knowledge ───────────────────────────────────────

def test_format_knowledge_empty_returns_placeholder():
    gen = _gen()
    result = gen._format_knowledge([])
    assert "No knowledge base records available" in result


def test_format_knowledge_single_record():
    gen = _gen()
    records = [{"vuln_class": "sqli", "title": "SQLi in login", "attack_technique": "UNION", "key_insight": "Use UNION-based extraction"}]
    result = gen._format_knowledge(records)
    assert "sqli" in result
    assert "SQLi in login" in result
    assert "UNION" in result
    assert "key_insight" not in result.lower() or "extraction" in result


def test_format_knowledge_caps_at_8():
    gen = _gen()
    records = [{"vuln_class": "xss", "title": f"Bug {i}", "attack_technique": "reflect", "key_insight": "test"} for i in range(15)]
    result = gen._format_knowledge(records)
    # only 8 entries numbered 1–8 should appear
    assert "8." in result
    assert "9." not in result


def test_format_knowledge_handles_missing_fields():
    gen = _gen()
    records = [{}]  # completely empty record
    result = gen._format_knowledge(records)
    assert "1." in result  # still emits entry, just with empty values


# ── PayloadGenerator._parse_response ─────────────────────────────────────────

def test_parse_response_valid_json():
    gen = _gen()
    raw = json.dumps([{"value": "' OR 1=1--", "rationale": "Classic bypass", "severity_hint": "critical", "requires_encoding": False}])
    result = gen._parse_response(raw, expected_count=10)
    assert len(result) == 1
    assert result[0].value == "' OR 1=1--"
    assert result[0].severity_hint == "critical"
    assert result[0].requires_encoding is False


def test_parse_response_strips_markdown_fences():
    gen = _gen()
    raw = '```json\n[{"value": "test", "rationale": "r", "severity_hint": "low", "requires_encoding": false}]\n```'
    result = gen._parse_response(raw, expected_count=10)
    assert len(result) == 1
    assert result[0].value == "test"


def test_parse_response_strips_plain_fences():
    gen = _gen()
    raw = '```\n[{"value": "x", "rationale": "r", "severity_hint": "medium", "requires_encoding": false}]\n```'
    result = gen._parse_response(raw, expected_count=10)
    assert len(result) == 1


def test_parse_response_invalid_json_returns_empty():
    gen = _gen()
    result = gen._parse_response("this is not json", expected_count=10)
    assert result == []


def test_parse_response_no_array_returns_empty():
    gen = _gen()
    result = gen._parse_response('{"error": "LLM confused"}', expected_count=10)
    assert result == []


def test_parse_response_respects_expected_count():
    gen = _gen()
    items = [{"value": f"payload{i}", "rationale": "r", "severity_hint": "medium", "requires_encoding": False} for i in range(20)]
    result = gen._parse_response(json.dumps(items), expected_count=5)
    assert len(result) == 5


def test_parse_response_skips_invalid_items():
    gen = _gen()
    raw = json.dumps([
        {"value": "good", "rationale": "ok", "severity_hint": "high", "requires_encoding": False},
        None,   # invalid item
        "not a dict",
    ])
    result = gen._parse_response(raw, expected_count=10)
    # should have at least the first valid item
    assert any(p.value == "good" for p in result)


def test_parse_response_default_severity():
    gen = _gen()
    raw = json.dumps([{"value": "x", "rationale": "r"}])
    result = gen._parse_response(raw, expected_count=10)
    assert len(result) == 1
    assert result[0].severity_hint == "medium"


def test_parse_response_requires_encoding_default_false():
    gen = _gen()
    raw = json.dumps([{"value": "test", "rationale": "r", "severity_hint": "low"}])
    result = gen._parse_response(raw, expected_count=10)
    assert result[0].requires_encoding is False


# ── PayloadGenerator.generate — mocked httpx ─────────────────────────────────

@pytest.mark.asyncio
async def test_generate_returns_payload_list():
    gen = _gen()
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = _llm_response([
        {"value": "' OR 1=1--", "rationale": "bypass", "severity_hint": "critical", "requires_encoding": False},
        {"value": "' UNION SELECT NULL--", "rationale": "union", "severity_hint": "high", "requires_encoding": False},
    ])

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("pentra_payload.generator.httpx.AsyncClient", return_value=mock_client):
        payloads = await gen.generate(_ctx(), knowledge_records=[], count=2)

    assert len(payloads) == 2
    assert payloads[0].value == "' OR 1=1--"
    assert payloads[1].severity_hint == "high"


@pytest.mark.asyncio
async def test_generate_caps_count_at_50():
    gen = _gen()
    items = [{"value": f"p{i}", "rationale": "r", "severity_hint": "low", "requires_encoding": False} for i in range(60)]
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = _llm_response(items)

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("pentra_payload.generator.httpx.AsyncClient", return_value=mock_client):
        payloads = await gen.generate(_ctx(), knowledge_records=[], count=999)

    assert len(payloads) <= 50


@pytest.mark.asyncio
async def test_generate_includes_knowledge_in_prompt():
    gen = _gen()
    knowledge = [{"vuln_class": "sqli", "title": "H1 SQLi", "attack_technique": "error-based", "key_insight": "dbms version leak"}]

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = _llm_response([{"value": "x", "rationale": "r", "severity_hint": "low", "requires_encoding": False}])

    captured: list[dict] = []

    async def fake_post(url, json=None, **kwargs):
        captured.append(json or {})
        return mock_resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = fake_post

    with patch("pentra_payload.generator.httpx.AsyncClient", return_value=mock_client):
        await gen.generate(_ctx(), knowledge_records=knowledge, count=1)

    assert captured
    user_content = captured[0]["messages"][1]["content"]
    assert "H1 SQLi" in user_content


@pytest.mark.asyncio
async def test_generate_with_tech_stack_in_prompt():
    gen = _gen()
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = _llm_response([])

    captured: list[dict] = []

    async def fake_post(url, json=None, **kwargs):
        captured.append(json or {})
        return mock_resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = fake_post

    ctx = _ctx(tech_stack=["rails", "mysql"])
    with patch("pentra_payload.generator.httpx.AsyncClient", return_value=mock_client):
        await gen.generate(ctx, knowledge_records=[], count=1)

    user_content = captured[0]["messages"][1]["content"]
    assert "rails" in user_content
    assert "mysql" in user_content


@pytest.mark.asyncio
async def test_generate_empty_llm_response_returns_empty():
    gen = _gen()
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"message": {"content": "[]"}}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("pentra_payload.generator.httpx.AsyncClient", return_value=mock_client):
        payloads = await gen.generate(_ctx(), knowledge_records=[], count=5)

    assert payloads == []


@pytest.mark.asyncio
async def test_generate_llm_returns_garbage_gives_empty():
    gen = _gen()
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"message": {"content": "Sorry I cannot help with that."}}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("pentra_payload.generator.httpx.AsyncClient", return_value=mock_client):
        payloads = await gen.generate(_ctx(), knowledge_records=[], count=5)

    assert payloads == []


# ── PayloadGenerateResponse model ─────────────────────────────────────────────

def test_payload_generate_response_model():
    resp = PayloadGenerateResponse(
        payloads=[Payload(value="test", rationale="r")],
        knowledge_used=3,
        model_used="qwen2.5-coder:7b",
    )
    assert len(resp.payloads) == 1
    assert resp.knowledge_used == 3
    assert resp.model_used == "qwen2.5-coder:7b"
