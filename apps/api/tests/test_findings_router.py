"""Tests for finding list, patch, and knowledge submission handlers."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.router import (
    get_recent_findings,
    list_findings,
    patch_finding,
    submit_finding_to_knowledge,
)
from app.api.schemas import FindingPatch, KnowledgeInjectRequest
from app.db.models import FindingORM, UserORM


def _make_user(is_admin: bool = False) -> UserORM:
    user = UserORM()
    user.id = uuid4()
    user.username = f"user_{user.id.hex[:6]}"
    user.email = f"{user.username}@test.local"
    user.hashed_password = "hashed"
    user.is_active = True
    user.is_admin = is_admin
    return user


def _make_finding(engagement_id=None, status: str = "open") -> FindingORM:
    finding = FindingORM()
    finding.id = uuid4()
    finding.engagement_id = engagement_id or uuid4()
    finding.title = "SQL Injection in search"
    finding.vuln_class = "sql_injection"
    finding.severity = "high"
    finding.cvss_score = 8.1
    finding.cvss_vector = None
    finding.target_url = "https://acme.test/search?q=1"
    finding.http_method = "GET"
    finding.status = status
    finding.discovered_by = "agent"
    finding.discovered_at = datetime.now(timezone.utc)
    finding.description = "Confirmed SQLi"
    finding.cve_ids = []
    finding.cve_data = None
    finding.chains = None
    finding.impact = None
    finding.remediation = None
    finding.reproduction_steps = ["Send payload", "Observe SQL error"]
    return finding


def _db_with_scalars(items: list[object]) -> AsyncMock:
    db = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    db.execute.return_value = result
    return db


@pytest.mark.asyncio
async def test_list_findings_returns_engagement_findings():
    user = _make_user()
    engagement_id = uuid4()
    finding = _make_finding(engagement_id)
    db = _db_with_scalars([finding])

    result = await list_findings(engagement_id=engagement_id, db=db, current_user=user)

    assert len(result) == 1
    assert result[0].id == finding.id
    assert result[0].engagement_id == engagement_id
    assert result[0].title == "SQL Injection in search"


@pytest.mark.asyncio
async def test_list_findings_returns_empty_list():
    user = _make_user()
    db = _db_with_scalars([])

    result = await list_findings(engagement_id=uuid4(), db=db, current_user=user)

    assert result == []


@pytest.mark.asyncio
async def test_get_recent_findings_applies_limit_and_returns_models():
    user = _make_user()
    finding = _make_finding()
    db = _db_with_scalars([finding])

    result = await get_recent_findings(limit=5, db=db, current_user=user)

    assert len(result) == 1
    assert result[0].id == finding.id
    assert result[0].severity == "high"
    db.execute.assert_called_once()


@pytest.mark.asyncio
async def test_patch_finding_returns_404_when_missing():
    user = _make_user()
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)

    with pytest.raises(HTTPException) as exc_info:
        await patch_finding(
            finding_id=uuid4(),
            body=FindingPatch(status="confirmed"),
            db=db,
            current_user=user,
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_patch_finding_updates_status_and_writes_audit():
    user = _make_user()
    finding = _make_finding(status="open")
    db = AsyncMock()
    db.add = MagicMock()
    db.get = AsyncMock(return_value=finding)

    result = await patch_finding(
        finding_id=finding.id,
        body=FindingPatch(status="false_positive"),
        db=db,
        current_user=user,
    )

    assert result.status == "false_positive"
    assert finding.status == "false_positive"
    db.add.assert_called_once()
    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(finding)


@pytest.mark.asyncio
async def test_submit_finding_to_knowledge_returns_404_when_missing():
    user = _make_user()
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)

    with pytest.raises(HTTPException) as exc_info:
        await submit_finding_to_knowledge(
            finding_id=uuid4(),
            body=KnowledgeInjectRequest(),
            db=db,
            current_user=user,
        )

    assert exc_info.value.status_code == 404


class _FakeKBContext:
    def __init__(self) -> None:
        self.db = AsyncMock()

    async def __aenter__(self):
        return self.db

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _install_fake_kb_modules(repo_factory):
    def async_session_local():
        return lambda: _FakeKBContext()

    kb_base = SimpleNamespace(AsyncSessionLocal=async_session_local)
    kb_repo = SimpleNamespace(KnowledgeRepository=repo_factory)
    return patch.dict(
        "sys.modules",
        {
            "pentra_knowledge.db.base": kb_base,
            "pentra_knowledge.db.repository": kb_repo,
        },
    )


@pytest.mark.asyncio
async def test_submit_finding_to_knowledge_returns_existing_record():
    user = _make_user()
    finding = _make_finding(status="confirmed")
    db = AsyncMock()
    db.get = AsyncMock(return_value=finding)
    existing_id = uuid4()

    class Repo:
        def __init__(self, kb_db):
            self.kb_db = kb_db

        async def get_by_source_id(self, source_id: str):
            return SimpleNamespace(id=existing_id)

    with _install_fake_kb_modules(Repo):
        result = await submit_finding_to_knowledge(
            finding_id=finding.id,
            body=KnowledgeInjectRequest(),
            db=db,
            current_user=user,
        )

    assert result.knowledge_record_id == str(existing_id)
    assert result.message == "Already exists in knowledge base"
    db.add.assert_not_called()
    db.commit.assert_not_called()


@pytest.mark.asyncio
async def test_submit_finding_to_knowledge_creates_record_and_audit_log():
    user = _make_user()
    finding = _make_finding(status="confirmed")
    db = AsyncMock()
    db.add = MagicMock()
    db.get = AsyncMock(return_value=finding)
    created_id = uuid4()
    created_payloads: list[dict] = []

    class Repo:
        def __init__(self, kb_db):
            self.kb_db = kb_db

        async def get_by_source_id(self, source_id: str):
            return None

        async def create(self, record_data: dict):
            created_payloads.append(record_data)
            return SimpleNamespace(id=created_id)

    with _install_fake_kb_modules(Repo):
        result = await submit_finding_to_knowledge(
            finding_id=finding.id,
            body=KnowledgeInjectRequest(
                key_insight="Trust boundary bypass",
                technique="Boolean SQLi",
                tags=["sqli", "confirmed"],
            ),
            db=db,
            current_user=user,
        )

    assert result.knowledge_record_id == str(created_id)
    assert result.message == "Finding submitted to knowledge base successfully"
    assert created_payloads[0]["title"] == finding.title
    assert created_payloads[0]["attack_technique"] == "Boolean SQLi"
    assert created_payloads[0]["key_insight"] == "Trust boundary bypass"
    assert created_payloads[0]["pentra_tags"] == ["finding", "confirmed", "sqli", "confirmed"]
    db.add.assert_called_once()
    db.commit.assert_called_once()
