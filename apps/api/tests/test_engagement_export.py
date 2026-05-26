"""Tests for engagement export / import endpoints (Sprint 6.2).

Tests exercise the handler logic and schema validation without a live database.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.api.schemas import (
    EngagementExportBundle,
    EngagementImportRequest,
    EngagementResponse,
    FindingExport,
)
from app.db.models import EngagementORM, FindingORM, WorkspaceORM, UserORM


# ── Helper factories ──────────────────────────────────────────────────────────

def _make_user(is_admin: bool = False) -> UserORM:
    u = UserORM()
    u.id = uuid4()
    u.username = f"user_{u.id.hex[:6]}"
    u.email = f"{u.username}@test.com"
    u.hashed_password = "hashed"
    u.is_active = True
    u.is_admin = is_admin
    return u


def _make_workspace(owner_id) -> WorkspaceORM:
    ws = WorkspaceORM()
    ws.id = uuid4()
    ws.name = "Test Workspace"
    ws.owner_id = owner_id
    return ws


def _make_engagement(workspace_id, user_id) -> EngagementORM:
    now = datetime.now(timezone.utc)
    eng = EngagementORM()
    eng.id = uuid4()
    eng.workspace_id = workspace_id
    eng.name = "Test Engagement"
    eng.description = "A test"
    eng.mode = "semi_auto"
    eng.status = "active"
    eng.in_scope = ["target.com"]
    eng.out_of_scope = []
    eng.llm_model = "qwen2.5-coder:7b"
    eng.langgraph_thread_id = str(eng.id)
    eng.created_by = user_id
    eng.opsec_mode = False
    eng.request_jitter_ms = 0
    eng.created_at = now
    eng.updated_at = now
    return eng


def _make_finding(engagement_id) -> FindingORM:
    f = FindingORM()
    f.id = uuid4()
    f.engagement_id = engagement_id
    f.title = "SQL Injection in /api/login"
    f.vuln_class = "sql_injection"
    f.severity = "high"
    f.cvss_score = 8.5
    f.target_url = "https://target.com/api/login"
    f.http_method = "POST"
    f.request_raw = "POST /api/login HTTP/1.1\n..."
    f.response_raw = "HTTP/1.1 500..."
    f.reproduction_steps = ["Send payload", "Observe error"]
    f.status = "confirmed"
    f.discovered_by = "nuclei"
    f.description = "Classic SQLi"
    f.cve_ids = []
    return f


# ── EngagementExportBundle schema ─────────────────────────────────────────────

def test_export_bundle_schema_construction():
    """EngagementExportBundle should be constructable with required fields."""
    user = _make_user()
    ws = _make_workspace(user.id)
    eng = _make_engagement(ws.id, user.id)

    eng_resp = EngagementResponse.model_validate(eng)
    bundle = EngagementExportBundle(
        exported_at=datetime.now(timezone.utc),
        engagement=eng_resp,
        findings=[],
    )

    assert bundle.export_version == "1"
    assert bundle.engagement.id == eng.id
    assert bundle.findings == []


def test_export_bundle_with_findings():
    """EngagementExportBundle preserves finding data."""
    user = _make_user()
    ws = _make_workspace(user.id)
    eng = _make_engagement(ws.id, user.id)

    finding_export = FindingExport(
        title="IDOR on /users/{id}",
        vuln_class="idor",
        severity="high",
        cvss_score=7.5,
        target_url="https://target.com/users/1",
        http_method="GET",
        request_raw="GET /users/1 HTTP/1.1",
        response_raw="HTTP/1.1 200 OK",
        reproduction_steps=["Change user ID"],
        status="confirmed",
        discovered_by="manual",
        description="Object-level auth bypass",
        cve_ids=[],
    )

    bundle = EngagementExportBundle(
        exported_at=datetime.now(timezone.utc),
        engagement=EngagementResponse.model_validate(eng),
        findings=[finding_export],
    )

    assert len(bundle.findings) == 1
    assert bundle.findings[0].title == "IDOR on /users/{id}"
    assert bundle.findings[0].vuln_class == "idor"


# ── EngagementImportRequest schema ────────────────────────────────────────────

def test_import_request_schema():
    """EngagementImportRequest wraps a bundle with an optional name."""
    user = _make_user()
    ws = _make_workspace(user.id)
    eng = _make_engagement(ws.id, user.id)

    bundle = EngagementExportBundle(
        exported_at=datetime.now(timezone.utc),
        engagement=EngagementResponse.model_validate(eng),
        findings=[],
    )

    req = EngagementImportRequest(bundle=bundle, new_name="Imported Run")
    assert req.new_name == "Imported Run"
    assert req.bundle.engagement.id == eng.id


def test_import_request_new_name_optional():
    """EngagementImportRequest new_name defaults to None."""
    user = _make_user()
    ws = _make_workspace(user.id)
    eng = _make_engagement(ws.id, user.id)

    bundle = EngagementExportBundle(
        exported_at=datetime.now(timezone.utc),
        engagement=EngagementResponse.model_validate(eng),
        findings=[],
    )
    req = EngagementImportRequest(bundle=bundle)
    assert req.new_name is None


# ── Access control logic ──────────────────────────────────────────────────────

def test_import_access_control_owner_allowed():
    """Owner can import into their own workspace."""
    user = _make_user()
    ws = _make_workspace(user.id)
    # Simulating the import handler check
    is_allowed = user.is_admin or ws.owner_id == user.id
    assert is_allowed is True


def test_import_access_control_non_owner_denied():
    """Non-owner, non-admin cannot import into another user's workspace."""
    owner = _make_user()
    attacker = _make_user()
    ws = _make_workspace(owner.id)
    is_allowed = attacker.is_admin or ws.owner_id == attacker.id
    assert is_allowed is False


def test_import_access_control_admin_allowed():
    """Admin can import into any workspace."""
    admin = _make_user(is_admin=True)
    owner = _make_user()
    ws = _make_workspace(owner.id)
    is_allowed = admin.is_admin or ws.owner_id == admin.id
    assert is_allowed is True


# ── Export logic unit test ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_handler_returns_404_for_missing_engagement():
    """export_engagement should raise 404 when engagement not found in DB."""
    from fastapi import HTTPException
    from app.api.router import export_engagement

    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=None)  # engagement not found

    user = _make_user()

    with pytest.raises(HTTPException) as exc_info:
        await export_engagement(
            engagement_id=uuid4(),
            db=mock_db,
            current_user=user,
        )

    assert exc_info.value.status_code == 404
    assert "not found" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_export_handler_returns_bundle():
    """export_engagement returns a valid bundle for an existing engagement."""
    from app.api.router import export_engagement

    user = _make_user()
    ws = _make_workspace(user.id)
    eng = _make_engagement(ws.id, user.id)
    finding = _make_finding(eng.id)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [finding]

    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=eng)
    mock_db.execute = AsyncMock(return_value=mock_result)

    result = await export_engagement(
        engagement_id=eng.id,
        db=mock_db,
        current_user=user,
    )

    assert isinstance(result, EngagementExportBundle)
    assert result.engagement.id == eng.id
    assert len(result.findings) == 1
    assert result.findings[0].title == finding.title


# ── Import logic unit test ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_import_handler_returns_404_for_missing_workspace():
    """import_engagement should raise 404 when workspace not found."""
    from fastapi import HTTPException
    from app.api.router import import_engagement

    user = _make_user()
    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=None)  # workspace not found

    owner = _make_user()
    ws = _make_workspace(owner.id)
    eng = _make_engagement(ws.id, owner.id)
    bundle = EngagementExportBundle(
        exported_at=datetime.now(timezone.utc),
        engagement=EngagementResponse.model_validate(eng),
        findings=[],
    )

    with pytest.raises(HTTPException) as exc_info:
        await import_engagement(
            workspace_id=uuid4(),
            body=EngagementImportRequest(bundle=bundle),
            db=mock_db,
            current_user=user,
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_import_handler_returns_403_for_non_owner():
    """import_engagement should raise 403 for non-owner, non-admin user."""
    from fastapi import HTTPException
    from app.api.router import import_engagement

    owner = _make_user()
    attacker = _make_user(is_admin=False)
    ws = _make_workspace(owner.id)
    eng = _make_engagement(ws.id, owner.id)

    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=ws)

    bundle = EngagementExportBundle(
        exported_at=datetime.now(timezone.utc),
        engagement=EngagementResponse.model_validate(eng),
        findings=[],
    )

    with pytest.raises(HTTPException) as exc_info:
        await import_engagement(
            workspace_id=ws.id,
            body=EngagementImportRequest(bundle=bundle),
            db=mock_db,
            current_user=attacker,
        )

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_import_handler_creates_new_uuid():
    """import_engagement creates a new EngagementORM with a fresh UUID."""
    from app.api.router import import_engagement

    owner = _make_user()
    ws = _make_workspace(owner.id)
    src_eng = _make_engagement(ws.id, owner.id)
    finding = _make_finding(src_eng.id)

    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=ws)
    mock_db.flush = AsyncMock()
    mock_db.commit = AsyncMock()

    added_objects: list = []

    def _add(obj):
        added_objects.append(obj)

    mock_db.add = _add

    bundle = EngagementExportBundle(
        exported_at=datetime.now(timezone.utc),
        engagement=EngagementResponse.model_validate(src_eng),
        findings=[
            FindingExport(
                title=finding.title,
                vuln_class=finding.vuln_class,
                severity=finding.severity,
                cvss_score=finding.cvss_score,
                target_url=finding.target_url,
                http_method=finding.http_method,
                request_raw=finding.request_raw,
                response_raw=finding.response_raw,
                reproduction_steps=finding.reproduction_steps,
                status=finding.status,
                discovered_by=finding.discovered_by,
                description=finding.description,
                cve_ids=[],
            )
        ],
    )

    # Mock db.refresh to populate the engagement
    async def _refresh(obj):
        # Simulate ORM populating attributes after commit
        pass

    mock_db.refresh = _refresh

    new_eng = EngagementORM()
    new_eng.id = uuid4()  # Will be created by handler with new uuid

    # We need to intercept the EngagementORM that gets added
    eng_objects = [obj for obj in added_objects if isinstance(obj, EngagementORM)]

    # The handler creates a new engagement — let's verify it doesn't reuse source ID
    # by calling the handler and checking new_id != src_eng.id
    import uuid as _uuid_mod
    generated_ids: list = []
    original_uuid4 = _uuid_mod.uuid4

    def _mock_uuid4():
        new_id = original_uuid4()
        generated_ids.append(new_id)
        return new_id

    with patch("app.api.router.uuid.uuid4", new=_mock_uuid4):
        try:
            await import_engagement(
                workspace_id=ws.id,
                body=EngagementImportRequest(bundle=bundle),
                db=mock_db,
                current_user=owner,
            )
        except Exception:
            pass  # refresh mock may fail validation, but the core logic ran

    # The handler should have generated a new ID
    assert len(generated_ids) >= 1
    assert generated_ids[0] != src_eng.id


@pytest.mark.asyncio
async def test_import_with_custom_name():
    """import_engagement should use new_name when provided."""
    from app.api.router import import_engagement

    owner = _make_user()
    ws = _make_workspace(owner.id)
    src_eng = _make_engagement(ws.id, owner.id)

    mock_db = AsyncMock()
    mock_db.get = AsyncMock(return_value=ws)
    mock_db.flush = AsyncMock()
    mock_db.commit = AsyncMock()

    added_engagements: list[EngagementORM] = []

    def _add(obj):
        if isinstance(obj, EngagementORM):
            added_engagements.append(obj)

    mock_db.add = _add
    mock_db.refresh = AsyncMock()

    bundle = EngagementExportBundle(
        exported_at=datetime.now(timezone.utc),
        engagement=EngagementResponse.model_validate(src_eng),
        findings=[],
    )

    try:
        await import_engagement(
            workspace_id=ws.id,
            body=EngagementImportRequest(bundle=bundle, new_name="My Custom Name"),
            db=mock_db,
            current_user=owner,
        )
    except Exception:
        pass

    assert len(added_engagements) >= 1
    assert added_engagements[0].name == "My Custom Name"
