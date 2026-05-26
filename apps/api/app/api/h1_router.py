"""Task 5.4 — HackerOne program scope import endpoint.

GET /api/v1/h1/programs/{handle}/scope
  → Returns in_scope, out_of_scope, and notes for a public H1 program.
  → Authenticated endpoint (any logged-in user).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.core.deps import get_current_user
from app.db.models import UserORM

router = APIRouter(prefix="/api/v1/h1", tags=["hackerone"])


@router.get(
    "/programs/{handle}/scope",
    summary="Get HackerOne program scope",
    description="Fetch the current in-scope and out-of-scope targets for a HackerOne bug bounty program by its handle.",
)
async def get_h1_program_scope(
    handle: str,
    _: UserORM = Depends(get_current_user),
) -> dict:
    """
    Fetch scope for a public HackerOne bug bounty program.

    Returns `in_scope` and `out_of_scope` lists ready to paste into the
    Engagement create form, plus `notes` for non-domain asset types.

    **Example:** `GET /api/v1/h1/programs/shopify/scope`
    """
    # Sanitise handle — only alphanumeric + hyphens
    import re
    if not re.fullmatch(r"[a-zA-Z0-9_\-]{1,100}", handle):
        raise HTTPException(status_code=422, detail="Invalid program handle format.")

    try:
        from pentra_knowledge.services.h1_program_sync import H1ProgramSync

        syncer = H1ProgramSync()
        h1_scope = await syncer.fetch_program_scope(handle)
        engagement_scope = syncer.convert_to_engagement_scope(h1_scope)

        return {
            "program_name": h1_scope.program_name,
            "program_url": h1_scope.program_url,
            "in_scope": engagement_scope.in_scope,
            "out_of_scope": engagement_scope.out_of_scope,
            "notes": engagement_scope.notes,
            "raw_in_scope_count": len(h1_scope.in_scope),
            "raw_out_of_scope_count": len(h1_scope.out_of_scope),
        }

    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=502,
            detail=f"Failed to fetch H1 scope: {exc}",
        ) from exc
