from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
from app.middleware.auth import get_current_user_optional
from app.services.intelligence_library import IntelligenceLibrary

router = APIRouter()


@router.get("/patterns")
async def list_patterns(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
) -> Dict[str, Any]:
    lib = IntelligenceLibrary()
    return await lib.list_patterns(page=page, size=size)


@router.get("/recall")
async def recall_patterns(
    fingerprint: str = Query(..., description="Target fingerprint (tech stack + service string)"),
    n: int = Query(default=5, ge=1, le=20),
) -> Dict[str, Any]:
    lib = IntelligenceLibrary()
    patterns = await lib.recall_patterns(target_fingerprint=fingerprint, n=n)
    return {"fingerprint": fingerprint, "results": patterns, "count": len(patterns)}


@router.post("/{session_id}/index")
async def index_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    from sqlalchemy import select
    from app.models.session import ResearchSession

    result = await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Session not found")

    lib = IntelligenceLibrary()
    await lib.store_session_patterns(str(session_id), db)
    return {"status": "indexed", "session_id": str(session_id)}


# ---------------------------------------------------------------------------
# T129/T130 — Threat Intelligence endpoints
# ---------------------------------------------------------------------------

@router.get("/threats")
async def list_threats(
    session_id: Optional[str] = Query(default=None, description="Optional session ID context"),
    _user: Optional[Dict[str, Any]] = Depends(get_current_user_optional),
) -> Dict[str, Any]:
    """Return CVEs matched to active Neo4j service nodes (T130)."""
    from app.services.cve_variant_matcher import get_threats_for_session
    threats = await get_threats_for_session(session_id)
    return {"threats": threats, "count": len(threats)}


@router.post("/threats/ingest")
async def trigger_ingest(
    background_tasks: BackgroundTasks,
    since_days: int = Query(default=1, ge=1, le=30, description="Ingest CVEs from last N days"),
    _user: Optional[Dict[str, Any]] = Depends(get_current_user_optional),
) -> Dict[str, Any]:
    """Manually trigger the threat intel ingestor (T129)."""
    from app.services.threat_intel_ingestor import run_ingestor
    background_tasks.add_task(run_ingestor, since_days)
    return {"status": "triggered", "since_days": since_days}


@router.post("/threats/{cve_id}/replay")
async def trigger_replay(
    cve_id: str,
    session_id: Optional[str] = Query(default=None),
    _user: Optional[Dict[str, Any]] = Depends(get_current_user_optional),
) -> Dict[str, Any]:
    """T131 — Spawn a replica and run the CVE PoC via sameday replay."""
    from app.services.cve_variant_matcher import run_sameday_replay
    result = await run_sameday_replay(cve_id, session_id)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "replay failed"))
    return result
