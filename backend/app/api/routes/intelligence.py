from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
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
