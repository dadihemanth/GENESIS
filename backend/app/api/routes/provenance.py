"""T103 provenance and T97 tool synthesis API routes.

GET  /provenance/{finding_id}          — get provenance chain for a finding
POST /provenance/{session_id}/record   — trigger provenance recording for all confirmed findings
GET  /provenance/search                — semantic search over recorded provenances
POST /tools/synthesize                 — T97: synthesize a new tool from description
GET  /tools/synthesized                — search existing synthesized tools
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db as get_pg_db
from app.services.provenance_recorder import (
    get_provenance,
    record_provenance,
    search_similar_provenances,
)
from app.services.tool_synthesizer import search_synthesized_tools, synthesize_tool

router = APIRouter()


# ---------------------------------------------------------------------------
# Provenance endpoints
# ---------------------------------------------------------------------------

@router.get("/{finding_id}")
async def get_finding_provenance(
    finding_id: str,
    session_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Return the full provenance chain for a confirmed finding."""
    result = await get_provenance(finding_id, session_id=session_id or "")
    if result is None:
        raise HTTPException(status_code=404, detail="Provenance not recorded for this finding")
    return {"finding_id": finding_id, "provenance": result}


@router.post("/{session_id}/record")
async def record_session_provenances(
    session_id: str,
    db: AsyncSession = Depends(get_pg_db),
) -> Dict[str, Any]:
    """Record provenance chains for all confirmed findings in a session."""
    from sqlalchemy import select
    from app.models.vulnerability import Vulnerability

    result = await db.execute(
        select(Vulnerability).where(
            Vulnerability.session_id == session_id,  # type: ignore[arg-type]
            Vulnerability.verification_status.in_(["confirmed", "exploited"]),
        )
    )
    vulns = result.scalars().all()

    recorded: List[str] = []
    failed: List[str] = []
    for v in vulns:
        prov = await record_provenance(
            session_id=session_id,
            finding_id=str(v.id),
            finding_title=v.title or "",
            finding_severity=v.severity or "",
        )
        if prov:
            recorded.append(str(v.id))
        else:
            failed.append(str(v.id))

    return {
        "session_id": session_id,
        "recorded": recorded,
        "failed": failed,
        "total": len(vulns),
    }


@router.get("/search")
async def search_provenances(
    q: str,
    n_results: int = Query(default=5, ge=1, le=20),
) -> Dict[str, Any]:
    """Semantic search over recorded provenance chains."""
    results = await search_similar_provenances(q, n_results=n_results)
    return {"query": q, "results": results, "count": len(results)}


# ---------------------------------------------------------------------------
# Tool synthesis endpoints (T97)
# ---------------------------------------------------------------------------

class SynthesizeToolRequest(BaseModel):
    description: str
    example_input: Optional[Dict[str, Any]] = None
    example_output: Optional[Dict[str, Any]] = None
    capability_tag: str = "custom"
    session_id: str = ""


@router.post("/tools/synthesize")
async def synthesize_new_tool(req: SynthesizeToolRequest) -> Dict[str, Any]:
    """T97 — synthesize and register a new tool from a natural-language description."""
    from app.services.llm_providers import build_llm_client
    from app.database.postgres import AsyncSessionLocal
    from sqlalchemy import select as _select
    from app.models.session import AppSettings as _AppSettingsRow
    async with AsyncSessionLocal() as _db:
        _rows = await _db.execute(_select(_AppSettingsRow))
        _app_settings = {r.key: r.value for r in _rows.scalars().all()}
    client = build_llm_client(_app_settings)
    model = _app_settings.get("llm_model") or "claude-opus-4-7"
    result = await synthesize_tool(
        description=req.description,
        example_input=req.example_input,
        example_output=req.example_output,
        capability_tag=req.capability_tag,
        session_id=req.session_id,
        client=client,
        model=model,
    )
    if result.get("status") == "validation_failed":
        raise HTTPException(status_code=422, detail=result)
    return result


@router.get("/tools/synthesized")
async def search_tools(
    q: str,
    n_results: int = Query(default=5, ge=1, le=20),
) -> Dict[str, Any]:
    """Semantic search over the synthesized tool registry."""
    results = await search_synthesized_tools(q, n_results=n_results)
    return {"query": q, "results": results, "count": len(results)}
