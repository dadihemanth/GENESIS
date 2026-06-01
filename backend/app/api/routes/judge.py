"""v8 — Judge and coverage REST endpoints.

GET /api/v1/judge/{session_id}/verdicts          list judge verdicts (newest first)
GET /api/v1/judge/{session_id}/verdicts/latest   single latest verdict
GET /api/v1/judge/{session_id}/coverage          kill-chain coverage matrix
GET /api/v1/judge/{session_id}/directives        supervisor directives
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from app.database.mongodb import (
    get_judge_verdicts_collection,
    get_supervisor_directives_collection,
    get_tool_outputs_collection,
)
from app.services.killchain_coverage import KillChainCoverage

router = APIRouter()


def _serialize(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Convert MongoDB document to JSON-serialisable dict."""
    doc = dict(doc)
    for k, v in list(doc.items()):
        if hasattr(v, "isoformat"):
            doc[k] = v.isoformat()
        elif isinstance(v, list):
            doc[k] = [
                (item.isoformat() if hasattr(item, "isoformat") else item)
                for item in v
            ]
    return doc


@router.get("/{session_id}/verdicts")
async def list_verdicts(
    session_id: str,
    limit: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """List all SessionJudge verdicts for a session, newest first."""
    col = get_judge_verdicts_collection()
    cursor = (
        col.find({"session_id": session_id})
        .sort("created_at", -1)
        .limit(limit)
    )
    docs: List[Dict[str, Any]] = []
    async for doc in cursor:
        docs.append(_serialize(doc))
    return {"session_id": session_id, "count": len(docs), "verdicts": docs}


@router.get("/{session_id}/verdicts/latest")
async def get_latest_verdict(session_id: str) -> Dict[str, Any]:
    """Return the most recent SessionJudge verdict for a session."""
    col = get_judge_verdicts_collection()
    doc = await col.find_one(
        {"session_id": session_id},
        sort=[("created_at", -1)],
    )
    if not doc:
        raise HTTPException(status_code=404, detail="No judge verdict found for this session")
    return _serialize(doc)


@router.get("/{session_id}/coverage")
async def get_coverage_matrix(session_id: str) -> Dict[str, Any]:
    """Return the kill-chain coverage matrix reconstructed from tool_outputs.

    Works for both active and completed sessions. Replays all tool_name values
    from the tool_outputs collection (indexed by session_id) through
    KillChainCoverage.record_tool() to reproduce the coverage state.
    """
    col = get_tool_outputs_collection()
    cursor = col.find(
        {"session_id": session_id},
        projection={"tool_name": 1, "_id": 0},
    )
    coverage = KillChainCoverage()
    tool_count = 0
    async for doc in cursor:
        tool_name = doc.get("tool_name", "")
        if tool_name:
            coverage.record_tool(tool_name)
            tool_count += 1

    return {
        "session_id": session_id,
        "tool_calls_replayed": tool_count,
        "overall_pct": round(coverage.overall_pct(), 1),
        "gate_passed": coverage.gate_passed(),
        "phases": coverage.to_dict(),
        "gaps": coverage.gap_report(),
    }


@router.get("/{session_id}/directives")
async def list_directives(
    session_id: str,
    agent_type: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
) -> Dict[str, Any]:
    """List supervisor directives for a session, newest first.

    Pass ?agent_type=exploit to filter to a specific agent.
    """
    col = get_supervisor_directives_collection()
    query: Dict[str, Any] = {"session_id": session_id}
    if agent_type:
        query["agent_type"] = agent_type
    cursor = (
        col.find(query)
        .sort("created_at", -1)
        .limit(limit)
    )
    docs: List[Dict[str, Any]] = []
    async for doc in cursor:
        docs.append(_serialize(doc))
    return {
        "session_id": session_id,
        "count": len(docs),
        "agent_type_filter": agent_type,
        "directives": docs,
    }
