"""v7.x adversarial-reasoning REST routes.

Endpoints:
  GET  /adversarial/{session_id}                — list rounds for a session
  GET  /adversarial/{session_id}?kind=red_blue   — filter to one kind
  GET  /adversarial/detail/{round_id}            — full document
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

from app.database.mongodb import get_adversarial_reasoning_collection

router = APIRouter()


def _serialise(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Convert Mongo BSON datetimes to ISO strings so FastAPI can serialise."""
    if doc is None:
        return doc
    out = dict(doc)
    ca = out.get("created_at")
    if hasattr(ca, "isoformat"):
        out["created_at"] = ca.isoformat()
    # Drop the BSON ObjectId if Mongo ever assigned one alongside our string _id.
    if "_id" in out and not isinstance(out["_id"], str):
        out["_id"] = str(out["_id"])
    return out


@router.get("/detail/{round_id}")
async def get_round_detail(round_id: str) -> Dict[str, Any]:
    """Return the full document for one adversarial round (red/blue or philosopher)."""
    doc = await get_adversarial_reasoning_collection().find_one({"_id": round_id})
    if not doc:
        raise HTTPException(status_code=404, detail=f"adversarial round {round_id} not found")
    return _serialise(doc)


@router.get("/{session_id}")
async def list_session_rounds(
    session_id: str,
    kind: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    """List adversarial rounds for a session, newest first."""
    q: Dict[str, Any] = {"session_id": str(session_id)}
    if kind in {"red_blue", "philosopher"}:
        q["kind"] = kind
    cursor = (
        get_adversarial_reasoning_collection()
        .find(q)
        .sort("created_at", -1)
        .limit(min(limit, 500))
    )
    items: List[Dict[str, Any]] = [_serialise(d) async for d in cursor]
    return {"session_id": session_id, "items": items, "count": len(items)}
