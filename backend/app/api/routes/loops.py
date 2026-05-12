"""v7.0 reasoning-loop REST routes.

Endpoints:
  GET  /loops/{session_id}                     — list all loops for a session (ticks stripped)
  GET  /loops/{session_id}?loop_type=...        — filter by loop type
  GET  /loops/detail/{loop_id}                  — full loop document including ticks
  GET  /loops/types                             — registered loop types + budgets
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

from app.services.reasoning import loop_state as _state
from app.services.reasoning.registry import LOOP_TYPES, get_budget

router = APIRouter()


@router.get("/types")
async def list_loop_types() -> Dict[str, Any]:
    """Registered v7 reasoning-loop types and their per-loop budgets."""
    types: List[Dict[str, Any]] = []
    for lt in LOOP_TYPES:
        b = get_budget(lt)
        types.append({
            "loop_type": lt,
            "max_tokens": b.max_tokens,
            "max_ticks": b.max_ticks,
        })
    return {"types": types, "count": len(types)}


@router.get("/detail/{loop_id}")
async def get_loop_detail(loop_id: str) -> Dict[str, Any]:
    """Full loop document, including every tick."""
    doc = await _state.get_loop(loop_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"loop {loop_id} not found")
    return doc


@router.get("/{session_id}")
async def list_session_loops(
    session_id: str,
    loop_type: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """List loops for a session (ticks omitted; use /detail/{loop_id} for full)."""
    loops = await _state.list_session_loops(session_id, loop_type=loop_type, limit=min(limit, 200))
    return {"session_id": session_id, "loops": loops, "count": len(loops)}
