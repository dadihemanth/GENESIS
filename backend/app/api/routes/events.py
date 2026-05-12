"""T146 — Event Store API routes (streaming replay)."""
from __future__ import annotations

import json
from typing import Any, AsyncGenerator, Dict

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from app.middleware.auth import get_current_user_optional

router = APIRouter()


@router.get("/sessions/{session_id}")
async def get_events(
    session_id: str,
    from_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=500, ge=1, le=5000),
    _user: Dict[str, Any] | None = Depends(get_current_user_optional),
) -> StreamingResponse:
    """Stream event log for a session as newline-delimited JSON."""
    from app.services.event_store import replay

    async def _generate() -> AsyncGenerator[str, None]:
        async for event in replay(session_id, from_seq=from_seq, limit=limit):
            yield json.dumps(event) + "\n"

    return StreamingResponse(_generate(), media_type="application/x-ndjson")


@router.get("/sessions/{session_id}/last")
async def get_last_event(
    session_id: str,
    _user: Dict[str, Any] | None = Depends(get_current_user_optional),
) -> Dict[str, Any]:
    """Return the last event for a session (for crash recovery)."""
    from app.services.event_store import get_last_event
    event = await get_last_event(session_id)
    return event or {"seq": None, "event_type": None, "note": "no events found"}


@router.get("/admin/ab-results")
async def ab_results(
    _user: Dict[str, Any] | None = Depends(get_current_user_optional),
) -> Dict[str, Any]:
    """T152 — Return A/B test performance comparison."""
    from app.services.novelty_ab_harness import get_ab_results
    return await get_ab_results()
