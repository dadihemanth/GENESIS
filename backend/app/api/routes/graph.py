"""T21 — Neo4j attack-graph REST endpoints.

Exposes:
  - ``POST /api/v1/graph/query``      — read-only Cypher runner.
    Proxied by the MCP ``graph_query`` tool; read-only filter rejects
    mutating clauses, then the query runs in a Neo4j READ-mode session
    with a 30s timeout and a 10k row cap.

  - ``GET  /api/v1/graph/session/{session_id}``
    — full nodes + edges for a session; feeds the T27 frontend panel.

  - ``GET  /api/v1/graph/shortest_path``
    — shortest path between two typed nodes. Query params:
      ``src_label``, ``src_id``, ``dst_label``, ``dst_id``, ``max_hops``.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services import attack_graph

logger = logging.getLogger(__name__)
router = APIRouter()


class CypherRequest(BaseModel):
    cypher: str = Field(..., min_length=1, max_length=20_000)
    params: Optional[Dict[str, Any]] = None
    row_cap: int = Field(default=10_000, ge=1, le=50_000)
    timeout_s: float = Field(default=30.0, gt=0, le=120.0)


@router.post("/query")
async def run_cypher(req: CypherRequest) -> Dict[str, Any]:
    """Run a read-only Cypher query. Rejects mutating clauses."""
    result = await attack_graph.run_read_cypher(
        cypher=req.cypher,
        params=req.params or {},
        row_cap=req.row_cap,
        timeout_s=req.timeout_s,
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "query failed"))
    return result


@router.get("/session/{session_id}")
async def get_session_graph(session_id: str) -> Dict[str, Any]:
    """Full nodes + edges for a session — drives the T27 frontend panel."""
    try:
        uuid.UUID(session_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid session_id: {exc}") from exc
    graph = await attack_graph.session_graph(session_id)
    return {"session_id": session_id, **graph}


@router.get("/shortest_path")
async def get_shortest_path(
    src_label: str = Query(...),
    src_id: str = Query(...),
    dst_label: str = Query(...),
    dst_id: str = Query(...),
    max_hops: int = Query(default=8, ge=1, le=15),
) -> Dict[str, Any]:
    """Typed shortest path between two nodes."""
    allowed_labels = {"Host", "Service", "Finding", "Credential", "Token", "Privilege", "Target"}
    if src_label not in allowed_labels or dst_label not in allowed_labels:
        raise HTTPException(
            status_code=400,
            detail=f"labels must be one of {sorted(allowed_labels)}",
        )
    result = await attack_graph.shortest_path(src_label, src_id, dst_label, dst_id, max_hops)
    if result is None:
        return {"found": False}
    return {"found": True, **result}
