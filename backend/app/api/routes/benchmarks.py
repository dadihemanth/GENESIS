"""validation milestone 7 — benchmark recall API routes.

GET  /api/v1/benchmarks/recall          — list recent scorecards
POST /api/v1/benchmarks/recall/run      — trigger an ad-hoc recall run
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Query
from pydantic import BaseModel, Field

router = APIRouter()


class RecallRunRequest(BaseModel):
    target_name: str = Field(default="openssl", description="Software target to benchmark")
    max_cves: int = Field(default=10, ge=1, le=50)
    scan_timeout: int = Field(default=1800, ge=60, le=7200)


def _strip_mongo_id(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Remove non-serializable _id field from MongoDB documents."""
    doc.pop("_id", None)
    # Convert datetime to ISO string for JSON serialization
    if "run_at" in doc and hasattr(doc["run_at"], "isoformat"):
        doc["run_at"] = doc["run_at"].isoformat()
    return doc


@router.get("/recall", response_model=Dict[str, Any])
async def list_recall_scorecards(
    limit: int = Query(default=20, ge=1, le=100),
) -> Dict[str, Any]:
    """Return the most recent recall benchmark scorecards."""
    from app.services.benchmark_recall import get_latest_scorecards
    docs = await get_latest_scorecards(limit=limit)
    return {
        "items": [_strip_mongo_id(d) for d in docs],
        "total": len(docs),
    }


@router.post("/recall/run", status_code=202, response_model=Dict[str, Any])
async def trigger_recall_run(
    body: RecallRunRequest,
    background_tasks: BackgroundTasks,
) -> Dict[str, Any]:
    """Trigger an ad-hoc recall benchmark run (runs in background)."""
    from app.services.benchmark_recall import run_recall_benchmark

    async def _run() -> None:
        await run_recall_benchmark(
            target_name=body.target_name,
            max_cves=body.max_cves,
            scan_timeout=body.scan_timeout,
        )

    background_tasks.add_task(_run)
    return {
        "status": "accepted",
        "target": body.target_name,
        "message": "Recall benchmark queued. Poll GET /api/v1/benchmarks/recall for results.",
    }
