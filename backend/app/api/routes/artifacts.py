from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException, Query
from fastapi.responses import FileResponse

from app.database.mongodb import get_artifacts_collection
from app.database.redis_client import publish_session_message

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("")
async def register_artifact(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Register a pulled artifact. Called by the `artifact_pull` MCP tool.

    Upserts on (session_id, sha256) so a repeated pull from the same URL does
    not double-count. Also publishes a shared-findings broadcast so other
    agents in multi-agent mode can react.
    """
    session_id = str(body.get("session_id", "")).strip()
    sha256 = str(body.get("sha256", "")).strip()
    if not session_id or not sha256:
        raise HTTPException(status_code=400, detail="session_id and sha256 are required")

    local_path = str(body.get("path", ""))[:1000]
    doc = {
        "session_id": session_id,
        "sha256": sha256,
        "uri": str(body.get("uri", ""))[:2000],
        "path": local_path,
        "size": int(body.get("size", 0) or 0),
        "mime": str(body.get("mime", ""))[:200],
        "kind": str(body.get("kind", "other"))[:50],
        "duration_ms": int(body.get("duration_ms", 0) or 0),
        "registered_at": datetime.now(timezone.utc),
    }

    # T23 — mirror into MinIO if the resolver is configured. Best-effort:
    # upload failure is logged but does NOT fail the registration — the
    # single-host path continues to work off ``path``.
    s3_key: Optional[str] = None
    if local_path:
        try:
            from app.services.artifact_resolver import get_resolver
            resolver = get_resolver()
            if resolver.enabled:
                s3_key = resolver.publish(local_path, session_id, sha256)
        except Exception as exc:  # noqa: BLE001
            logger.warning("MinIO publish failed for %s/%s: %s", session_id, sha256, exc)
    if s3_key:
        doc["s3_key"] = s3_key

    coll = get_artifacts_collection()
    await coll.update_one(
        {"session_id": session_id, "sha256": sha256},
        {"$set": doc},
        upsert=True,
    )

    # Broadcast — other agents may want to kick off decompile / code_read
    try:
        await publish_session_message(session_id, {
            "type": "artifact_pulled",
            "data": {
                "sha256": sha256,
                "path": doc["path"],
                "kind": doc["kind"],
                "size": doc["size"],
                "mime": doc["mime"],
                "uri": doc["uri"],
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception:
        pass

    return {"ok": True, "sha256": sha256, "session_id": session_id, "s3_key": s3_key}


@router.get("")
async def list_artifacts(session_id: str = Query(...), limit: int = 100) -> Dict[str, Any]:
    """List artifacts pulled for a session (newest first)."""
    coll = get_artifacts_collection()
    cursor = coll.find({"session_id": session_id}).sort("registered_at", -1).limit(max(1, min(limit, 500)))
    items: List[Dict[str, Any]] = []
    async for doc in cursor:
        doc.pop("_id", None)
        ts = doc.get("registered_at")
        if isinstance(ts, datetime):
            doc["registered_at"] = ts.isoformat()
        items.append(doc)
    return {"items": items, "count": len(items), "session_id": session_id}


@router.get("/resolve/{session_id}/{sha256}")
async def resolve_artifact_bytes(session_id: str, sha256: str) -> FileResponse:
    """T23 — Remote-worker artifact fetch.

    Used when a worker on host B needs the bytes of an artifact pulled on
    host A. Resolver tries the local filesystem first (same-host case), then
    falls back to streaming from MinIO into a cache dir.
    """
    from app.services.artifact_resolver import resolve_artifact, ArtifactResolverError

    try:
        path = await resolve_artifact(session_id, sha256)
    except ArtifactResolverError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    # FastAPI's FileResponse handles the streaming + Content-Length.
    return FileResponse(str(path), media_type="application/octet-stream", filename=path.name)


@router.get("/lookup")
async def lookup_artifact(
    session_id: str = Query(...),
    sha256: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve an artifact by sha256 or on-disk path. Used by binary_decompile / code_read."""
    if not sha256 and not path:
        raise HTTPException(status_code=400, detail="sha256 or path is required")
    coll = get_artifacts_collection()
    query: Dict[str, Any] = {"session_id": session_id}
    if sha256:
        query["sha256"] = sha256
    if path:
        query["path"] = path
    doc = await coll.find_one(query)
    if not doc:
        raise HTTPException(status_code=404, detail="artifact not found")
    doc.pop("_id", None)
    ts = doc.get("registered_at")
    if isinstance(ts, datetime):
        doc["registered_at"] = ts.isoformat()
    return doc
