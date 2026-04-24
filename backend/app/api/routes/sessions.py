from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.mongodb import get_agent_thoughts_collection, get_tool_outputs_collection, get_hypothesis_journals_collection
from app.database.postgres import get_db
from app.database.redis_client import publish_session_message
from app.models.session import ResearchSession
from app.schemas.session import (
    AgentThoughtRead,
    SessionCreate,
    SessionList,
    SessionRead,
    ToolOutputRead,
)

router = APIRouter()


@router.post("", response_model=SessionRead, status_code=201)
async def create_session(
    body: SessionCreate,
    db: AsyncSession = Depends(get_db),
) -> ResearchSession:
    session = ResearchSession(
        target_ip=body.target_ip,
        target_hostname=body.target_hostname,
        status="pending",
        phase="reconnaissance",
        scan_profile=body.scan_profile or "deep",
        agent_mode=body.agent_mode or "solo",
        config=body.config or {},
    )
    db.add(session)
    await db.flush()
    await db.refresh(session)
    return session


@router.get("", response_model=SessionList)
async def list_sessions(
    status: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    query = select(ResearchSession)
    count_query = select(func.count()).select_from(ResearchSession)

    if status:
        query = query.where(ResearchSession.status == status)
        count_query = count_query.where(ResearchSession.status == status)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    query = query.order_by(ResearchSession.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    sessions = result.scalars().all()

    return {"items": sessions, "total": total, "page": page, "size": size}


@router.get("/{session_id}", response_model=SessionRead)
async def get_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ResearchSession:
    result = await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.post("/{session_id}/start", response_model=SessionRead)
async def start_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ResearchSession:
    result = await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.status not in ("pending", "paused"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot start session in status '{session.status}'",
        )

    session.status = "running"
    session.started_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(session)

    # Dispatch Celery task — commit first so worker sees the row
    from app.services.tasks import run_research_session
    run_research_session.apply_async(
        args=[str(session_id), session.target_ip],
        queue="research",
    )

    return session


@router.post("/{session_id}/pause", response_model=SessionRead)
async def pause_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ResearchSession:
    result = await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.status != "running":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot pause session in status '{session.status}'",
        )

    session.status = "paused"
    await db.flush()
    await db.refresh(session)

    await publish_session_message(
        str(session_id),
        {
            "type": "session_update",
            "data": {"status": "paused"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    return session


@router.post("/{session_id}/resume", response_model=SessionRead)
async def resume_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ResearchSession:
    result = await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.status != "paused":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot resume session in status '{session.status}'",
        )

    session.status = "running"
    await db.commit()
    await db.refresh(session)

    await publish_session_message(
        str(session_id),
        {
            "type": "session_update",
            "data": {"status": "running"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    # Re-dispatch Celery task to resume — commit first so worker sees the row
    from app.services.tasks import run_research_session
    run_research_session.apply_async(
        args=[str(session_id), session.target_ip],
        queue="research",
    )

    return session


@router.post("/{session_id}/stop", response_model=SessionRead)
async def stop_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ResearchSession:
    result = await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    session.status = "stopped"
    session.completed_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(session)

    await publish_session_message(
        str(session_id),
        {
            "type": "session_update",
            "data": {"status": "stopped"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    return session


@router.get("/{session_id}/thoughts")
async def get_thoughts(
    session_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Dict[str, Any]:
    collection = get_agent_thoughts_collection()
    session_id_str = str(session_id)

    total = await collection.count_documents({"session_id": session_id_str})
    cursor = (
        collection.find({"session_id": session_id_str})
        .sort("timestamp", 1)
        .skip((page - 1) * size)
        .limit(size)
    )
    docs = await cursor.to_list(length=size)

    items = []
    for doc in docs:
        items.append(
            {
                "id": str(doc.get("_id", "")),
                "session_id": doc.get("session_id", ""),
                "thought": doc.get("thought", ""),
                "phase": doc.get("phase", ""),
                "iteration": doc.get("iteration", 0),
                "tool_calls": doc.get("tool_calls", []),
                "timestamp": doc.get("timestamp"),
            }
        )

    return {"items": items, "total": total, "page": page, "size": size}


@router.get("/{session_id}/hypotheses")
async def get_hypotheses(session_id: uuid.UUID) -> Dict[str, Any]:
    collection = get_hypothesis_journals_collection()
    session_id_str = str(session_id)
    cursor = collection.find({"session_id": session_id_str}).sort("updated_at", 1)
    docs = await cursor.to_list(length=500)
    items = []
    for doc in docs:
        items.append({
            "hyp_id": doc.get("hyp_id", ""),
            "session_id": doc.get("session_id", ""),
            "statement": doc.get("statement", ""),
            "confidence": doc.get("confidence", 0.5),
            "evidence_for": doc.get("evidence_for", []),
            "evidence_against": doc.get("evidence_against", []),
            "next_test": doc.get("next_test", ""),
            "status": doc.get("status", "active"),
            "updated_at": str(doc.get("updated_at", "")),
        })
    return {"items": items, "total": len(items)}


@router.get("/{session_id}/tool-outputs")
async def get_tool_outputs(
    session_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Dict[str, Any]:
    collection = get_tool_outputs_collection()
    session_id_str = str(session_id)

    total = await collection.count_documents({"session_id": session_id_str})
    cursor = (
        collection.find({"session_id": session_id_str})
        .sort("timestamp", 1)
        .skip((page - 1) * size)
        .limit(size)
    )
    docs = await cursor.to_list(length=size)

    items = []
    for doc in docs:
        items.append(
            {
                "id": str(doc.get("_id", "")),
                "session_id": doc.get("session_id", ""),
                "tool_name": doc.get("tool_name", ""),
                "params": doc.get("params", {}),
                "raw_output": doc.get("raw_output"),
                "parsed_output": doc.get("parsed_output"),
                "duration_seconds": doc.get("duration_seconds"),
                "timestamp": doc.get("timestamp"),
            }
        )

    return {"items": items, "total": total, "page": page, "size": size}


@router.get("/{session_id}/attack-chains")
async def get_attack_chains(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    result = await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Session not found")

    from app.services.attack_chain import AttackChainService
    return await AttackChainService().get_chains(str(session_id), db)


@router.get("/{session_id}/network-topology")
async def get_network_topology(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    result = await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.network_topology or {"nodes": [], "edges": []}


@router.get("/{session_id}/mitre-mapping")
async def get_mitre_mapping(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    from sqlalchemy import text as _text
    result = await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Session not found")

    from app.models.vulnerability import Vulnerability
    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.session_id == session_id)
    )
    vulns = vuln_result.scalars().all()

    technique_map: Dict[str, int] = {}
    for v in vulns:
        for technique in (v.mitre_techniques or []):
            t = str(technique)
            technique_map[t] = technique_map.get(t, 0) + 1

    return {
        "session_id": str(session_id),
        "techniques": technique_map,
        "total_techniques": len(technique_map),
        "total_mappings": sum(technique_map.values()),
    }


@router.get("/{session_id}/errors")
async def get_session_errors(
    session_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Dict[str, Any]:
    """Return the structured error log for a session.

    Ordered oldest-first so the UI shows the *first* failure cause at the top —
    later errors are often cascades of the first one.
    """
    from app.database.mongodb import get_session_errors_collection
    collection = get_session_errors_collection()
    session_id_str = str(session_id)

    total = await collection.count_documents({"session_id": session_id_str})
    cursor = (
        collection.find({"session_id": session_id_str})
        .sort("timestamp", 1)
        .skip((page - 1) * size)
        .limit(size)
    )
    docs = await cursor.to_list(length=size)

    items = []
    for doc in docs:
        items.append({
            "id": str(doc.get("_id", "")),
            "session_id": doc.get("session_id", ""),
            "phase": doc.get("phase", ""),
            "error_type": doc.get("error_type", ""),
            "error_message": doc.get("error_message", ""),
            "traceback": doc.get("traceback", ""),
            "iteration": doc.get("iteration"),
            "tool": doc.get("tool"),
            "context": doc.get("context", {}),
            "timestamp": doc.get("timestamp"),
        })

    return {"items": items, "total": total, "page": page, "size": size}
