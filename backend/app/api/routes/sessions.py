from __future__ import annotations

import uuid
import logging
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
logger = logging.getLogger(__name__)


async def _cleanup_session_docker_resources(session_id: uuid.UUID, reason: str) -> None:
    """Best-effort lifecycle cleanup; failures must not block session state changes."""
    try:
        from app.services.session_container_cleanup import cleanup_session_containers

        cleanup = await cleanup_session_containers(str(session_id), reason=reason)
        await publish_session_message(
            str(session_id),
            {
                "type": "session_update",
                "data": {"container_cleanup": cleanup},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("session docker cleanup failed for %s (%s): %s", session_id, reason, exc)


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
        agent_mode=body.agent_mode or "multi_agent",
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

    await _cleanup_session_docker_resources(session_id, "session_paused")

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


@router.get("/{session_id}/routing")
async def get_session_routing(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """v7.x — explain which model serves which role for this session.

    For each known role, returns: assigned profile id/name/provider/model,
    role purpose, fallback path, and ACTUAL llm_usage count + tokens emitted
    under that role's source labels. The Routing tab uses this to make the
    role → model mapping transparent so 'why is Opus $0?' is impossible to
    misread.
    """
    import json as _json
    from app.models.session import AppSettings as _AppSettings
    from app.services.llm_routing import KNOWN_ROLES, ROLE_DETAILS
    from app.database.mongodb import get_llm_usage_collection

    # Load profiles + assignments + mode
    rows = await db.execute(
        select(_AppSettings).where(_AppSettings.key.in_(
            ["model_profiles", "role_assignments", "llm_mode"]
        ))
    )
    settings_map: Dict[str, str] = {r.key: r.value for r in rows.scalars().all()}
    try:
        profiles = _json.loads(settings_map.get("model_profiles") or "[]") or []
    except Exception:
        profiles = []
    try:
        assignments = _json.loads(settings_map.get("role_assignments") or "{}") or {}
    except Exception:
        assignments = {}
    profiles_by_id = {p.get("id"): p for p in profiles if isinstance(p, dict)}
    mode = (settings_map.get("llm_mode") or "single").strip().lower()

    # Aggregate llm_usage per source for this session
    usage_by_source: Dict[str, Dict[str, Any]] = {}
    try:
        col = get_llm_usage_collection()
        cursor = col.aggregate([
            {"$match": {"session_id": str(session_id)}},
            {"$group": {
                "_id": {"source": "$source", "model": "$model"},
                "calls": {"$sum": 1},
                "input": {"$sum": "$input_tokens"},
                "output": {"$sum": "$output_tokens"},
            }},
        ])
        async for d in cursor:
            src = (d["_id"] or {}).get("source") or "unknown"
            model = (d["_id"] or {}).get("model") or ""
            entry = usage_by_source.setdefault(src, {
                "source": src, "model": model, "calls": 0,
                "input_tokens": 0, "output_tokens": 0,
            })
            entry["calls"] += int(d.get("calls", 0))
            entry["input_tokens"] += int(d.get("input", 0))
            entry["output_tokens"] += int(d.get("output", 0))
    except Exception:
        pass

    # Resolve each role
    rows_out: List[Dict[str, Any]] = []
    primary_id = assignments.get("primary") or (profiles[0]["id"] if profiles else None)
    for role in KNOWN_ROLES:
        details = ROLE_DETAILS.get(role, {})
        assigned_id = assignments.get(role)
        fell_back = False
        if not assigned_id and primary_id:
            assigned_id = primary_id
            fell_back = True
        profile = profiles_by_id.get(assigned_id) if assigned_id else None
        # Aggregate actual usage for this role's known sources
        role_sources = list(details.get("sources", ()))
        # subagent role aggregates ALL subagent:* sources
        if role == "subagent":
            role_sources = [k for k in usage_by_source.keys() if k.startswith("subagent:")]
        total_calls = 0
        total_in = 0
        total_out = 0
        observed_models = set()
        for src in role_sources:
            entry = usage_by_source.get(src)
            if not entry:
                continue
            total_calls += entry["calls"]
            total_in += entry["input_tokens"]
            total_out += entry["output_tokens"]
            if entry["model"]:
                observed_models.add(entry["model"])
        active_in_mode = (
            "both" in details.get("fires_in", "")
            or (mode == "single" and "solo" in details.get("fires_in", ""))
            or (mode == "multi" and "multi" in details.get("fires_in", ""))
            or (mode == "single" and "agent_mode" in details.get("fires_in", ""))
        )
        # explain why this is the right model — short freeform string
        good_models = details.get("good_models", "")
        explanation = (
            f"This role {details.get('purpose','—')[:200]} "
            f"Recommended models: {good_models}."
        )
        if not assigned_id:
            why_chosen = "No profile assigned and no profiles configured at all."
        elif fell_back:
            why_chosen = (
                f"No explicit assignment for `{role}` — fell back to the `primary` "
                f"profile."
            )
        else:
            why_chosen = (
                f"Operator explicitly assigned profile `{(profile or {}).get('name','?')}` "
                f"to role `{role}` in Settings."
            )
        rows_out.append({
            "role": role,
            "purpose": details.get("purpose", ""),
            "fires_in": details.get("fires_in", ""),
            "active_for_this_session_mode": active_in_mode,
            "good_models": good_models,
            "assigned_profile_id": assigned_id,
            "assigned_profile_name": (profile or {}).get("name") if profile else None,
            "assigned_provider": (profile or {}).get("provider") if profile else None,
            "assigned_model": (profile or {}).get("model") if profile else None,
            "fallback_to_primary": fell_back,
            "calls_this_session": total_calls,
            "input_tokens_this_session": total_in,
            "output_tokens_this_session": total_out,
            "observed_models": sorted(observed_models),
            "why_assigned": why_chosen,
            "explanation": explanation,
        })

    return {
        "session_id": str(session_id),
        "llm_mode": mode,
        "profiles_configured": len(profiles),
        "rows": rows_out,
    }


@router.get("/{session_id}/reproducibility")
async def get_session_reproducibility(session_id: uuid.UUID):
    """v7.x — per-session reproducibility report. Returns the doc written
    at session-finalize. 404 when no report exists yet (in-progress or
    pre-v7.x sessions)."""
    from app.database.mongodb import get_reproducibility_reports_collection
    doc = await get_reproducibility_reports_collection().find_one(
        {"session_id": str(session_id)}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="no reproducibility report yet")
    # serialise BSON datetime
    ca = doc.get("created_at")
    if hasattr(ca, "isoformat"):
        doc["created_at"] = ca.isoformat()
    if "_id" in doc and not isinstance(doc["_id"], str):
        doc["_id"] = str(doc["_id"])
    return doc


@router.get("/{session_id}/coverage-matrix")
async def get_session_coverage_matrix(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """v7.x — per-endpoint × per-attack-class coverage heatmap.

    Cells: ``{[endpoint][class]: {attempted: N, confirmed: bool, last_tool: str}}``.
    Counts every tool invocation that maps to one of the 16 attack classes
    via ``_ATTACK_CLASS_PROBES``. A cell flips to confirmed when a
    vulnerability with verification_status ∈ {confirmed, exploited} is
    attached to that endpoint × class.

    The endpoint dimension is best-effort: extracted from the call's params
    (``target_url`` / ``url`` / ``endpoint`` / ``target`` / ``host``), with
    the session target_ip as fallback. Cells outside the 16 attack classes
    (e.g. raw recon scans like nmap) are intentionally excluded — this is a
    targeted-probe heatmap, not a tool log.
    """
    sess_result = await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )
    session = sess_result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    from app.models.vulnerability import Vulnerability
    from app.services.ai_orchestrator import AIOrchestrator
    from app.database.mongodb import get_vulnerability_metadata_collection

    classes: List[str] = list(AIOrchestrator._ATTACK_CLASS_PROBES.keys())
    tool_to_class: Dict[str, str] = {}
    for cls_name, probes in AIOrchestrator._ATTACK_CLASS_PROBES.items():
        for p in probes:
            tool_to_class.setdefault(p, cls_name)

    fallback_target = (session.target_ip or "unknown").strip()

    def _endpoint_for(params: Dict[str, Any]) -> str:
        if not isinstance(params, dict):
            return fallback_target
        for k in ("target_url", "url", "endpoint", "target", "host", "target_ip"):
            v = params.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()[:140]
        return fallback_target

    cells: Dict[str, Dict[str, Dict[str, Any]]] = {}

    cursor = (
        get_tool_outputs_collection()
        .find({"session_id": str(session_id)})
        .sort("timestamp", 1)
    )
    async for doc in cursor:
        tool_name = (doc.get("tool_name") or "").strip()
        attack_class = tool_to_class.get(tool_name)
        if not attack_class:
            continue
        ep = _endpoint_for(doc.get("params") or {})
        cell = cells.setdefault(ep, {}).setdefault(
            attack_class, {"attempted": 0, "confirmed": False, "last_tool": ""}
        )
        cell["attempted"] += 1
        cell["last_tool"] = tool_name

    v_result = await db.execute(
        select(Vulnerability).where(Vulnerability.session_id == session_id)
    )
    vulns = list(v_result.scalars().all())

    metadata_by_vuln: Dict[str, Dict[str, Any]] = {}
    try:
        async for d in get_vulnerability_metadata_collection().find(
            {"session_id": str(session_id)}
        ):
            vid = d.get("vuln_id")
            if vid:
                metadata_by_vuln[str(vid)] = d
    except Exception:
        pass

    # Heuristic title-to-class mapping when tool_used isn't probe-mapped.
    _CLASS_KEYWORDS: Dict[str, List[str]] = {
        "auth_bypass":     ["auth bypass", "authentication bypass", "session", "saml"],
        "sqli":            ["sql injection", "sqli", "second-order"],
        "ssrf":            ["ssrf", "server-side request"],
        "idor":            ["idor", "insecure direct"],
        "deserialisation": ["deserial", "object injection", "pickle", "marshal"],
        "ssti":            ["template injection", "ssti", "jinja", "twig"],
        "jwt":             ["jwt", "json web token"],
        "graphql":         ["graphql"],
        "smuggling":       ["smuggling", "request splitting"],
        "cache":           ["cache", "varnish", "cdn"],
        "oauth":           ["oauth"],
        "xxe_xml":         ["xxe", "xml external"],
        "xss":             ["xss", "cross-site script", "dom clobber"],
        "rce":             ["rce", "remote code", "command injection", "shell"],
        "lfi_path":        ["lfi", "path traversal", "directory traversal", "file inclusion"],
        "crypto":          ["padding oracle", "bleichenbach", "ecdsa", "rsa", "lattice", "tls", "ssl"],
    }

    for v in vulns:
        if v.verification_status not in ("confirmed", "exploited"):
            continue
        meta = metadata_by_vuln.get(str(v.id), {})
        ep = (
            str(meta.get("endpoint") or "").strip()
            or (v.affected_service or "").strip()
            or fallback_target
        )[:140]

        attack_class: Optional[str] = None
        tool_used = str(meta.get("tool_used") or "")
        for t in tool_used.replace(";", ",").split(","):
            t = t.strip()
            if t in tool_to_class:
                attack_class = tool_to_class[t]
                break
        if not attack_class:
            title_lower = (v.title or "").lower()
            for cls_name, kws in _CLASS_KEYWORDS.items():
                if any(kw in title_lower for kw in kws):
                    attack_class = cls_name
                    break
        if not attack_class:
            continue
        cell = cells.setdefault(ep, {}).setdefault(
            attack_class, {"attempted": 0, "confirmed": False, "last_tool": ""}
        )
        cell["confirmed"] = True

    endpoints = sorted(cells.keys())
    total_cells = len(endpoints) * len(classes)
    attempted_cells = sum(
        1 for e in endpoints for c in classes
        if cells.get(e, {}).get(c, {}).get("attempted", 0) > 0
    )
    confirmed_cells = sum(
        1 for e in endpoints for c in classes
        if cells.get(e, {}).get(c, {}).get("confirmed")
    )
    coverage_pct = round(100.0 * attempted_cells / total_cells, 1) if total_cells else 0.0

    return {
        "session_id": str(session_id),
        "target_ip": session.target_ip or "",
        "endpoints": endpoints,
        "classes": classes,
        "cells": cells,
        "density": {
            "total_cells": total_cells,
            "attempted_cells": attempted_cells,
            "confirmed_cells": confirmed_cells,
            "coverage_pct": coverage_pct,
        },
    }


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

    await _cleanup_session_docker_resources(session_id, "session_stopped")

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
    size: int = Query(default=50, ge=1, le=1000),
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


# ── Report download ────────────────────────────────────────────────────────


def _md_escape(s: str | None) -> str:
    """Escape markdown control characters in user-supplied strings."""
    if not s:
        return ""
    return (
        str(s)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "\\`")
    )


def _md_codeblock(s: str | None, lang: str = "") -> str:
    if not s:
        return ""
    text = str(s).rstrip()
    return f"```{lang}\n{text}\n```"


@router.get("/{session_id}/report")
async def download_session_report(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Render a Markdown report for a finished or in-progress session.

    Includes session metadata, an executive summary, every persisted
    finding with its evidence trail and remediation, the attack-chain
    table, the confirmed-hypothesis trail, and a tool-call histogram.
    Returned as `text/markdown` with a Content-Disposition that the
    browser saves as ``genesis-{target}-{short-id}.md``.
    """
    from fastapi.responses import Response
    from app.models.vulnerability import Vulnerability
    from app.services.finding_explainer import build_plain_language_finding

    sid = str(session_id)

    # Session row
    session = (await db.execute(
        select(ResearchSession).where(ResearchSession.id == session_id)
    )).scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    # Findings — ordered by severity desc then created_at
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns_rows = (await db.execute(
        select(Vulnerability).where(Vulnerability.session_id == session_id)
    )).scalars().all()
    vulns = sorted(
        vulns_rows,
        key=lambda v: (sev_rank.get((v.severity or "info").lower(), 9), v.created_at or datetime.min),
    )

    # Hypotheses — confirmed only, latest version per id
    hyp_coll = get_hypothesis_journals_collection()
    cursor = hyp_coll.find({"session_id": sid}).sort("updated_at", -1)
    latest_by_id: Dict[str, Dict[str, Any]] = {}
    async for doc in cursor:
        hid = str(doc.get("hyp_id", "")).strip()
        if hid and hid not in latest_by_id:
            latest_by_id[hid] = doc
    confirmed_hyps = [h for h in latest_by_id.values() if h.get("status") == "confirmed"]
    confirmed_hyps.sort(key=lambda h: float(h.get("confidence") or 0), reverse=True)

    # Tool-call histogram
    tool_coll = get_tool_outputs_collection()
    tool_counts: Dict[str, int] = {}
    async for doc in tool_coll.find({"session_id": sid}, projection={"tool_name": 1}):
        n = doc.get("tool_name") or "?"
        tool_counts[n] = tool_counts.get(n, 0) + 1

    # Vulnerability metadata (evidence_for) for each finding
    from app.database.mongodb import get_vulnerability_metadata_collection
    meta_coll = get_vulnerability_metadata_collection()
    meta_by_vid: Dict[str, Dict[str, Any]] = {}
    async for doc in meta_coll.find({"session_id": sid}):
        vid = str(doc.get("vuln_id", ""))
        if vid:
            meta_by_vid[vid] = doc

    # ── Build the Markdown ─────────────────────────────────────────────────
    sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    status_counts: Dict[str, int] = {}
    chain_ids: set[str] = set()
    mitre_set: set[str] = set()
    for v in vulns:
        sev_counts[(v.severity or "info").lower()] = sev_counts.get((v.severity or "info").lower(), 0) + 1
        st = (v.verification_status or "unverified").lower()
        status_counts[st] = status_counts.get(st, 0) + 1
        if v.attack_chain_id:
            chain_ids.add(v.attack_chain_id)
        for t in (v.mitre_techniques or []):
            if isinstance(t, str) and t:
                mitre_set.add(t)

    started = session.started_at.isoformat() if session.started_at else "—"
    completed = session.completed_at.isoformat() if session.completed_at else "—"
    target_label = session.target_hostname or session.target_ip or "(unknown)"

    md: List[str] = []
    md.append(f"# GENESIS report — {_md_escape(target_label)}")
    md.append("")
    md.append("| Field | Value |")
    md.append("|---|---|")
    md.append(f"| Target | `{_md_escape(session.target_ip)}`{' (' + _md_escape(session.target_hostname) + ')' if session.target_hostname else ''} |")
    md.append(f"| Session ID | `{sid}` |")
    md.append(f"| Status | {session.status} |")
    md.append(f"| Phase | {session.phase} |")
    md.append(f"| Iterations | {session.iteration} |")
    md.append(f"| Agent mode | {session.agent_mode} |")
    md.append(f"| Scan profile | {session.scan_profile} |")
    md.append(f"| Started | {started} |")
    md.append(f"| Completed | {completed} |")
    md.append("")
    md.append("## Executive summary")
    md.append("")
    md.append(f"- **{len(vulns)}** total findings")
    md.append(
        f"  - Critical: **{sev_counts.get('critical', 0)}**, "
        f"High: **{sev_counts.get('high', 0)}**, "
        f"Medium: **{sev_counts.get('medium', 0)}**, "
        f"Low: **{sev_counts.get('low', 0)}**, "
        f"Info: **{sev_counts.get('info', 0)}**"
    )
    md.append(f"- Verification: {', '.join(f'{k}: {v}' for k, v in sorted(status_counts.items()))}")
    md.append(f"- Attack chains: **{len(chain_ids)}**")
    md.append(f"- Distinct MITRE techniques: **{len(mitre_set)}**" + (f" ({', '.join(sorted(mitre_set))})" if mitre_set else ""))
    md.append(f"- Hypotheses confirmed: **{len(confirmed_hyps)}**")
    md.append(f"- Total tool calls: **{sum(tool_counts.values())}** across **{len(tool_counts)}** distinct tools")
    md.append("")

    md.append("## Findings")
    md.append("")
    if not vulns:
        md.append("_No findings recorded._")
        md.append("")
    for i, v in enumerate(vulns, start=1):
        meta = meta_by_vid.get(str(v.id), {})
        evidence_for = meta.get("evidence_for", []) or []
        endpoint = meta.get("endpoint", "")
        technique_tag = meta.get("technique_tag", "")
        md.append(f"### {i}. [{(v.severity or 'info').upper()}] {_md_escape(v.title)}")
        md.append("")
        md.append("| | |")
        md.append("|---|---|")
        md.append(f"| Severity | {v.severity} |")
        if v.cvss_score is not None:
            md.append(f"| CVSS | {v.cvss_score:.1f} |")
        md.append(f"| Verification status | {v.verification_status} |")
        md.append(f"| Confidence | {v.confidence:.2f} |")
        md.append(f"| Affected service | `{_md_escape(v.affected_service)}`{(':' + str(v.port)) if v.port else ''} |")
        if v.cve_ids:
            md.append(f"| CVE | {', '.join(v.cve_ids)} |")
        if v.is_zero_day:
            md.append(f"| Zero-day candidate | yes |")
        if v.attack_chain_id:
            md.append(f"| Attack chain | `{v.attack_chain_id}`{(' (step ' + str(v.chain_position) + ')') if v.chain_position else ''} |")
        if v.mitre_techniques:
            md.append(f"| MITRE | {', '.join(v.mitre_techniques)} |")
        if endpoint:
            md.append(f"| Endpoint | `{_md_escape(endpoint)}` |")
        if technique_tag:
            md.append(f"| Technique tag | `{_md_escape(technique_tag)}` |")
        md.append("")
        plain = build_plain_language_finding(v, meta)
        md.append("**Description.** " + plain["description"])
        md.append("")
        md.append("**Why it matters.** " + plain["why_it_matters"])
        md.append("")
        md.append("**Proof.** " + plain["proof"])
        md.append("")
        md.append("**Solution.** " + plain["solution"])
        md.append("")
        md.append("**Validation note.** " + plain["validation_note"])
        md.append("")
        md.append("**Technical evidence appendix:**")
        md.append("")
        if v.description:
            md.append("- Raw technical description: " + str(v.description)[:800])
        if evidence_for:
            for e in evidence_for:
                md.append(f"- {str(e)[:600]}")
        if v.verification_output:
            md.append("- Verification output: " + str(v.verification_output)[:800])
        if not (v.description or evidence_for or v.verification_output):
            md.append("- No additional technical evidence was attached to the compact report.")
        md.append("")
        if v.exploit_code:
            md.append("**Technical appendix: exploit / PoC.**")
            md.append(_md_codeblock(v.exploit_code, ""))
            md.append("")
        if v.patch_code:
            md.append("**Technical appendix: suggested patch.**")
            md.append(_md_codeblock(v.patch_code, ""))
            md.append("")

    if chain_ids:
        md.append("## Attack chains")
        md.append("")
        for cid in sorted(chain_ids):
            members = [v for v in vulns if v.attack_chain_id == cid]
            members.sort(key=lambda v: v.chain_position or 0)
            md.append(f"### `{cid}` — {len(members)} step{'s' if len(members) != 1 else ''}")
            md.append("")
            for v in members:
                pos = f"step {v.chain_position} · " if v.chain_position else ""
                md.append(f"1. {pos}**[{(v.severity or 'info').upper()}]** {_md_escape(v.title)}")
            md.append("")

    if confirmed_hyps:
        md.append("## Hypothesis trail (confirmed)")
        md.append("")
        for h in confirmed_hyps:
            md.append(f"- **`{h.get('hyp_id') or '?'}`** (conf {float(h.get('confidence') or 0):.2f}) — {_md_escape(h.get('statement'))}")
            ef = h.get("evidence_for") or []
            if ef:
                for e in ef[:5]:
                    md.append(f"   - evidence: {_md_escape(str(e))[:300]}")
        md.append("")

    if tool_counts:
        md.append("## Tool-call histogram")
        md.append("")
        md.append("| Tool | Calls |")
        md.append("|---|---:|")
        for name, n in sorted(tool_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            md.append(f"| `{name}` | {n} |")
        md.append("")

    md.append("---")
    md.append(f"_Generated by GENESIS at {datetime.now(timezone.utc).isoformat()}_")
    md.append("")

    body = "\n".join(md)
    safe_target = "".join(c if c.isalnum() or c in "._-" else "_" for c in target_label)[:64]
    short_id = sid.split("-")[0]
    filename = f"genesis-{safe_target}-{short_id}.md"
    return Response(
        content=body,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{session_id}/report.html")
async def download_session_html_report(
    session_id: uuid.UUID,
    audience: str = Query(default="combined", pattern="^(combined|executive|technical)$"),
    include_raw: bool = Query(default=True),
    max_evidence_chars: int = Query(default=1200, ge=200, le=10000),
    db: AsyncSession = Depends(get_db),
):
    """Render a self-contained HTML report for executive and technical readers."""
    from fastapi.responses import Response
    from app.services.html_report import render_session_html_report

    try:
        filename, body = await render_session_html_report(
            session_id,
            db,
            audience=audience,
            include_raw=include_raw,
            max_evidence_chars=max_evidence_chars,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")
    return Response(
        content=body,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
