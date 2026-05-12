"""Goal compiler endpoints — v6.0 T132.

POST /api/v1/goals/sessions/{session_id}    — compile NL goal into attack tree
GET  /api/v1/goals/sessions/{session_id}    — get current goal tree
"""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.middleware.auth import get_current_user_optional

router = APIRouter()


class GoalRequest(BaseModel):
    goal: str


class GoalTreeResponse(BaseModel):
    session_id: str
    goal_text: str
    compiled_tree: dict
    status: str


@router.post("/sessions/{session_id}", response_model=GoalTreeResponse, status_code=201)
async def create_goal(
    session_id: uuid.UUID,
    body: GoalRequest,
    user: Optional[dict] = Depends(get_current_user_optional),
):
    from app.services.goal_compiler import compile_goal
    from app.database.postgres import AsyncSessionLocal
    from app.models.user import Goal
    from sqlalchemy import select

    tree = await compile_goal(str(session_id), body.goal)

    async with AsyncSessionLocal() as db:
        # Upsert: replace any existing goal for this session
        r = await db.execute(select(Goal).where(Goal.session_id == session_id))
        existing = r.scalar_one_or_none()
        if existing:
            existing.goal_text = body.goal
            existing.compiled_tree = tree
            existing.status = "active"
            goal = existing
        else:
            goal = Goal(
                id=uuid.uuid4(),
                session_id=session_id,
                goal_text=body.goal,
                compiled_tree=tree,
                status="active",
            )
            db.add(goal)
        await db.commit()
        if not existing:
            await db.refresh(goal)

    # Also write to MongoDB goal_trees so the orchestrator can read it at session start
    try:
        from app.database.mongodb import get_goal_trees_collection
        gt_col = get_goal_trees_collection()  # NOTE: sync getter, do not await
        await gt_col.update_one(
            {"session_id": str(session_id)},
            {"$set": {**tree, "session_id": str(session_id), "goal_text": body.goal}},
            upsert=True,
        )
    except Exception as _exc:
        pass  # non-fatal; orchestrator falls back to auto-compile

    return GoalTreeResponse(
        session_id=str(session_id),
        goal_text=body.goal,
        compiled_tree=tree,
        status="active",
    )


async def _merge_live_progress(compiled_tree: dict, session_id: uuid.UUID) -> dict:
    """Decorate each sub_goal with status/evidence_count from goal_progress.

    Returns a shallow-copied tree so we don't mutate the cached PG/Mongo doc.
    Falls back to the un-decorated tree on any error — Goal tab still renders.
    """
    if not compiled_tree or not isinstance(compiled_tree, dict):
        return compiled_tree
    try:
        from app.database.mongodb import get_goal_progress_collection
        col = get_goal_progress_collection()
        doc = await col.find_one({"session_id": str(session_id)})
        progress_map = (doc or {}).get("progress") or {}
        if not progress_map:
            return compiled_tree
        decorated = dict(compiled_tree)
        new_phases = []
        for pi, phase in enumerate(compiled_tree.get("phases") or []):
            new_phase = dict(phase)
            new_sg = []
            for si, sg in enumerate(phase.get("sub_goals") or []):
                merged = dict(sg)
                entry = progress_map.get(f"{pi}.{si}")
                if entry:
                    if entry.get("status"):
                        merged["status"] = entry["status"]
                    if entry.get("evidence_count") is not None:
                        merged["evidence_count"] = entry["evidence_count"]
                new_sg.append(merged)
            new_phase["sub_goals"] = new_sg
            new_phases.append(new_phase)
        decorated["phases"] = new_phases
        return decorated
    except Exception:
        return compiled_tree


@router.get("/sessions/{session_id}", response_model=GoalTreeResponse)
async def get_goal(session_id: uuid.UUID):
    """Return the compiled goal tree for a session.

    Reads from PostgreSQL first; falls back to MongoDB `goal_trees` if the
    PG row is missing. Auto-compiled goals always write to both, but a
    transient PG failure (during session bootstrap) shouldn't make the Goal
    tab look broken when MongoDB has the data.
    """
    from app.database.postgres import AsyncSessionLocal
    from app.models.user import Goal
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        r = await db.execute(
            select(Goal).where(Goal.session_id == session_id).order_by(Goal.created_at.desc())
        )
        goal = r.scalar_one_or_none()

    if goal:
        decorated_tree = await _merge_live_progress(goal.compiled_tree, session_id)
        return GoalTreeResponse(
            session_id=str(session_id),
            goal_text=goal.goal_text,
            compiled_tree=decorated_tree,
            status=goal.status,
        )

    # MongoDB fallback: orchestrator's auto-compile writes here even when PG fails
    try:
        from app.database.mongodb import get_goal_trees_collection
        gt_col = get_goal_trees_collection()  # NOTE: sync getter
        gt_doc = await gt_col.find_one({"session_id": str(session_id)})
        if gt_doc and gt_doc.get("root"):
            gt_doc.pop("_id", None)
            decorated_tree = await _merge_live_progress(gt_doc, session_id)
            return GoalTreeResponse(
                session_id=str(session_id),
                goal_text=str(gt_doc.get("goal_text", "")),
                compiled_tree=decorated_tree,
                status="active",
            )
    except Exception:
        pass  # Mongo unavailable — fall through to 404

    raise HTTPException(status_code=404, detail="No goal set for this session")
