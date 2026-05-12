"""Operator-goal subtask progress — live derivation.

The goal compiler emits a static attack tree at session start (root → phases →
sub_goals). Nothing in the system mutates it as the agent works, so the Goal
tab UI never showed progress. This module derives progress on-demand from
existing session state and broadcasts a single consolidated `goal_progress`
WS event.

Signals used (loose heuristic, intentionally conservative):
- A sub_goal flips to "in_progress" the first time a tool whose name overlaps
  one of its `probe_hints` runs.
- It flips to "done" when a stored vulnerability or a confirmed hypothesis
  carries enough keyword overlap with the sub_goal description.

The matching is fuzzy by design — `probe_hints` is free-text from the LLM, and
the vulnerability/hypothesis text is free-form. Better to occasionally show
"in_progress" too eagerly than to leave the tree frozen at 0%.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.database.mongodb import (
    get_goal_progress_collection,
    get_goal_trees_collection,
    get_hypothesis_journals_collection,
    get_tool_outputs_collection,
)
from app.database.postgres import AsyncSessionLocal
from app.database.redis_client import publish_session_message

logger = logging.getLogger(__name__)

# Per-session debounce timestamps (monotonic). Tool storms (parallel nuclei
# templates etc.) shouldn't trigger 50 recomputes — one consolidated update
# per ~2s is enough for human-perceived realtime.
_DEBOUNCE_WINDOW_SECONDS = 2.0
_last_compute: Dict[str, float] = {}
_inflight: Dict[str, asyncio.Task] = {}

# Stopwords stripped before keyword overlap. Includes generic security verbs
# that appear in nearly every sub_goal description.
_STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "of", "for", "in", "on", "at", "by",
    "with", "from", "as", "is", "are", "be", "been", "being", "this", "that",
    "via", "any", "all", "all-", "find", "test", "scan", "check", "verify",
    "identify", "enumerate", "discover", "look", "search", "attempt", "try",
    "use", "run", "achieve", "perform", "do", "get", "set",
}


def _tokens(text: str) -> set[str]:
    """Lowercase, alnum-only word set with stopwords stripped."""
    if not text:
        return set()
    raw = re.findall(r"[a-z0-9]+", text.lower())
    return {w for w in raw if len(w) >= 4 and w not in _STOPWORDS}


def _hint_matches_tool(hint: str, tool_name: str) -> bool:
    """Loose match between a probe_hint and an executed tool name.

    `probe_hints` examples: "nmap_scan", "nuclei_scan", "idor_probe",
    "ai_request_forge". Tool names are exact module names. Strip common
    suffixes and check substring overlap in either direction.
    """
    if not hint or not tool_name:
        return False
    h = hint.lower().strip()
    t = tool_name.lower().strip()
    if h == t:
        return True
    # Strip common probe_hint suffixes the LLM tacks on
    for suffix in ("_scan", "_probe", "_check", "_analyze", "_run"):
        if h.endswith(suffix):
            h = h[: -len(suffix)]
            break
    return h in t or t in h


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _load_compiled_tree(session_id: str) -> Optional[Dict[str, Any]]:
    try:
        gt_col = get_goal_trees_collection()
        doc = await gt_col.find_one({"session_id": str(session_id)})
        if not doc:
            return None
        if doc.get("phases"):
            return doc
    except Exception as exc:  # noqa: BLE001
        logger.debug("goal_progress: mongo goal_trees lookup failed: %s", exc)
    # PG fallback — orchestrator may have only written to PG
    try:
        from sqlalchemy import select  # noqa: WPS433
        from app.models.user import Goal  # noqa: WPS433
        async with AsyncSessionLocal() as db:
            r = await db.execute(
                select(Goal).where(Goal.session_id == session_id).order_by(Goal.created_at.desc())
            )
            goal = r.scalar_one_or_none()
            if goal and goal.compiled_tree:
                return dict(goal.compiled_tree)
    except Exception as exc:  # noqa: BLE001
        logger.debug("goal_progress: pg goal lookup failed: %s", exc)
    return None


async def _load_session_vulnerabilities(session_id: str) -> list[Dict[str, Any]]:
    """Pull (title, description, affected_service, severity) for the session."""
    try:
        from sqlalchemy import select  # noqa: WPS433
        from app.models.vulnerability import Vulnerability  # noqa: WPS433
        async with AsyncSessionLocal() as db:
            r = await db.execute(
                select(Vulnerability).where(Vulnerability.session_id == session_id)
            )
            return [
                {
                    "id": str(v.id),
                    "title": v.title or "",
                    "description": v.description or "",
                    "affected_service": v.affected_service or "",
                    "severity": v.severity or "",
                    "cve_ids": list(v.cve_ids or []),
                }
                for v in r.scalars().all()
            ]
    except Exception as exc:  # noqa: BLE001
        logger.debug("goal_progress: vulnerabilities load failed: %s", exc)
        return []


async def _load_confirmed_hypotheses(session_id: str) -> list[Dict[str, Any]]:
    try:
        col = get_hypothesis_journals_collection()
        cursor = col.find(
            {"session_id": str(session_id), "status": "confirmed"},
            {"statement": 1, "next_test": 1, "_id": 0},
        )
        return [doc async for doc in cursor]
    except Exception as exc:  # noqa: BLE001
        logger.debug("goal_progress: hypothesis load failed: %s", exc)
        return []


async def _load_tools_run(session_id: str) -> list[Dict[str, Any]]:
    try:
        col = get_tool_outputs_collection()
        cursor = col.find(
            {"session_id": str(session_id)},
            {"tool_name": 1, "timestamp": 1, "_id": 1},
        ).sort("timestamp", -1)
        return [
            {"tool_name": doc.get("tool_name", ""), "id": str(doc.get("_id", ""))}
            async for doc in cursor
        ]
    except Exception as exc:  # noqa: BLE001
        logger.debug("goal_progress: tool_outputs load failed: %s", exc)
        return []


async def compute_progress(session_id: str) -> Dict[str, Dict[str, Any]]:
    """Derive progress map keyed by `"{phase_idx}.{subgoal_idx}"`.

    Returns {} if there's no compiled goal tree for this session.
    """
    tree = await _load_compiled_tree(session_id)
    if not tree:
        return {}

    phases = tree.get("phases") or []
    if not phases:
        return {}

    tools_run, vulns, confirmed_hyps = await asyncio.gather(
        _load_tools_run(session_id),
        _load_session_vulnerabilities(session_id),
        _load_confirmed_hypotheses(session_id),
    )

    progress: Dict[str, Dict[str, Any]] = {}

    for pi, phase in enumerate(phases):
        sub_goals = phase.get("sub_goals") or []
        for si, sg in enumerate(sub_goals):
            sg_id = f"{pi}.{si}"
            description = sg.get("description") or ""
            probe_hints = sg.get("probe_hints") or []
            desc_tokens = _tokens(description)

            status = "pending"
            evidence_count = 0
            last_tool: Optional[str] = None
            last_finding_id: Optional[str] = None

            # Signal 1: probe_hint overlap with executed tools → in_progress
            for tool in tools_run:
                tname = tool.get("tool_name") or ""
                if any(_hint_matches_tool(h, tname) for h in probe_hints):
                    status = "in_progress"
                    evidence_count += 1
                    if last_tool is None:
                        last_tool = tname

            # Signal 2: vulnerability description / title / service overlap → done
            for v in vulns:
                v_text = " ".join([
                    v.get("title", ""),
                    v.get("description", ""),
                    v.get("affected_service", ""),
                    " ".join(v.get("cve_ids", [])),
                ])
                v_tokens = _tokens(v_text)
                if desc_tokens and len(desc_tokens & v_tokens) >= 2:
                    status = "done"
                    evidence_count += 1
                    if last_finding_id is None:
                        last_finding_id = v.get("id")

            # Signal 3: confirmed hypothesis statement overlap → done
            for h in confirmed_hyps:
                h_tokens = _tokens(h.get("statement", "") + " " + h.get("next_test", ""))
                if desc_tokens and len(desc_tokens & h_tokens) >= 2:
                    status = "done"
                    evidence_count += 1

            progress[sg_id] = {
                "status": status,
                "evidence_count": evidence_count,
                "last_tool": last_tool,
                "last_finding_id": last_finding_id,
            }

    return progress


async def _do_persist_and_broadcast(session_id: str) -> None:
    try:
        progress = await compute_progress(session_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("goal_progress: compute failed for %s: %s", session_id, exc)
        return
    if not progress:
        return

    last_updated = _now_iso()

    try:
        col = get_goal_progress_collection()
        await col.update_one(
            {"session_id": str(session_id)},
            {"$set": {
                "session_id": str(session_id),
                "progress": progress,
                "last_updated": last_updated,
            }},
            upsert=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("goal_progress: mongo upsert failed for %s: %s", session_id, exc)

    try:
        await publish_session_message(str(session_id), {
            "type": "goal_progress",
            "data": {
                "progress": progress,
                "last_updated": last_updated,
            },
            "timestamp": last_updated,
        })
    except Exception as exc:  # noqa: BLE001
        logger.debug("goal_progress: ws publish failed for %s: %s", session_id, exc)


async def finalize_unachieved_subgoals(session_id: str) -> Dict[str, Dict[str, Any]]:
    """Called at session-end. Marks every sub-goal NOT in 'done' state as
    'not_achieved' with an auto-generated reason that distinguishes
    'we tried but found nothing' from 'we never even got to it'. The
    progress doc is upserted and broadcast so the operator-goal UI flips
    from in_progress -> not_achieved + reason text.

    Returns the updated progress map.
    """
    progress = await compute_progress(session_id)
    if not progress:
        return {}
    for sg_id, info in progress.items():
        st = info.get("status", "pending")
        if st == "done":
            continue
        if st == "in_progress":
            info["status"] = "not_achieved"
            info["reason"] = (
                "Probed but no matching findings or confirmed hypotheses "
                "emerged before session end."
            )
        else:  # pending
            info["status"] = "not_achieved"
            info["reason"] = (
                "Sub-goal was never exercised — no tool ran whose name "
                "overlapped the probe_hints. Likely outside the agent's "
                "explored attack surface."
            )

    last_updated = _now_iso()
    try:
        col = get_goal_progress_collection()
        await col.update_one(
            {"session_id": str(session_id)},
            {"$set": {
                "session_id": str(session_id),
                "progress": progress,
                "last_updated": last_updated,
                "finalized": True,
            }},
            upsert=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("goal_progress: finalize upsert failed for %s: %s", session_id, exc)

    try:
        await publish_session_message(str(session_id), {
            "type": "goal_progress",
            "data": {
                "progress": progress,
                "last_updated": last_updated,
                "finalized": True,
            },
            "timestamp": last_updated,
        })
    except Exception as exc:  # noqa: BLE001
        logger.debug("goal_progress: finalize broadcast failed: %s", exc)

    return progress


def schedule_recompute(session_id: str) -> None:
    """Fire-and-forget, debounced recompute trigger.

    Safe to call from any orchestrator hook — never raises, never blocks the
    caller's main loop. If a recompute for this session is in-flight or fired
    within the debounce window, drops the call.
    """
    if not session_id:
        return
    sid = str(session_id)
    now = time.monotonic()
    last = _last_compute.get(sid, 0.0)
    if now - last < _DEBOUNCE_WINDOW_SECONDS:
        return
    inflight = _inflight.get(sid)
    if inflight is not None and not inflight.done():
        return
    _last_compute[sid] = now
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return  # No running loop — caller is not inside async context
    task = loop.create_task(_do_persist_and_broadcast(sid))
    _inflight[sid] = task

    def _cleanup(_t: asyncio.Task) -> None:
        _inflight.pop(sid, None)

    task.add_done_callback(_cleanup)
