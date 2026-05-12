"""T102 — long_horizon_planner: cross-session rolling attack tree.

Extends plan_tree.py (T11 per-session plans) to maintain a persistent,
cross-session rolling attack tree per engagement (target IP).

MongoDB collection `long_horizon_plans`:
  {engagement_id, target_ip, open_questions: [], completed_chains: [],
   current_frontier: [], created_at, updated_at}

At session start the orchestrator calls `get_open_questions(target_ip)` to
inject unresolved attack threads from prior sessions into the context.
At session end it calls `update_from_session()` to persist new findings and
close answered questions.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database.mongodb import get_db

logger = logging.getLogger(__name__)

_COLLECTION = "long_horizon_plans"


# ---------------------------------------------------------------------------
# Plan lifecycle
# ---------------------------------------------------------------------------

async def get_or_create_plan(target_ip: str) -> Dict[str, Any]:
    """Return the existing long-horizon plan for target_ip, or create a new one."""
    db = await get_db()
    doc = await db[_COLLECTION].find_one({"target_ip": target_ip})
    if doc:
        doc.pop("_id", None)
        return doc

    engagement_id = f"eng-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    plan: Dict[str, Any] = {
        "engagement_id": engagement_id,
        "target_ip": target_ip,
        "open_questions": [],
        "completed_chains": [],
        "current_frontier": [],
        "sessions": [],
        "created_at": now,
        "updated_at": now,
    }
    await db[_COLLECTION].insert_one(plan)
    plan.pop("_id", None)
    logger.info("long_horizon_planner: created plan %s for %s", engagement_id, target_ip)
    return plan


async def get_open_questions(
    target_ip: str,
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """Return unresolved open questions for the target, ordered by priority."""
    try:
        db = await get_db()
        doc = await db[_COLLECTION].find_one({"target_ip": target_ip})
        if not doc:
            return []
        questions = doc.get("open_questions", [])
        # Sort by priority (higher = more important), return top N
        questions.sort(key=lambda q: q.get("priority", 0), reverse=True)
        return questions[:limit]
    except Exception as exc:
        logger.warning("get_open_questions failed: %s", exc)
        return []


async def add_open_question(
    target_ip: str,
    question: str,
    source_session_id: str = "",
    priority: float = 0.5,
    context: str = "",
) -> bool:
    """Add a new open question (unresolved attack thread) to the plan."""
    try:
        db = await get_db()
        entry = {
            "question_id": f"q-{uuid.uuid4().hex[:8]}",
            "question": question[:500],
            "source_session_id": source_session_id,
            "priority": priority,
            "context": context[:300],
            "added_at": datetime.now(timezone.utc).isoformat(),
            "resolved": False,
        }
        await db[_COLLECTION].update_one(
            {"target_ip": target_ip},
            {
                "$push": {"open_questions": entry},
                "$set": {"updated_at": datetime.now(timezone.utc)},
            },
            upsert=True,
        )
        return True
    except Exception as exc:
        logger.warning("add_open_question failed: %s", exc)
        return False


async def resolve_question(target_ip: str, question_id: str, resolution: str = "") -> bool:
    """Mark an open question as resolved."""
    try:
        db = await get_db()
        await db[_COLLECTION].update_one(
            {"target_ip": target_ip, "open_questions.question_id": question_id},
            {
                "$set": {
                    "open_questions.$.resolved": True,
                    "open_questions.$.resolution": resolution[:300],
                    "open_questions.$.resolved_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )
        return True
    except Exception as exc:
        logger.warning("resolve_question failed: %s", exc)
        return False


async def update_from_session(
    session_id: str,
    target_ip: str,
    confirmed_vulns: List[Dict[str, Any]],
    new_questions: Optional[List[str]] = None,
) -> bool:
    """Update the long-horizon plan after a session completes.

    - Adds confirmed vulnerability chains to `completed_chains`
    - Appends any new unresolved questions raised during the session
    - Records the session ID in the plan's session history
    """
    try:
        db = await get_db()
        now = datetime.now(timezone.utc)

        # Build completed chain entries from confirmed vulns
        chain_entries = [
            {
                "vuln_id": str(v.get("id", "")),
                "title": v.get("title", "")[:200],
                "severity": v.get("severity", ""),
                "session_id": session_id,
                "found_at": now.isoformat(),
            }
            for v in confirmed_vulns[:20]
        ]

        update_ops: Dict[str, Any] = {
            "$push": {
                "sessions": session_id,
            },
            "$set": {"updated_at": now},
        }

        if chain_entries:
            update_ops["$push"]["completed_chains"] = {"$each": chain_entries}

        await db[_COLLECTION].update_one(
            {"target_ip": target_ip},
            update_ops,
            upsert=True,
        )

        # Add new open questions
        for q in (new_questions or [])[:5]:
            await add_open_question(
                target_ip=target_ip,
                question=q,
                source_session_id=session_id,
                priority=0.5,
            )

        logger.info(
            "long_horizon_planner: updated plan for %s (chains=%d, new_questions=%d)",
            target_ip, len(chain_entries), len(new_questions or []),
        )
        return True
    except Exception as exc:
        logger.warning("update_from_session failed: %s", exc)
        return False


async def get_plan(target_ip: str) -> Optional[Dict[str, Any]]:
    """Retrieve the full long-horizon plan for a target."""
    try:
        db = await get_db()
        doc = await db[_COLLECTION].find_one({"target_ip": target_ip})
        if doc:
            doc.pop("_id", None)
        return doc
    except Exception as exc:
        logger.warning("get_plan failed: %s", exc)
        return None


async def format_for_context(target_ip: str, max_questions: int = 3) -> str:
    """Return a compact context string for injection into the LLM system prompt."""
    questions = await get_open_questions(target_ip, limit=max_questions)
    if not questions:
        return ""
    lines = ["## Prior Session Open Questions (Long-Horizon Plan)"]
    for q in questions:
        lines.append(f"- {q['question']}")
        if q.get("context"):
            lines.append(f"  Context: {q['context']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# T133 — Counterfactual path generator
# ---------------------------------------------------------------------------

async def generate_counterfactual_paths(
    blocked_step: str,
    attack_tree: Dict[str, Any],
    client: Any = None,
    model: str = "claude-haiku-4-5-20251001",
) -> List[Dict[str, Any]]:
    """T133: Generate 3-5 alternative attack paths when a step is blocked.

    Args:
        blocked_step: Description of the blocked/failed attack step.
        attack_tree: Current session attack tree (from goal_trees MongoDB collection).
        client: Anthropic client (optional; skips LLM if None).
        model: Model to use for generation.

    Returns:
        List of alternative path dicts: [{path, rationale, requires, confidence}]
    """
    if not client:
        return []

    try:
        import json as _json
        tree_summary = _json.dumps(attack_tree, default=str)[:2000]
        prompt = (
            f"An attack step was blocked: {blocked_step}\n\n"
            f"Current attack tree:\n{tree_summary}\n\n"
            "Generate 3-5 alternative attack paths that work around this blockage. "
            "Return JSON array: [{\"path\": \"description\", \"rationale\": \"why this works\", "
            "\"requires\": \"what finding type is needed first\", \"confidence\": 0.0-1.0}]"
        )
        response = await client.messages.create(
            model=model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text if response.content else ""
        start = text.find("[")
        end = text.rfind("]") + 1
        if start >= 0 and end > start:
            paths = _json.loads(text[start:end])
            return paths[:5]
    except Exception as exc:
        logger.warning("generate_counterfactual_paths failed: %s", exc)
    return []


# ---------------------------------------------------------------------------
# T134 — Multi-session kill-chain planner
# ---------------------------------------------------------------------------

async def plan_kill_chain(
    goal_tree: Dict[str, Any],
    current_findings: List[Dict[str, Any]],
    prior_sessions: List[str],
    target_ip: str,
    client: Any = None,
    model: str = "claude-haiku-4-5-20251001",
) -> Dict[str, Any]:
    """T134: Plan a multi-session kill chain toward the operator goal.

    Generates a structured kill chain plan with steps, missing prerequisites,
    and open questions tagged with 'requires: <finding_type>'.

    Args:
        goal_tree: Compiled goal tree from T132 goal_compiler.
        current_findings: Confirmed findings from this and prior sessions.
        prior_sessions: List of session IDs already completed against this target.
        target_ip: Target IP for plan persistence.
        client: Anthropic client (optional).
        model: Model to use.

    Returns:
        Kill chain plan dict: {steps, missing_prerequisites, open_questions, confidence}
    """
    empty_plan: Dict[str, Any] = {
        "steps": [],
        "missing_prerequisites": [],
        "open_questions": [],
        "confidence": 0.0,
    }
    if not client:
        return empty_plan

    try:
        import json as _json
        goal_summary = _json.dumps(goal_tree, default=str)[:1500]
        findings_summary = _json.dumps(
            [{"title": f.get("title"), "severity": f.get("severity")} for f in current_findings[:20]],
            default=str,
        )

        prompt = (
            f"Target: {target_ip}\n"
            f"Operator goal tree:\n{goal_summary}\n\n"
            f"Confirmed findings so far:\n{findings_summary}\n\n"
            f"Prior session count: {len(prior_sessions)}\n\n"
            "Plan a multi-session kill chain to achieve the operator goal. "
            "Identify what's confirmed, what's missing, and what open questions "
            "require specific finding types from future sessions. "
            "Return JSON: {\"steps\": [{\"step\": str, \"status\": \"done|pending\", "
            "\"evidence\": str}], \"missing_prerequisites\": [str], "
            "\"open_questions\": [{\"question\": str, \"requires\": str}], "
            "\"confidence\": 0.0-1.0}"
        )
        response = await client.messages.create(
            model=model,
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text if response.content else ""
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            plan = _json.loads(text[start:end])
            # Persist open questions with 'requires' tag to long-horizon plan
            for oq in plan.get("open_questions", [])[:5]:
                await add_open_question(
                    target_ip=target_ip,
                    question=oq.get("question", "")[:300],
                    priority=0.7,
                    context=f"requires: {oq.get('requires', '')}",
                )
            return plan
    except Exception as exc:
        logger.warning("plan_kill_chain failed: %s", exc)
    return empty_plan
