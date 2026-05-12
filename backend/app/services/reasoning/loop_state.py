"""v7 loop_state — persistence for reasoning-loop intermediate state.

One MongoDB document per loop run. Each tick is appended to `ticks[]` so the
full trace is replayable for the frontend Reasoning Loops tab and ingestable
as v8 training corpus.

Schema (MongoDB collection `loop_state`):
  {
    "loop_id":     "loop-{uuid}",         # primary key
    "session_id":  "...",
    "loop_type":   "code_intent|rop_composition|...",
    "status":      "running|complete|aborted",
    "inputs":      {...},                 # original arguments
    "ticks":       [
      {
        "iteration":      1,
        "state_snapshot": {...},          # working memory at this tick
        "branches":       [...],          # candidates considered
        "chosen":         "...",          # which branch we committed to
        "reasoning":      "...",          # short LLM rationale
        "tokens":         123,            # tokens spent this tick
        "ts":             ISO8601,
      },
      ...
    ],
    "result":       {...},                # final output (or partial if aborted)
    "tokens_spent": 0,                    # cumulative
    "tick_count":   0,
    "created_at":   datetime,
    "updated_at":   datetime,
  }
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database.mongodb import get_db
from app.database.redis_client import publish_session_message

logger = logging.getLogger(__name__)

_COLLECTION = "loop_state"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


async def create_loop(
    session_id: str,
    loop_type: str,
    inputs: Dict[str, Any],
) -> str:
    """Create a new loop document and return its loop_id."""
    loop_id = f"loop-{uuid.uuid4().hex[:12]}"
    doc: Dict[str, Any] = {
        "loop_id": loop_id,
        "session_id": session_id,
        "loop_type": loop_type,
        "status": "running",
        "inputs": inputs,
        "ticks": [],
        "result": None,
        "tokens_spent": 0,
        "tick_count": 0,
        "created_at": _now(),
        "updated_at": _now(),
    }
    try:
        db = await get_db()
        await db[_COLLECTION].insert_one(doc)
    except Exception as exc:
        logger.warning("loop_state create failed (%s): %s", loop_type, exc)

    try:
        await publish_session_message(session_id, {
            "type": "loop_started",
            "data": {"loop_id": loop_id, "loop_type": loop_type, "inputs_keys": list(inputs.keys())[:10]},
            "timestamp": _now_iso(),
        })
    except Exception:
        pass

    return loop_id


async def append_tick(
    session_id: str,
    loop_id: str,
    *,
    state_snapshot: Dict[str, Any],
    branches: Optional[List[Dict[str, Any]]] = None,
    chosen: Optional[str] = None,
    reasoning: str = "",
    tokens: int = 0,
) -> int:
    """Append a tick record. Returns the new tick_count."""
    tick: Dict[str, Any] = {
        "iteration": 0,  # filled below
        "state_snapshot": state_snapshot,
        "branches": branches or [],
        "chosen": chosen,
        "reasoning": reasoning[:1500],
        "tokens": int(tokens),
        "ts": _now_iso(),
    }
    new_count = 0
    try:
        db = await get_db()
        existing = await db[_COLLECTION].find_one({"loop_id": loop_id}, projection={"tick_count": 1})
        new_count = (existing or {}).get("tick_count", 0) + 1
        tick["iteration"] = new_count
        await db[_COLLECTION].update_one(
            {"loop_id": loop_id},
            {
                "$push": {"ticks": tick},
                "$inc": {"tokens_spent": int(tokens), "tick_count": 1},
                "$set": {"updated_at": _now()},
            },
        )
    except Exception as exc:
        logger.warning("loop_state append_tick failed: %s", exc)

    try:
        await publish_session_message(session_id, {
            "type": "loop_tick",
            "data": {
                "loop_id": loop_id,
                "iteration": new_count,
                "chosen": chosen,
                "reasoning": tick["reasoning"],
                "branch_count": len(tick["branches"]),
                "tokens": int(tokens),
            },
            "timestamp": _now_iso(),
        })
    except Exception:
        pass

    return new_count


async def finalize_loop(
    session_id: str,
    loop_id: str,
    *,
    status: str,                      # "complete" | "aborted"
    result: Optional[Dict[str, Any]] = None,
) -> None:
    """Mark the loop done."""
    if status not in ("complete", "aborted"):
        status = "aborted"
    try:
        db = await get_db()
        await db[_COLLECTION].update_one(
            {"loop_id": loop_id},
            {"$set": {"status": status, "result": result, "updated_at": _now()}},
        )
    except Exception as exc:
        logger.warning("loop_state finalize failed: %s", exc)

    try:
        await publish_session_message(session_id, {
            "type": "loop_finished",
            "data": {
                "loop_id": loop_id,
                "status": status,
                "result_keys": list((result or {}).keys())[:10],
            },
            "timestamp": _now_iso(),
        })
    except Exception:
        pass


async def get_loop(loop_id: str) -> Optional[Dict[str, Any]]:
    try:
        db = await get_db()
        doc = await db[_COLLECTION].find_one({"loop_id": loop_id})
        if doc:
            doc.pop("_id", None)
        return doc
    except Exception as exc:
        logger.warning("loop_state get_loop failed: %s", exc)
        return None


async def list_session_loops(
    session_id: str,
    loop_type: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Return loops for a session, newest first. Ticks are stripped to a count."""
    try:
        db = await get_db()
        query: Dict[str, Any] = {"session_id": session_id}
        if loop_type:
            query["loop_type"] = loop_type
        cursor = (
            db[_COLLECTION]
            .find(query, projection={"ticks": 0})
            .sort("created_at", -1)
            .limit(min(limit, 200))
        )
        out: List[Dict[str, Any]] = []
        async for doc in cursor:
            doc.pop("_id", None)
            out.append(doc)
        return out
    except Exception as exc:
        logger.warning("loop_state list_session_loops failed: %s", exc)
        return []


async def init_indexes() -> None:
    try:
        db = await get_db()
        await db[_COLLECTION].create_index("loop_id", unique=True)
        await db[_COLLECTION].create_index("session_id")
        await db[_COLLECTION].create_index([("session_id", 1), ("created_at", -1)])
        await db[_COLLECTION].create_index("loop_type")
    except Exception as exc:
        logger.warning("loop_state init_indexes failed: %s", exc)
