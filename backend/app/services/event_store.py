"""T146 — Event Store (append-only event log).

Emits structured events to PostgreSQL event_log table.
Supports replay from any sequence number for crash recovery.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, Optional

from sqlalchemy import text

logger = logging.getLogger(__name__)

# Canonical event types
EVENT_SESSION_CREATED = "session_created"
EVENT_PHASE_CHANGED = "phase_changed"
EVENT_TOOL_EXECUTED = "tool_executed"
EVENT_HYPOTHESIS_CONFIRMED = "hypothesis_confirmed"
EVENT_VULNERABILITY_FOUND = "vulnerability_found"
EVENT_FINDING_ESCALATED = "finding_escalated"
EVENT_SESSION_COMPLETED = "session_completed"
EVENT_AUDIT_ACTION = "audit_action"
EVENT_REPLICA_SPAWNED = "replica_spawned"
EVENT_GOAL_COMPILED = "goal_compiled"
EVENT_BUDGET_WARN = "budget_warn"
EVENT_BUDGET_BLOCKED = "budget_blocked"
EVENT_MODEL_DRIFT_ALERT = "model_drift_alert"


async def emit(session_id: str, event_type: str, payload: Dict[str, Any]) -> Optional[int]:
    """Append an event to the event_log. Returns the assigned seq."""
    from app.database.postgres import get_db_session

    now = datetime.now(timezone.utc)
    try:
        async with get_db_session() as db:
            result = await db.execute(
                text(
                    "INSERT INTO event_log (session_id, event_type, payload, ts) "
                    "VALUES (:session_id, :event_type, :payload::jsonb, :ts) "
                    "RETURNING seq"
                ),
                {
                    "session_id": session_id,
                    "event_type": event_type,
                    "payload": _serialize(payload),
                    "ts": now,
                },
            )
            await db.commit()
            row = result.fetchone()
            return row[0] if row else None
    except Exception as exc:
        logger.warning("event_store emit failed (%s %s): %s", session_id, event_type, exc)
        return None


def _serialize(payload: Dict[str, Any]) -> str:
    import json
    return json.dumps(payload, default=str)


async def replay(
    session_id: str,
    from_seq: int = 0,
    limit: int = 1000,
) -> AsyncGenerator[Dict[str, Any], None]:
    """Stream events for a session from from_seq onward."""
    from app.database.postgres import get_db_session
    import json

    async with get_db_session() as db:
        result = await db.execute(
            text(
                "SELECT seq, session_id, event_type, payload, ts FROM event_log "
                "WHERE session_id = :session_id AND seq >= :from_seq "
                "ORDER BY seq ASC LIMIT :limit"
            ),
            {"session_id": session_id, "from_seq": from_seq, "limit": limit},
        )
        for row in result:
            payload = row[3]
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except Exception:
                    pass
            yield {
                "seq": row[0],
                "session_id": row[1],
                "event_type": row[2],
                "payload": payload,
                "ts": row[4].isoformat() if row[4] else None,
            }


async def get_last_event(session_id: str) -> Optional[Dict[str, Any]]:
    """Return the last event for crash recovery / resume."""
    from app.database.postgres import get_db_session
    import json

    async with get_db_session() as db:
        result = await db.execute(
            text(
                "SELECT seq, event_type, payload, ts FROM event_log "
                "WHERE session_id = :session_id ORDER BY seq DESC LIMIT 1"
            ),
            {"session_id": session_id},
        )
        row = result.fetchone()
        if not row:
            return None
        payload = row[2]
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                pass
        return {
            "seq": row[0],
            "event_type": row[1],
            "payload": payload,
            "ts": row[3].isoformat() if row[3] else None,
        }
