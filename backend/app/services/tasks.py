from __future__ import annotations

import asyncio
import logging
import traceback
from datetime import datetime, timezone

from app.services.celery_app import celery_app

logger = logging.getLogger(__name__)


def _record_celery_error(session_id: str, exc: BaseException) -> None:
    """Record a Celery-level exception into session_errors.

    This path runs outside the orchestrator's event loop, so it opens a fresh
    motor client via `asyncio.run` and never raises.
    """
    try:
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        doc = {
            "session_id": session_id,
            "phase": "celery_task",
            "error_type": type(exc).__name__,
            "error_message": str(exc)[:4000],
            "traceback": tb[:8000],
            "iteration": None,
            "tool": None,
            "context": {},
            "timestamp": datetime.now(timezone.utc),
        }

        async def _insert() -> None:
            # Fresh loop — drop any module-level Motor client bound to the
            # orchestrator's (now dead) loop before touching Mongo.
            from app.database.mongodb import reset_mongo_client, get_session_errors_collection
            reset_mongo_client()
            await get_session_errors_collection().insert_one(doc)

        asyncio.run(_insert())
    except Exception as inner:
        logger.debug("_record_celery_error failed: %s", inner)


def _mark_session_failed(session_id: str, reason: str) -> None:
    """Flip the session row to status=failed when the orchestrator couldn't.

    Used when the Celery task itself crashes (e.g. import error, asyncio.run
    raised) before the orchestrator's own `_set_session_failed` could fire.
    """
    try:
        from sqlalchemy import update
        from app.database.postgres import AsyncSessionLocal, engine
        from app.models.session import ResearchSession
        import uuid as _uuid

        async def _update() -> None:
            await engine.dispose()
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ResearchSession)
                    .where(ResearchSession.id == _uuid.UUID(session_id))
                    .values(
                        status="failed",
                        completed_at=datetime.now(timezone.utc),
                        summary=f"Session failed: {reason[:500]}",
                    )
                )
                await db.commit()

        asyncio.run(_update())
    except Exception as inner:
        logger.debug("_mark_session_failed failed: %s", inner)


@celery_app.task(
    bind=True,
    name="app.services.tasks.run_research_session",
    queue="research",
    max_retries=0,
)
def run_research_session(self, session_id: str, target_ip: str) -> dict:
    """
    Celery task that drives a full autonomous security research session.
    Calls asyncio.run() so the async orchestrator can run inside this sync Celery task.
    """
    from app.services.ai_orchestrator import AIOrchestrator

    logger.info("Celery task started: session_id=%s target_ip=%s", session_id, target_ip)
    try:
        orchestrator = AIOrchestrator()
        asyncio.run(orchestrator.run_session(session_id, target_ip))
        logger.info("Celery task completed: session_id=%s", session_id)
        return {"session_id": session_id, "status": "completed"}
    except Exception as exc:
        logger.exception("Celery task failed: session_id=%s error=%s", session_id, exc)
        _record_celery_error(session_id, exc)
        # Best-effort: ensure the DB row reflects the failure even if the
        # orchestrator never got far enough to call _set_session_failed.
        _mark_session_failed(session_id, f"{type(exc).__name__}: {str(exc)[:500]}")
        return {"session_id": session_id, "status": "failed", "error": str(exc)}
