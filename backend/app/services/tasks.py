from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import threading
import traceback
from datetime import datetime, timezone

from celery.signals import worker_ready, worker_shutdown

from app.config import settings
from app.services.celery_app import celery_app

logger = logging.getLogger(__name__)


# ── T23 — worker capability heartbeat ─────────────────────────────────────
# Each worker writes its advertised capabilities into Redis under
# ``genesis:workers:<hostname>:capabilities`` with a short TTL, refreshed
# every 30s. Callers (or a future smart-dispatcher) can read this index to
# pick a worker with the right tools installed. Workers with an empty
# ``WORKER_CAPABILITIES`` env do NOT appear in the registry — they still
# serve the default ``research`` queue, matching today's single-host
# behaviour. Zero operational cost until a multi-host deploy turns it on.

_CAPABILITY_HEARTBEAT_INTERVAL_S = 30
_CAPABILITY_TTL_S = 90  # 3x the heartbeat — survives one missed tick.
_heartbeat_stop = threading.Event()
_heartbeat_thread: threading.Thread | None = None


def _parse_capabilities(raw: str) -> list[str]:
    return [tag.strip().lower() for tag in raw.split(",") if tag.strip()]


def _heartbeat_loop(worker_name: str, capabilities: list[str]) -> None:
    """Sync-Redis heartbeat so we don't need an async loop just for this."""
    try:
        import redis
    except ImportError:
        logger.debug("redis sync client not available; heartbeat skipped")
        return
    try:
        client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("heartbeat: cannot connect to redis: %s", exc)
        return

    key = f"genesis:workers:{worker_name}:capabilities"
    payload = json.dumps({
        "worker": worker_name,
        "capabilities": capabilities,
        "started_at": datetime.now(timezone.utc).isoformat(),
    })
    while not _heartbeat_stop.is_set():
        try:
            client.set(key, payload, ex=_CAPABILITY_TTL_S)
        except Exception as exc:  # noqa: BLE001
            logger.debug("heartbeat write failed: %s", exc)
        _heartbeat_stop.wait(_CAPABILITY_HEARTBEAT_INTERVAL_S)
    try:
        client.delete(key)
    except Exception:  # noqa: BLE001
        pass


@worker_ready.connect
def _on_worker_ready(sender=None, **_kwargs):  # noqa: D401
    """Start the capability heartbeat when Celery finishes boot."""
    global _heartbeat_thread
    raw = settings.worker_capabilities or os.environ.get("WORKER_CAPABILITIES", "")
    capabilities = _parse_capabilities(raw)
    if not capabilities:
        logger.info("worker_ready: no capabilities advertised (WORKER_CAPABILITIES empty)")
        return
    worker_name = (
        getattr(sender, "hostname", None) or os.environ.get("HOSTNAME") or socket.gethostname()
    )
    _heartbeat_stop.clear()
    _heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        args=(worker_name, capabilities),
        name="genesis-worker-heartbeat",
        daemon=True,
    )
    _heartbeat_thread.start()
    logger.info(
        "worker_ready: advertising capabilities=%s as %s (heartbeat every %ss, ttl %ss)",
        capabilities, worker_name, _CAPABILITY_HEARTBEAT_INTERVAL_S, _CAPABILITY_TTL_S,
    )


@worker_shutdown.connect
def _on_worker_shutdown(sender=None, **_kwargs):  # noqa: D401
    _heartbeat_stop.set()
    if _heartbeat_thread is not None:
        _heartbeat_thread.join(timeout=2)


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


def _reset_async_singletons() -> None:
    """Drop every module-level async singleton before a new `asyncio.run`.

    Celery's prefork worker reuses the same OS process across tasks. Each
    task calls `asyncio.run(...)` which spins up a *new* event loop; the
    previous loop is closed. Any cached async client (redis, motor, chroma,
    asyncpg pool) holds sockets/futures bound to the closed loop and will
    raise `RuntimeError: Event loop is closed` the first time we touch it.

    Resetting at the top of every task guarantees each run starts with
    fresh connections on the current loop.
    """
    try:
        from app.database.redis_client import reset_redis_client
        reset_redis_client()
    except Exception as exc:  # noqa: BLE001
        logger.debug("reset_redis_client failed: %s", exc)
    try:
        from app.database.mongodb import reset_mongo_client
        reset_mongo_client()
    except Exception as exc:  # noqa: BLE001
        logger.debug("reset_mongo_client failed: %s", exc)
    try:
        from app.database.chroma_client import reset_chroma_client
        reset_chroma_client()
    except Exception as exc:  # noqa: BLE001
        logger.debug("reset_chroma_client failed: %s", exc)
    try:
        from app.database.neo4j_client import reset_neo4j_client
        reset_neo4j_client()
    except Exception as exc:  # noqa: BLE001
        logger.debug("reset_neo4j_client failed: %s", exc)
    try:
        from app.services.artifact_resolver import reset_resolver
        reset_resolver()
    except Exception as exc:  # noqa: BLE001
        logger.debug("reset_resolver failed: %s", exc)


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
    _reset_async_singletons()
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
