from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import health, intelligence, sessions, settings, tools, vulnerabilities, callback, session_memory

router = APIRouter()

router.include_router(health.router, prefix="/health", tags=["health"])
router.include_router(sessions.router, prefix="/sessions", tags=["sessions"])
router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
router.include_router(settings.router, prefix="/settings", tags=["settings"])
router.include_router(tools.router, prefix="/tools", tags=["tools"])
router.include_router(intelligence.router, prefix="/intelligence", tags=["intelligence"])
router.include_router(callback.router, prefix="/callback", tags=["callback"])
router.include_router(session_memory.router, prefix="/session-memory", tags=["session-memory"])
