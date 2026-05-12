from __future__ import annotations

import hmac
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.router import router as api_router
from app.websocket.router import router as ws_router

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",

)

_API_KEY = os.getenv("API_KEY", "")
# Expose Swagger docs only when no API key is configured (i.e. dev mode)
_DOCS_URL = None if _API_KEY else "/docs"
_REDOC_URL = None if _API_KEY else "/redoc"
_OPENAPI_URL = None if _API_KEY else "/openapi.json"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: startup + shutdown."""
    # ---- Startup ----
    logger.info("Starting up security research platform...")

    # PostgreSQL: create tables and seed default settings
    try:
        from app.database.postgres import create_tables, init_default_settings
        await create_tables()
        await init_default_settings()
        logger.info("PostgreSQL tables created and settings seeded.")
    except Exception as exc:
        logger.error("PostgreSQL init failed: %s", exc)

    # MongoDB: create indexes
    try:
        from app.database.mongodb import init_indexes
        await init_indexes()
        logger.info("MongoDB indexes created.")
    except Exception as exc:
        logger.error("MongoDB init failed: %s", exc)

    # v7.0: loop_state collection indexes
    try:
        from app.services.reasoning.loop_state import init_indexes as _init_loop_state_indexes
        await _init_loop_state_indexes()
        logger.info("v7 loop_state indexes created.")
    except Exception as exc:
        logger.error("v7 loop_state init failed: %s", exc)

    # Redis: warm up connection
    try:
        from app.database.redis_client import get_redis
        redis = await get_redis()
        await redis.ping()
        logger.info("Redis connection established.")
    except Exception as exc:
        logger.error("Redis init failed: %s", exc)

    # Neo4j (T21): ensure uniqueness constraints + indexes exist
    try:
        from app.database.neo4j_client import ensure_schema
        await ensure_schema()
        logger.info("Neo4j schema ensured.")
    except Exception as exc:
        logger.error("Neo4j schema init failed: %s", exc)

    yield

    # ---- Shutdown ----
    logger.info("Shutting down...")
    try:
        from app.database.redis_client import close_redis
        await close_redis()
    except Exception:
        pass
    try:
        from app.database.mongodb import close_mongo
        await close_mongo()
    except Exception:
        pass
    try:
        from app.database.postgres import engine
        await engine.dispose()
    except Exception:
        pass
    try:
        from app.database.neo4j_client import close_neo4j_driver
        await close_neo4j_driver()
    except Exception:
        pass


app = FastAPI(
    title="GENESIS",
    description="Generative Engine for Novel Exploitation & Security Intelligence Study",
    version="7.0 - Tier 9",
    lifespan=lifespan,
    docs_url=_DOCS_URL,
    redoc_url=_REDOC_URL,
    openapi_url=_OPENAPI_URL,
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)


# ---------------------------------------------------------------------------
# API key authentication middleware
# ---------------------------------------------------------------------------

_UNAUTHENTICATED_PATHS = {"/", "/health", "/api/v1/health"}
# OOB callback hit endpoint must be reachable by target servers with no API key
_UNAUTHENTICATED_PREFIXES = ("/api/v1/callback/hit/",)


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    api_key = _API_KEY
    # Auth disabled when no key is configured (development mode)
    if not api_key:
        return await call_next(request)
    if request.url.path in _UNAUTHENTICATED_PATHS:
        return await call_next(request)
    if any(request.url.path.startswith(p) for p in _UNAUTHENTICATED_PREFIXES):
        return await call_next(request)
    # WebSocket: accept key via ?token= query parameter
    if request.url.path.startswith("/ws/"):
        token = request.query_params.get("token", "")
        if token and hmac.compare_digest(token.encode(), api_key.encode()):
            return await call_next(request)
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    # REST: require X-API-Key header
    provided = request.headers.get("X-API-Key", "")
    if provided and hmac.compare_digest(provided.encode(), api_key.encode()):
        return await call_next(request)
    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid or missing X-API-Key header"},
    )

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(api_router, prefix="/api/v1")
app.include_router(ws_router)  # WebSocket at /ws/{session_id}

# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={"detail": "Resource not found", "path": str(request.url.path)},
    )


@app.exception_handler(500)
async def server_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled 500 error: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
