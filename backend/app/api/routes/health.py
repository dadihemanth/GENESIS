from __future__ import annotations

import asyncio
from typing import Any, Dict

import httpx
from fastapi import APIRouter

from app.config import settings

router = APIRouter()


async def _check_postgres() -> Dict[str, Any]:
    try:
        from app.database.postgres import engine
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        return {"status": "ok"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


async def _check_mongodb() -> Dict[str, Any]:
    try:
        from app.database.mongodb import _get_client
        client = _get_client()
        await client.admin.command("ping")
        return {"status": "ok"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


async def _check_redis() -> Dict[str, Any]:
    try:
        from app.database.redis_client import get_redis
        redis = await get_redis()
        pong = await redis.ping()
        return {"status": "ok" if pong else "error"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


async def _check_chroma() -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://{settings.chroma_host}:{settings.chroma_port}/api/v1/heartbeat")
            if resp.status_code == 200:
                return {"status": "ok"}
            return {"status": "error", "detail": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


async def _check_mcp() -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.mcp_base_url}/health")
            if resp.status_code == 200:
                return {"status": "ok", "detail": resp.json()}
            return {"status": "error", "detail": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


async def _check_neo4j() -> Dict[str, Any]:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(settings.neo4j_uri)
        host = parsed.hostname or "neo4j"
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://{host}:7474")
            if resp.status_code in (200, 401):
                return {"status": "ok"}
            return {"status": "error", "detail": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


async def _check_minio() -> Dict[str, Any]:
    try:
        endpoint = settings.minio_endpoint or "minio:9000"
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://{endpoint}/minio/health/live")
            if resp.status_code == 200:
                return {"status": "ok"}
            return {"status": "error", "detail": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


@router.get("")
async def health_check() -> Dict[str, Any]:
    """Public liveness probe — returns status only, no service topology."""
    results = await asyncio.gather(
        _check_postgres(),
        _check_mongodb(),
        _check_redis(),
        _check_chroma(),
        _check_mcp(),
        _check_neo4j(),
        _check_minio(),
        return_exceptions=False,
    )
    all_ok = all(r.get("status") == "ok" for r in results)
    return {"status": "healthy" if all_ok else "degraded"}


@router.get("/detailed")
async def health_check_detailed() -> Dict[str, Any]:
    """Authenticated detailed health check including per-service status."""
    postgres_result, mongo_result, redis_result, chroma_result, mcp_result, neo4j_result, minio_result = await asyncio.gather(
        _check_postgres(),
        _check_mongodb(),
        _check_redis(),
        _check_chroma(),
        _check_mcp(),
        _check_neo4j(),
        _check_minio(),
        return_exceptions=False,
    )

    all_ok = all(
        r.get("status") == "ok"
        for r in [postgres_result, mongo_result, redis_result, chroma_result, mcp_result, neo4j_result, minio_result]
    )

    return {
        "status": "healthy" if all_ok else "degraded",
        "services": {
            "postgres": postgres_result,
            "mongodb": mongo_result,
            "redis": redis_result,
            "chromadb": chroma_result,
            "mcp_server": mcp_result,
            "neo4j": neo4j_result,
            "minio": minio_result,
        },
    }
