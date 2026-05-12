from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.database.redis_client import get_redis

router = APIRouter()

_TTL = 3600  # tokens expire after 1 hour


def _key(token: str) -> str:
    return f"genesis:oob:{token}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("/generate")
async def generate_token(description: str = "") -> Dict[str, Any]:
    """Generate a unique OOB callback token and return its listener URL."""
    token = secrets.token_hex(16)
    redis = await get_redis()
    await redis.set(_key(token), json.dumps({
        "created_at": _now(),
        "description": description,
        "hits": [],
    }), ex=_TTL)
    return {
        "token": token,
        "http_url": f"http://genesis-backend:8000/api/v1/callback/hit/{token}",
        "description": description,
    }


@router.get("/hit/{token}")
@router.post("/hit/{token}")
async def record_hit(token: str, request: Request) -> JSONResponse:
    """Called by the target when an OOB payload triggers. No auth required — target has no API key."""
    redis = await get_redis()
    raw = await redis.get(_key(token))
    if not raw:
        return JSONResponse(status_code=200, content={"status": "ok"})  # silent — don't reveal invalidity

    data = json.loads(raw)
    hit = {
        "timestamp": _now(),
        "source_ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "headers": dict(request.headers),
        "path": str(request.url),
    }
    data["hits"].append(hit)
    await redis.set(_key(token), json.dumps(data), ex=_TTL)
    return JSONResponse(status_code=200, content={"status": "ok"})


@router.get("/check/{token}")
async def check_token(token: str) -> Dict[str, Any]:
    """Check whether an OOB token has been triggered."""
    redis = await get_redis()
    raw = await redis.get(_key(token))
    if not raw:
        return {"token": token, "triggered": False, "hits": [], "error": "token not found or expired"}
    data = json.loads(raw)
    return {
        "token": token,
        "triggered": len(data["hits"]) > 0,
        "hit_count": len(data["hits"]),
        "hits": data["hits"],
        "description": data.get("description", ""),
    }
