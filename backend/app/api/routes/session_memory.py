from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter

from app.database.redis_client import get_redis

router = APIRouter()

_TTL = 86400  # 24 hours per session


def _key(session_id: str, category: str) -> str:
    return f"genesis:session_memory:{session_id}:{category}"


@router.post("/{session_id}/store")
async def store_memory(session_id: str, body: Dict[str, Any]) -> Dict[str, str]:
    """Store a key/value fact in the session working memory."""
    category = body.get("category", "general")
    key = body.get("key", "")
    value = body.get("value", "")
    if not key:
        return {"status": "error", "detail": "key required"}

    redis = await get_redis()
    redis_key = _key(session_id, category)
    raw = await redis.get(redis_key)
    store: Dict[str, Any] = json.loads(raw) if raw else {}
    store[key] = value
    await redis.set(redis_key, json.dumps(store), ex=_TTL)
    return {"status": "ok"}


@router.get("/{session_id}/query")
async def query_memory(
    session_id: str,
    category: Optional[str] = None,
    key: Optional[str] = None,
) -> Dict[str, Any]:
    """Query session working memory. Returns all entries if no filter given."""
    redis = await get_redis()

    if category:
        raw = await redis.get(_key(session_id, category))
        store: Dict[str, Any] = json.loads(raw) if raw else {}
        if key:
            return {"category": category, "key": key, "value": store.get(key)}
        return {"category": category, "entries": store}

    # No category filter — scan all categories for this session
    pattern = f"genesis:session_memory:{session_id}:*"
    keys: List[str] = []
    cursor = 0
    while True:
        cursor, batch = await redis.scan(cursor, match=pattern, count=100)
        keys.extend(batch)
        if cursor == 0:
            break

    result: Dict[str, Any] = {}
    for k in keys:
        cat = k.decode().split(":")[-1] if isinstance(k, bytes) else k.split(":")[-1]
        raw = await redis.get(k)
        result[cat] = json.loads(raw) if raw else {}
    return {"session_id": session_id, "memory": result}
