from __future__ import annotations

import json
from typing import Any

from redis.asyncio import Redis
from redis.asyncio.client import PubSub

from app.config import settings

_redis: Redis | None = None


async def get_redis() -> Redis:
    global _redis
    if _redis is None:
        _redis = Redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis


async def close_redis() -> None:
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None


async def publish_session_message(session_id: str, message: dict[str, Any]) -> None:
    redis = await get_redis()
    channel = f"session:{session_id}"
    await redis.publish(channel, json.dumps(message))


async def create_session_subscriber(session_id: str) -> PubSub:
    redis = await get_redis()
    pubsub = redis.pubsub()
    channel = f"session:{session_id}"
    await pubsub.subscribe(channel)
    return pubsub
