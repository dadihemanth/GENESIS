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


def reset_redis_client() -> None:
    """Drop the module-level async Redis client synchronously.

    Called at the start of every Celery task so a new event loop doesn't
    inherit a connection pool whose sockets are bound to the previous (now
    closed) loop — which raises `RuntimeError: Event loop is closed` the next
    time we publish or subscribe.

    We can't `await aclose()` here (no loop), so we forcibly disconnect the
    underlying connection pool (a synchronous call) and drop the reference.
    The OS will reclaim the sockets; the next `get_redis()` call will spin
    up a fresh client on the live loop.
    """
    global _redis
    try:
        if _redis is not None:
            try:
                _redis.connection_pool.disconnect()
            except Exception:  # noqa: BLE001
                pass
    finally:
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
