"""T152 — Novelty A/B Testing Harness.

For 10% of sessions, randomly assigns variant A (existing T30/T31 novelty scorer)
vs variant B (T125 curiosity model). Tracks confirmed-bug-per-iteration rates.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_AB_ROLLOUT_PCT = 0.10  # 10% of sessions get variant B
_VARIANT_A = "novelty_v1"
_VARIANT_B = "curiosity_v2"
_REDIS_PREFIX = "ab_test:"


def _assign_variant(session_id: str) -> str:
    """Deterministically assign A/B variant based on session_id hash."""
    digest = int(hashlib.sha256(session_id.encode()).hexdigest(), 16)
    return _VARIANT_B if (digest % 100) < int(_AB_ROLLOUT_PCT * 100) else _VARIANT_A


async def record_session_variant(session_id: str) -> str:
    """Assign and record the variant for a session. Returns variant name."""
    from app.database.redis_client import get_redis_client

    variant = _assign_variant(session_id)
    redis = await get_redis_client()
    await redis.set(f"{_REDIS_PREFIX}variant:{session_id}", variant, ex=86400 * 30)
    return variant


async def get_session_variant(session_id: str) -> str:
    """Return the variant assigned to a session."""
    from app.database.redis_client import get_redis_client

    redis = await get_redis_client()
    val = await redis.get(f"{_REDIS_PREFIX}variant:{session_id}")
    if val:
        return val.decode() if isinstance(val, bytes) else str(val)
    return _assign_variant(session_id)


async def record_iteration_outcome(
    session_id: str,
    confirmed_bugs: int,
    iterations: int,
) -> None:
    """Record iteration→confirmed_bugs stats for the session's variant."""
    from app.database.redis_client import get_redis_client

    variant = await get_session_variant(session_id)
    redis = await get_redis_client()
    pipe = redis.pipeline()
    pipe.incrby(f"{_REDIS_PREFIX}{variant}:total_bugs", confirmed_bugs)
    pipe.incrby(f"{_REDIS_PREFIX}{variant}:total_iterations", iterations)
    pipe.incr(f"{_REDIS_PREFIX}{variant}:session_count")
    await pipe.execute()


async def get_ab_results() -> Dict[str, Any]:
    """Return current A/B test performance comparison."""
    from app.database.redis_client import get_redis_client

    redis = await get_redis_client()
    keys = [
        f"{_REDIS_PREFIX}{_VARIANT_A}:total_bugs",
        f"{_REDIS_PREFIX}{_VARIANT_A}:total_iterations",
        f"{_REDIS_PREFIX}{_VARIANT_A}:session_count",
        f"{_REDIS_PREFIX}{_VARIANT_B}:total_bugs",
        f"{_REDIS_PREFIX}{_VARIANT_B}:total_iterations",
        f"{_REDIS_PREFIX}{_VARIANT_B}:session_count",
    ]
    values = await redis.mget(keys)
    ints = [int(v or 0) for v in values]

    def rate(bugs: int, iters: int) -> float:
        return bugs / iters if iters > 0 else 0.0

    a_rate = rate(ints[0], ints[1])
    b_rate = rate(ints[3], ints[4])
    lift = (b_rate - a_rate) / a_rate if a_rate > 0 else 0.0

    return {
        _VARIANT_A: {
            "total_bugs": ints[0],
            "total_iterations": ints[1],
            "session_count": ints[2],
            "bugs_per_iteration": round(a_rate, 4),
        },
        _VARIANT_B: {
            "total_bugs": ints[3],
            "total_iterations": ints[4],
            "session_count": ints[5],
            "bugs_per_iteration": round(b_rate, 4),
        },
        "lift": round(lift, 4),
        "winner": _VARIANT_B if lift > 0 else _VARIANT_A if lift < 0 else "tied",
        "rollout_pct": _AB_ROLLOUT_PCT,
    }
