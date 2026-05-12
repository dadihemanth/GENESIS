"""T145 — Budget Controls Tracker.

Tracks per-session: LLM token usage, sandbox CPU-seconds, tool call count.
Reads budget_controls table; blocks tool calls at 100%, warns at 80%.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_WARN_THRESHOLD = 0.80
_BLOCK_THRESHOLD = 1.00


async def get_budget_control(tenant_id: str, target_ip: str) -> Optional[Dict[str, Any]]:
    """Fetch budget control record for a target."""
    from app.database.postgres import get_db_session
    from app.models.user import BudgetControl
    from sqlalchemy import select

    async with get_db_session() as db:
        result = await db.execute(
            select(BudgetControl).where(
                BudgetControl.tenant_id == tenant_id,
                BudgetControl.target_ip == target_ip,
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return {
            "id": str(row.id),
            "monthly_usd_cap": row.monthly_usd_cap,
            "token_budget": row.token_budget,
            "sandbox_cpu_cap": row.sandbox_cpu_cap,
            "tool_call_cap": row.tool_call_cap,
        }


async def get_session_spend(session_id: str) -> Dict[str, Any]:
    """Read current spend counters from Redis."""
    from app.database.redis_client import get_redis_client

    redis = await get_redis_client()
    prefix = f"budget:{session_id}"
    keys = [f"{prefix}:tokens", f"{prefix}:tool_calls", f"{prefix}:cpu_seconds", f"{prefix}:usd"]
    values = await redis.mget(keys)
    return {
        "tokens": int(values[0] or 0),
        "tool_calls": int(values[1] or 0),
        "cpu_seconds": float(values[2] or 0),
        "usd": float(values[3] or 0),
    }


async def record_tool_call(session_id: str, tokens_used: int = 0, cpu_seconds: float = 0.0) -> None:
    """Increment spend counters after a tool execution."""
    from app.database.redis_client import get_redis_client

    redis = await get_redis_client()
    prefix = f"budget:{session_id}"
    pipe = redis.pipeline()
    pipe.incr(f"{prefix}:tool_calls")
    if tokens_used > 0:
        pipe.incrby(f"{prefix}:tokens", tokens_used)
    if cpu_seconds > 0:
        await redis.incrbyfloat(f"{prefix}:cpu_seconds", cpu_seconds)
    await pipe.execute()


async def estimate_usd(tokens: int) -> float:
    """Rough USD estimate based on Claude Opus 4 pricing ($15/1M input tokens)."""
    return tokens / 1_000_000 * 15.0


async def check_budget(session_id: str, tenant_id: str, target_ip: str) -> Dict[str, Any]:
    """Check if session is within budget. Returns {allowed, warn, reason}."""
    control = await get_budget_control(tenant_id, target_ip)
    if not control:
        return {"allowed": True, "warn": False, "reason": "no budget control set"}

    spend = await get_session_spend(session_id)
    usd = await estimate_usd(spend["tokens"])

    checks = []
    overall_ratio = 0.0

    if control.get("token_budget"):
        ratio = spend["tokens"] / control["token_budget"]
        overall_ratio = max(overall_ratio, ratio)
        if ratio >= _BLOCK_THRESHOLD:
            checks.append(f"token budget exhausted ({spend['tokens']}/{control['token_budget']})")
    if control.get("tool_call_cap"):
        ratio = spend["tool_calls"] / control["tool_call_cap"]
        overall_ratio = max(overall_ratio, ratio)
        if ratio >= _BLOCK_THRESHOLD:
            checks.append(f"tool call cap reached ({spend['tool_calls']}/{control['tool_call_cap']})")
    if control.get("monthly_usd_cap"):
        ratio = usd / control["monthly_usd_cap"]
        overall_ratio = max(overall_ratio, ratio)
        if ratio >= _BLOCK_THRESHOLD:
            checks.append(f"USD cap reached (${usd:.2f}/${control['monthly_usd_cap']})")

    if checks:
        return {"allowed": False, "warn": True, "reason": "; ".join(checks), "spend": spend}

    return {
        "allowed": True,
        "warn": overall_ratio >= _WARN_THRESHOLD,
        "reason": f"budget at {overall_ratio:.0%}" if overall_ratio >= _WARN_THRESHOLD else "ok",
        "spend": spend,
    }
