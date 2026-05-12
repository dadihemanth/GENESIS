"""v7.x — token-usage recorder.

A tiny shared helper invoked after every `client.messages.create()` call
across the orchestrator, critic, multi-agent sub-agents, and adversarial
agents. Persists one row per call into the `llm_usage` Mongo collection so
the Costs tab can total the spend (and the per-iteration line chart) without
re-deriving usage from logs.

Pricing is NOT computed here — `routes/costs.py` reads the per-model rate
card from AppSettings at request time so historical sessions can be re-priced
when rates change.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from app.database.mongodb import get_llm_usage_collection

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


PublishFn = Callable[[str, dict], Awaitable[None]]


async def record_llm_usage(
    *,
    session_id: str,
    iteration: int,
    source: str,
    model: str,
    response: Any,
    publish_fn: Optional[PublishFn] = None,
) -> None:
    """Persist a single LLM-call usage row + (optionally) broadcast it.

    `source` is a free-form tag identifying the call site (orchestrator,
    critic, red_blue, philosopher, subagent:exploit, etc.) so the Costs tab
    can break down spend by what produced it.

    Failures are non-fatal — usage tracking must never break a session.
    """
    try:
        usage = getattr(response, "usage", None)
        if usage is None:
            return
        input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
        output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
        cache_create = int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
        cache_read = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        if input_tokens == 0 and output_tokens == 0 and cache_create == 0 and cache_read == 0:
            return  # adapter returned no usage — skip
        doc = {
            "session_id": str(session_id),
            "iteration": int(iteration or 0),
            "source": str(source or "orchestrator"),
            "model": str(model or ""),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_create_tokens": cache_create,
            "cache_read_tokens": cache_read,
            "ts": datetime.now(timezone.utc),
        }
        try:
            await get_llm_usage_collection().insert_one(doc)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[USAGE] mongo insert failed (non-fatal): %s", exc)
            return
        if publish_fn is not None:
            try:
                await publish_fn(str(session_id), {
                    "type": "llm_usage_recorded",
                    "data": {
                        "session_id": doc["session_id"],
                        "iteration": doc["iteration"],
                        "source": doc["source"],
                        "model": doc["model"],
                        "input_tokens": doc["input_tokens"],
                        "output_tokens": doc["output_tokens"],
                        "cache_create_tokens": doc["cache_create_tokens"],
                        "cache_read_tokens": doc["cache_read_tokens"],
                        "ts": doc["ts"].isoformat(),
                    },
                    "timestamp": _now_iso(),
                })
            except Exception as exc:  # noqa: BLE001
                logger.debug("[USAGE] publish failed (non-fatal): %s", exc)
    except Exception as exc:  # noqa: BLE001
        logger.debug("[USAGE] record failed (non-fatal): %s", exc)
